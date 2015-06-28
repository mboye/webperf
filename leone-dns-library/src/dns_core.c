#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "dns_core.h"
#include "dns_cache.h"
#include "dns_support.h"
#include "leone_tools.h"

#ifdef __linux
#include <endian.h>
#elif __APPLE__
#include <machine/endian.h>
#endif

void dns_state_reset(DNSResolverState *state)
{
    int i;
    /* Free responses */
    for (i = 0; i < state->nrof_responses; i++)
    {
        dns_message_free(state->responses[i]);
        state->responses[i] = NULL;
    }
    state->nrof_responses = 0;
    /* Free queries */
    for (i = 0; i < state->nrof_queries; i++)
    {
        free(state->queries[i]->authority);
        free(state->queries[i]->destination);
        free(state->queries[i]->qname);
        state->queries[i] = NULL;
    }
    state->nrof_queries = 0;
}

void dns_cache_free(DNSCache *cache)
{
    dns_cache_node_free(cache->root);
    dns_message_free(cache->root);
    free(cache);
}

void dns_cache_node_free(DNSMessage *node)
{
    int i;
    DNSMessage *child;
    for (i = 0; i < node->nrof_children; i++)
    {
        child = node->children[i];
        dns_cache_node_free(child);
    }
    /* At this point, the node has no children so we can free it.
     * Never free root of tree. Otherwise initialization must be done again. */
    if (strcmp(node->label, "") != 0)
    {
        dns_message_free(node);
    }
}

int dns_trail(char *domain,
              char **domain_trail)
{
    unsigned int i;
    for (i = 0; domain_trail[i] != NULL && i < DNS_MAX_DOMAINS; i++)
    {
        if (strcasecmp(domain_trail[i], domain) == 0)
        {
            /* Match found. Return trail value. */
            return 1 << i;
        }
    }
    if (i == DNS_MAX_DOMAINS)
        return -1;
    /* No queries have been sent for this domain. */
    domain_trail[i] = allocstrcpy(domain, strlen(domain), 1);
    log_debug(__func__, "New trail bit of '%s' is %u", domain, 1 << i);
    return 1 << i;
}

void dns_trail_free(char **domain_trail)
{
    unsigned int i;
    for (i = 0; domain_trail[i] != NULL && i < DNS_MAX_DOMAINS; i++)
    {
        free(domain_trail[i]);
    }

}

unsigned int dns_domain_id(DNSCache *cache,
                           char *domain)
{
    DNSMessage *msg = dns_cache_find_domain(cache, domain);
    if (msg != NULL)
    {
        return msg->domain_id;
    }
    else
    {
        return 0;
    }
}

int dns_detect_domain_loop(DNSCache *cache,
                           unsigned int domain_trail[],
                           char *qname)
{
    DNSMessage *message;
    int i = 0;
    if ((message = dns_cache_find_domain(cache, qname)) != NULL)
    {
        for (i = 0; i < LEONE_DNS_MAX_DOMAIN_TRAIL; i++)
        {
            if (domain_trail[i] == message->domain_id)
            {
                /* We have already tried to resolve this domain name, so this must be a loop. */
                log_debug(__func__, "DNS domain loop detected.");
                return 1;
            }
        }
        return 0;
    }
    else
    {
        return 0;
    }
}

int dns_detect_record_loop(DNSRecord *record,
                           unsigned int record_trail[])
{
    int i;
    for (i = 0; i < LEONE_DNS_MAX_RECORD_TRAIL; i++)
    {
        if (record_trail[i] == record->record_id)
        {
            return 1;
        }
        else if (record_trail[i] == 0)
        {
            /* Speed up */
            break;
        }
    }
    return 0;
}

int dns_queue_find(DNSQueryQueue *queue,
                   char *qname)
{
    DNSQueryQueue *q;
    assert(queue != NULL);
    assert(qname != NULL);
    for (q = queue; q != NULL; q = q->next)
    {
        if (strcasecmp(q->qname, qname) == 0)
        {
            return 1;
        }
    }
    return 0;

}

void dns_record_trail_mark(DNSQueryQueue *queue_top,
                           DNSRecord *record)
{
    if (queue_top->trail_offset + 1 < LEONE_DNS_MAX_RECORD_TRAIL)
    {
        queue_top->record_trail[++queue_top->trail_offset] = record->record_id;
    }
    else
    {
        log_debug(__func__, "WARNING: Maximum record trail length exceeded.");
    }
}

int dns_resolve(DNSCache *cache,
                DNSResolverState *state,
                char *qname_original,
                DNSRecordType qtype,
                char **final_qname)
{
    DNSMessage *best_authority, *best_destination;
    int i, sock, j;
    int send_count;
    DNSRecord *ns, **best_destination_nwp, *destination;
    unsigned char nrof_best_destinations;
    unsigned short flags = 0;
    char *qpacket;
    unsigned short qpacket_len, qpacket_id;
    int destination_len;
    struct sockaddr_storage destination_addr;
    char response_received;
    int poll_retval = -1;
    char respbuf[1024];
    int respbuf_len = 0;
    unsigned short rcvd_id;
    struct pollfd poll_rcv;
    struct timeval tm_start, tm_end, tm_diff;
    DNSQuery *query;
    DNSRecord *final_rr;
    DNSMessage *final_msg;
    DNSMessage *last_response;
    char next_query;
    int parser_retval;
    DNSQueryQueue *queue, *queue_top, *queue_tmp;
    struct timeval rtt_sum;
    unsigned int domain_trail[LEONE_DNS_MAX_DOMAIN_TRAIL]; /* Array used to keep track of the order in which domain names are resolved. Used for loop detection. */
#ifndef NDEBUG
    char *debug_str;
#endif
    /* Clear old responses. */
    dns_state_reset(state);

    /* Reset domain trail. */
    bzero(domain_trail, LEONE_DNS_MAX_DOMAIN_TRAIL * sizeof(unsigned int));

    /* Reset resolution statistics. */
    bzero(&state->stats, sizeof(state->stats));
    bzero(&rtt_sum, sizeof(struct timeval));

    /* Add first item to query queue. */
    queue = calloc(1, sizeof(DNSQueryQueue));
    queue->qname = allocstrcpy(qname_original, strlen(qname_original), 1);
    queue_top = queue;

    /* Create socket. */
    if ((sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        log_debug(__func__, "socket(): %s", strerror(errno));
        log_debug(__func__, "Trying to create IPv4 socket instead.");
        if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            exit(EXIT_FAILURE);
        }
    }

    while (queue_top != NULL && state->nrof_responses < DNS_MAX_RESPONSES)
    {
        /* TODO: if next_query == 1 should we skip this queue item? */
        next_query = 0;
        response_received = 0;
        log_debug(__func__, "QNAME at beginning is '%s'", queue_top->qname);

        /* Check for DNS domain loops (CNAME loops) */
        if (dns_detect_domain_loop(cache, domain_trail, queue_top->qname))
        {
            /* Loop detected. */
            /* Free entire query queue. */
            while (queue_top != NULL)
            {
                queue_tmp = queue_top->prev;
                free(queue_top->qname);
                free(queue_top);
                queue_top = queue_tmp;
            }
            queue_top = NULL;
            queue = NULL;
            return DNS_LOOP;
        }
        /* Update final QNAME. */
        if (final_qname != NULL)
        {
            if (*final_qname != NULL)
                free(*final_qname);
            *final_qname = allocstrcpy(queue_top->qname,
                                       strlen(queue_top->qname),
                                       1);
        }
        /* Check if name is already in cache. */
        if ((final_rr = dns_cache_find_rr(cache, queue_top->qname, qtype,
                                          ANSWERS | ADDITIONALS,
                                          &final_msg)))
        {
            if (final_rr->type == qtype)
            {
#ifndef NDEBUG
                debug_str = dns_record_rdata_str(final_rr);
                log_debug(__func__, "Query complete. %s = %s", queue_top->qname,
                          debug_str);
                free(debug_str);
#endif
                state->responses[state->nrof_responses++] =
                    dns_message_copy(
                                     final_msg,
                                     state->nwp); /* Resolver MUST always return COPY of entries in cache. */

                /* Remove last entry in queue. */
                assert(queue_top->next == NULL);
                queue_tmp = queue_top->prev;
                free(queue_top->qname);
                free(queue_top);
                queue_top = queue_tmp;
                queue_tmp = NULL;
                if (queue_top != NULL)
                {
                    queue_top->next = NULL;
                }
            }
            else if (final_rr->type == CNAME)
            {
                log_debug(__func__, "Query complete. %s = %s", queue_top->qname,
                          final_rr->data);
                /* Check if CNAME has already been followed for loop detection. */
                if (dns_detect_record_loop(final_rr, queue_top->record_trail))
                {
                    log_debug(__func__,
                              "ERROR: CNAME '%s' has already been followed: Loop detected.");
                    /* Abort resolution. */
                    break;
                }
                /* if CNAME has not been followed, override current QNAME and continue resolution. */
                assert(queue_top != NULL);
                assert(queue_top->next == NULL);
                assert(queue_top->qname != NULL);
                assert(strlen(queue_top->qname) > 0);
                free(queue_top->qname);
                queue_top->qname = allocstrcpy(final_rr->data,
                                               strlen(final_rr->data),
                                               1);
                next_query = 1;
                /* Mark CNAME as used. */
                dns_record_trail_mark(queue_top, final_rr);
            }
            /* TODO: Wooooow. Check the line below again! */
        }
        else if ((state->recurse
            && (best_authority = &state->recursive_authority) != NULL)
            || (best_authority = dns_cache_find_best_ns(cache,
                                                        queue_top->qname)))
        {/* Find next name server to query. */

            /* Create DNS packet. */
            dns_message_flag(&flags,
                             DNS_FLAG_RECURSION_DESIRED,
                             state->recurse);

            dns_create_packet(queue_top->qname, qtype, flags, &qpacket,
                              &qpacket_len,
                              &qpacket_id);

            authority_search:

            /* Try all name servers. */
            for (i = 0; i < best_authority->nrof_authorities; i++)
            {
                ns = best_authority->authorities[i];
                if (ns->type != NS)
                {
                    continue;
                }

                log_debug(__func__, "Best authority for '%s' is '%s'",
                          queue_top->qname,
                          ns->data);

                /* Check if name server has already been asked the current question. */
                assert(queue_top != NULL);
                if (dns_detect_record_loop(ns, queue_top->record_trail))
                {
                    log_debug(__func__,
                              "WARNING: '%s' has already been queried about '%s' - skipping server.",
                              ns->data,
                              queue_top->qname);
                    continue;
                }

                /* Find A/AAAA record for best authority.
                 * If NULL is returned, no A/AAAA record for the NS record is in the cache.
                 * The resolver must first find the A/AAAA record before continuing with the current query. */
                if (dns_cache_find_rr(cache, ns->data, A_AAAA,
                                      ANSWERS | ADDITIONALS,
                                      &best_destination) == NULL)
                {
                    if (state->recurse)
                    {
                        /* If resolver is in recursive mode an IP address for the NS record should have been provided. */
                        free(qpacket);
                        /* Free entire query queue. */
                        while (queue_top != NULL)
                        {
                            queue_tmp = queue_top->prev;
                            free(queue_top->qname);
                            free(queue_top);
                            queue_top = queue_tmp;
                        }

                        log_debug(__func__,
                                  "DNS client improperly configured. Missing A/AAAA record of recursive nameserver.");

                        return DNS_LOOP;
                    }
                    else
                    {
                        /* The NS record is missing a matching A record, so change query name */
                        log_debug(__func__,
                                  "No A/AAAA record for NS record exists in cache. Changing QNAME to '%s'",
                                  ns->data);

                        /* Loop detection: Check if we have already tried to resolve the new QNAME */
                        if (dns_queue_find(queue, ns->data))
                        {
                            log_debug(__func__,
                                      "NS loop detected. Trying next authority...");
                            continue;
                        }

                        if (strcasecmp(ns->data, queue_top->qname) == 0)
                        {
                            /* Hmm...querying the server itself about itself is not a good idea. */
                            log_debug(__func__,
                                      "WARNING: Best authority is the same as QNAME itself!");
                            while (best_authority->parent != NULL)
                            {
                                best_authority = best_authority->parent;
                                if (best_authority->nrof_authorities > 0)
                                {
                                    goto authority_search;
                                }
                            }

                            /* This is bad. */
                            return DNS_LOOP;

                        }
                        else
                        {

                            /* Add new item to query queue */
                            queue_tmp = calloc(1, sizeof(DNSQueryQueue));
                            queue_tmp->qname = strdup(ns->data);
                            queue_tmp->prev = queue_top;
                            queue_top->next = queue_tmp;
                            queue_top = queue_tmp;

                            next_query = 1;
                            break;
                        }
                    }
                }
                /* Mark authority as used for current QNAME. */
                dns_record_trail_mark(queue_top, ns);
                /*log_debug(__func__, "Marking '%s' as USED for '%s'", ns->data, queue_top->qname);*/

                /* Order records by NWP. */
                /* TODO: Problem with record ordering. Returns IPv6 before IPv4. */
                nrof_best_destinations = dns_message_nwp(best_destination,
                                                         state->nwp,
                                                         &best_destination_nwp);
                if (nrof_best_destinations == 0)
                {
                    log_debug(__func__,
                              "WARNING: A(%s) has zero NWP record (%d A/AAAA records available).",
                              ns->data,
                              best_destination->nrof_answers
                                  + best_destination->nrof_additionals);
                }

                /* Try all A/AAAA records for best authority. */
                for (j = 0; j < nrof_best_destinations; j++)
                {
                    destination = best_destination_nwp[j];
                    assert(destination->type == A || destination->type == AAAA);
                    if (dns_detect_record_loop(destination,
                                               queue_top->record_trail))
                    {
                        log_debug(__func__,
                                  "A/AAAA record is broken - skipping it.");
                        continue;
                    }
                    bzero(&destination_addr, sizeof(struct sockaddr_storage));
                    if (destination->type == A)
                    {
                        destination_addr.ss_family = AF_INET;
                        destination_len = sizeof(struct sockaddr_in);
                        memcpy(
                               &((struct sockaddr_in * ) &destination_addr)->sin_addr,
                               destination->data,
                               4); /* Copy IPv4 address. */
                        ((struct sockaddr_in *)&destination_addr)->sin_port =
                            htons(53); /* Set port number. */
                    }
                    else
                    {
                        destination_addr.ss_family = AF_INET6;
                        destination_len = sizeof(struct sockaddr_in6);
                        memcpy(
                               &((struct sockaddr_in6 * ) &destination_addr)->sin6_addr,
                               destination->data,
                               16); /* Copy IPv6 address. */
                        ((struct sockaddr_in6 *)&destination_addr)->sin6_port =
                            htons(53);/* Set port number. */
                    }

#ifndef NDEBUG
                    debug_str = dns_record_rdata_str(destination);
                    log_debug(__func__, "Query destination: %s", debug_str);
                    free(debug_str);
#endif

                    /* Create query structure. */
                    if ((state->queries[state->nrof_queries] =
                        calloc(1,
                               sizeof(DNSQuery))) == NULL)
                    {
                        log_debug(__func__, "Out of memory.");
                        exit(DNS_MEMORY);
                    }
                    query = state->queries[state->nrof_queries];
                    query->authority = allocstrcpy(ns->data, strlen(ns->data),
                                                   1);
                    query->destination = dns_record_rdata_str(destination);
                    query->qname = allocstrcpy(queue_top->qname,
                                               strlen(queue_top->qname),
                                               1);
                    query->pksize = qpacket_len;
                    state->nrof_queries++;

                    /* Connect to socket in order to receive ICMP errors. */
                    if (connect(sock, (struct sockaddr *)&destination_addr,
                                destination_len) != 0)
                    {
                        log_debug(__func__, "connect(): %s", strerror(errno));
                        /* Mark A/AAAA record as broken. */
                        dns_record_trail_mark(queue_top, destination);
                        continue;
                    }
                    send_count = 0;
                    /* As long as a response to the query has not been received AND number of retries has not been exceeded. */
                    while ((!response_received && !next_query)
                        && send_count < DNS_MAX_SEND_COUNT
                        && state->timeout[send_count] > 0)
                    {
                        /* Send packet. */
                        log_debug(__func__, "Transmission attempt %d",
                                  send_count);
                        if (send(sock, qpacket, qpacket_len, 0)
                            == qpacket_len)
                        {

                            /* Set transmission timestamp. */
                            gettimeofday(&tm_start, NULL);
                            state->stats.data_tx += qpacket_len;
                            state->stats.packet_tx++;
                            /* Wait for response. */
                            poll_rcv.fd = sock;
                            poll_rcv.events = POLLIN;
                            response_received = 0;

                            /* Poll for response on socket. */
                            log_debug(__func__, "Timeout is %u ms.",
                                      state->timeout[send_count]);
                            poll_retval = poll(&poll_rcv, 1,
                                               state->timeout[send_count++]);
                            switch (poll_retval)
                            {
                                default:
                                    case 0:
                                    /* Timeout or error. */
                                    log_debug(__func__,
                                              "Request time out or error.");
                                    break;
                                case 1:
                                    /* Ready to receive data. */
                                    if ((respbuf_len = recv(sock, respbuf,
                                                            sizeof(respbuf),
                                                            MSG_DONTWAIT))
                                        != -1)
                                    {
                                        /* Set reception time. */
                                        gettimeofday(&tm_end, NULL);

                                        /* Quickly check transaction ID. */
                                        rcvd_id =
                                            ntohs(chars_to_short(respbuf));

                                        if (rcvd_id == qpacket_id)
                                        {
                                            response_received = 1;
                                            state->stats.data_rx += (size_t)respbuf_len;
                                            state->stats.packet_rx++;
                                            /* Parse DNS message if transaction ID matches. */
                                            if ((state->responses[state->nrof_responses] =
                                                calloc(1, sizeof(DNSMessage)))
                                                == NULL)
                                            {
                                                log_debug(__func__,
                                                          "Out of memory.");
                                                exit(DNS_MEMORY);
                                            }
                                            last_response =
                                                state->responses[state->nrof_responses];
                                            query->response = last_response;
                                            /* Calculate RTT of last response. */
                                            timersub(&tm_end,
                                                     &tm_start,
                                                     &tm_diff);
                                            /* Update sum of RTTs. */
                                            state->stats.network_time +=
                                                timeval_to_msec(&tm_diff);
                                            last_response->rtt =
                                                timeval_to_msec(
                                                                &tm_diff);
                                            last_response->pksize = respbuf_len;
                                            /* Parse response. */
                                            if ((parser_retval =
                                                dns_message_parse(
                                                                  state,
                                                                  cache, respbuf,
                                                                  respbuf_len,
                                                                  queue_top->qname))
                                                == DNS_OK)
                                            {
                                                last_response->query = query;
                                                state->nrof_responses++;
                                                /* Check if response answered the query. */
                                                if (last_response->nrof_answers
                                                    > 0)
                                                {
                                                    final_rr =
                                                        last_response->answers[0];
                                                    /* Check name of record returned. */
                                                    if (strcasecmp(
                                                                   last_response->answers[0]->name,
                                                                   queue_top->qname)
                                                        == 0)
                                                    {
                                                        /* Name is a match. Check record type. */
                                                        if (final_rr->type == A
                                                            || final_rr->type
                                                                == AAAA)
                                                        {
#ifndef NDEBUG
                                                            debug_str =
                                                                dns_record_rdata_str(
                                                                                     final_rr);
                                                            log_debug(__func__,
                                                                      "Query complete. %s = %s",
                                                                      queue_top->qname,
                                                                      debug_str);
                                                            free(debug_str);
#endif
                                                            /* Remove last entry in queue. */
                                                            assert(
                                                                   queue_top->next == NULL);
                                                            queue_tmp =
                                                                queue_top->prev;
                                                            free(queue_top->qname);
                                                            free(queue_top);
                                                            queue_top =
                                                                queue_tmp;
                                                            queue_tmp = NULL;
                                                            if (queue_top
                                                                != NULL)
                                                            {
                                                                queue_top->next =
                                                                NULL;
                                                            }

                                                            next_query = 1;
                                                        }
                                                        else if (final_rr->type
                                                            == CNAME)
                                                        {
                                                            log_debug(__func__,
                                                                      "Query complete. %s = %s",
                                                                      queue_top->qname,
                                                                      final_rr->data);
                                                            /* Override current QNAME and continue resolution. */
                                                            assert(
                                                                   queue_top != NULL);
                                                            assert(
                                                                   queue_top->next == NULL);
                                                            assert(
                                                                   queue_top->qname != NULL);
                                                            free(queue_top->qname);
                                                            queue_top->qname =
                                                                allocstrcpy(
                                                                            final_rr->data,
                                                                            strlen(
                                                                                   final_rr->data),
                                                                            1);
                                                            next_query = 1;
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    /* The response did not contain any answers. Continue resolution... */
                                                    next_query = 1;
                                                }
                                            }
                                            else if (parser_retval
                                                == DNS_ERROR_NXDOMAIN)
                                            {
                                                /* An authoritative name server says the record does not exist. Abort resolution...*/
                                                state->nrof_responses++; /* Increment number of responses to included response containing SOA record. */
                                                free(qpacket);
                                                query->response_code =
                                                    parser_retval;
                                                return DNS_RECORD_NOT_FOUND;
                                                /* TODO: Should we actually continue here? */
                                            }
                                            else
                                            {
                                                /* The query failed, so we assume that the server malfunctioned.
                                                 * Let's try the next name A/AAAA record for the name server. */
                                                query->response_code =
                                                    parser_retval;
                                                query->response = NULL;
                                                free(last_response);
                                                goto next_destination;
                                            }
                                        }
                                        else
                                        {
                                            log_debug(__func__,
                                                      "ID mismatch: %u - expected %u.",
                                                      qpacket_id,
                                                      rcvd_id);
                                        }
                                    }
                                    else
                                    {
                                        /* Receive failed to try next destination. */
                                        log_debug(__func__,
                                                  "recv(): %s. Trying next destination...",
                                                  strerror(errno));
                                        goto next_destination;
                                    }
                                    break;
                            }
                            if (poll_retval < 0)
                            {
                                /* poll() failed, so try next server. */
                                break;
                            }
                        }
                        else
                        {
                            log_debug(__func__, "send(): %s", strerror(errno));
                            usleep(state->timeout[send_count]);
                            send_count++;
                        }
                    }
                    if (state->timeout[send_count] == 0)
                    {
                        log_debug(__func__, "Query time out.");
                    }
                    if (next_query)
                    {
                        free(qpacket);
                        break;
                    }
                    next_destination: continue;
                }
                free(best_destination_nwp);
                if (next_query)
                    break;
            }

            /* All name servers have been tried without success.
             * The query has failed. */
            if (!next_query)
            {
                free(qpacket);
                if (poll_retval == 0)
                {
                    log_debug(__func__, "The query timed out.");
                    return DNS_TIMEOUT;
                }
                else
                {
                    log_debug(__func__, "The query could not be completed.");
                    return DNS_RECORD_NOT_FOUND;
                }
            }
        }
        else
        {
            return DNS_NO_AUTHORITIES;
        }
    }
    /* Check if query was successful. */
    if (queue_top == NULL && state->nrof_responses > 0)
    {
        /* Fix pointers with respect to QTYPE. */
        if (qtype == A)
        {
            dns_fix_pointers(state->responses[state->nrof_responses - 1],
                             IPv46);
        }
        else if (qtype == AAAA)
        {
            dns_fix_pointers(state->responses[state->nrof_responses - 1], IPv6);
        }
        else
        {
            dns_fix_pointers(state->responses[state->nrof_responses - 1],
                             DEFAULT);
        }
        return DNS_OK;
    }
    else
    {
        /* Free entire query queue. */
        while (queue_top != NULL)
        {
            queue_tmp = queue_top->prev;
            free(queue_top->qname);
            free(queue_top);
            queue_top = queue_tmp;
        }
        return DNS_MAX_RESPONSES_EXCEEDED;
    }
}

char *dns_record_rdata_str(DNSRecord *record)
{
    char *result = NULL, *tmp = NULL;
    DNSRecordSOA *soa;
    unsigned int result_len;
    assert(record!=NULL);
    if (record->type == A || record->type == AAAA)
    {
        /* Convert RDATA to IPv4 or IPv6 result. */
        result = malloc(sizeof(char) * (INET6_ADDRSTRLEN + 1));
        if (record->data_len == 4)
        {
            inet_ntop(AF_INET, record->data, result, INET6_ADDRSTRLEN);
        }
        else if (record->data_len == 16)
        {
            inet_ntop(AF_INET6, record->data, result, INET6_ADDRSTRLEN);
        }
        /* Captures unknown data length and inet_ntop() failures. */
        if (result == NULL)
        {
            snprintf(result, INET6_ADDRSTRLEN + 1, "?");
        }
    }
    else if (record->type == CNAME || record->type == NS)
    {
        return allocstrcpy(record->data, record->data_len, 1);
    }
    else if (record->type == SOA)
    {
        soa = (DNSRecordSOA *)record->data;
        result = malloc(sizeof(char) * (strlen(soa->domain) + 256));
        snprintf(result,
                 1024,
                 "{\"domain\":\"%s\",\"serial\":%u,\"refresh\":%u,\"retry\":%u,\"expire\":%u,\"min-ttl\":%u}",
                 soa->domain,
                 soa->serial,
                 soa->refresh,
                 soa->retry,
                 soa->expire,
                 soa->minimum_ttl);
    }
    else
    {
        /* If the record is not supported just return "UNSUPPORTED" */
        return allocstrcpy("UNSUPPORTED", 1, 1);
    }
    /* Optimize memory usage. */
    result_len = strlen(result) + 1;
    if ((tmp = realloc(result, result_len)) != NULL)
    {
        return tmp;
    }
    else
    {
        log_debug(__func__, "Out of memory.");
        exit(DNS_MEMORY);
    }
}

char *dns_cache_domain(DNSMessage *node)
{
    char *domain;
    char *domain_ptr;
    unsigned char label_len;
    DNSMessage *parent;
    assert(node != NULL);
    domain = calloc(DNS_MAX_DOMAIN_LENGTH + 1, sizeof(char));
    domain_ptr = domain;
    if (node->parent == NULL)
    {
        snprintf(domain, DNS_MAX_DOMAIN_LENGTH + 1, "<root>");
    }
    else
    {
        parent = node;
        while (parent != NULL)
        {
            label_len = strlen(parent->label);
            memcpy(domain_ptr, parent->label, label_len);
            domain_ptr += label_len;
            if (parent->parent != NULL)
                memcpy(domain_ptr++, ".", 1);
            parent = parent->parent;
        }
    }
    return domain;
}

/*
 int dns_domain_labels_count(char *domain) {
 int i;
 char *label, *tmp, *domain_copy;
 int nrof_labels;
 char *labels[127];
 domain_copy = allocstrcpy(domain, strlen(domain), 1);
 tmp = domain_copy;
 i = 0;
 while ((label = strtok(tmp, ".")) != NULL) {
 if (tmp != NULL)
 tmp = NULL;
 i++;
 }
 free(domain_copy);
 nrof_labels
 return i;
 }
 */

int dns_split_name(char *name,
                   char *labels[])
{
    int nrof_labels = 0;
    char *name_tmp, *name_split_ptr = NULL, *label;
    name_tmp = strdup(name);
    while ((label = strtok_r(name_tmp, ".", &name_split_ptr)) != NULL)
    {
        if (nrof_labels > DNS_MAX_LABELS)
        {
            log_debug(__func__, "WARNING: Max labels reached.");
            break;
        }
        labels[nrof_labels] = strdup(label);
        if (name_tmp != NULL)
            name_tmp = NULL;
        nrof_labels++;
    }
    free(name_tmp);
    return nrof_labels;
}

int dns_domain_similarity(char *domain_a,
                          char *domain_b)
{
    char *labels_a[DNS_MAX_LABELS], *labels_b[DNS_MAX_LABELS];
    unsigned char nrof_labels_a, nrof_labels_b;
    int a, b;
    int similarity = 1; /* Domains always have <root> in common so min. similarity is 1. */

    log_debug(__func__, "Comparing '%s' and '%s'", domain_a, domain_b);
    nrof_labels_a = dns_split_name(domain_a, labels_a);
    nrof_labels_b = dns_split_name(domain_b, labels_b);

    /* Determine how many labels the two domains have in common. */
    a = nrof_labels_a - 1;
    b = nrof_labels_b - 1;
    while (a >= 0 && b >= 0)
    {
        if (strcasecmp(labels_a[a], labels_b[b]) == 0)
        {
            similarity++;
            a--;
            b--;
        }
        else
        {
            break;
        }
    }
    /*
     free(tmp_a);
     free(tmp_b);
     */
    log_debug(__func__, "'%s' and '%s' have %d labels in common.", domain_a,
              domain_b,
              similarity);
    return similarity;

}

unsigned char dns_count_labels(char *domain)
{
    int i = 0;
    char *labels[DNS_MAX_LABELS];
    /* char *copy, *domain_tmp, *label; */
    int nrof_labels;
    if (strlen(domain) == 0 || strcmp(domain, ".") == 0)
    {
        return 0;
    }
    /*
     copy = allocstrcpy(domain, strlen(domain), 1);
     domain_tmp = copy;
     while ((label = strtok(domain_tmp, ".")) != NULL) {
     if (domain_tmp != NULL)
     domain_tmp = NULL;
     i++;
     }
     free(copy);
     */
    nrof_labels = dns_split_name(domain, labels);
    for (i = 0; i < nrof_labels; i++)
    {
        free(labels[i]);
    }
    return nrof_labels;
}

char *dns_cat_labels(char **labels,
                     unsigned char start_label,
                     char end_label)
{
    char *domain = malloc(sizeof(char) * (DNS_MAX_DOMAIN_LENGTH + 1));
    int i, offset = 0, label_len;
    for (i = start_label; i < end_label; i++)
    {
        label_len = strlen(labels[i]);
        memcpy(domain + offset, labels[i], label_len);
        offset += label_len;
        domain[offset] = '.';
        offset++;
    }
    domain[offset - 1] = '\0';
    return domain;
}

char *dns_message_fqdn(DNSMessage *message)
{
    DNSMessage *m;
    char *result = calloc(256, sizeof(char));
    unsigned char len = 0;
    m = message;
    if (m->parent == NULL)
    {
        log_debug(__func__, "FQDN: '.'");
        result = malloc(sizeof(char) * 2);
        result[0] = '.';
        result[1] = '\0';
        return result;
    }
    else
    {
        while (m->parent != NULL)
        {
            len += snprintf(result + len, 256 - len, "%s.", m->label);
            m = m->parent;
        }
        log_debug(__func__, "FQDN: '%s'", result);
    }
    return realloc(result, len + 1);
}

void skip_line(char*  buf,
               off_t  buf_len,
               off_t* pos)
{
    while (*pos < buf_len && buf[*pos] != '\n')
    {
        (*pos)++;
    }
    (*pos)++; /* Consume line ending. */
}

DNSResolverState *dns_state_init()
{
    DNSResolverState *state;
    DNSRecord *ns;
    int i;
    if ((state = calloc(1, sizeof(DNSResolverState))) == NULL)
    {
        return NULL;
    }
    for (i = 0; i < DNS_RETRIES_DEFAULT; i++)
    {
        state->timeout[i] = DNS_TIMEOUT_DEFAULT;
    }

    /* Create DNS mesage containing NS information. */
    bzero(&state->recursive_authority, sizeof(DNSMessage));
    state->recursive_authority.domain_id = 1;
    state->recursive_authority.label =
        allocstrcpy(DNS_FAKE_ROOT_SERVER_NAME,
                    strlen(DNS_FAKE_ROOT_SERVER_NAME),
                    1);

    /* Create NS record for recursive resolver. */
    if ((state->recursive_authority.authorities[0] = calloc(1,
                                                            sizeof(DNSRecord)))
        == NULL)
    {
        free(state);
        return NULL;
    }
    ns = state->recursive_authority.authorities[0];
    ns->name = allocstrcpy(DNS_FAKE_ROOT_SERVER_NAME,
                           strlen(DNS_FAKE_ROOT_SERVER_NAME),
                           1);
    ns->class = IN;
    ns->type = NS;
    ns->ttl = 3600;
    ns->data = allocstrcpy(DNS_FAKE_ROOT_SERVER_NAME,
                           strlen(DNS_FAKE_ROOT_SERVER_NAME),
                           1);
    ns->data_len = strlen(ns->data);
    ns->record_id = 1; /* Reserved record ID */

    state->recursive_authority.nrof_authorities = 1;

    return state;

}
