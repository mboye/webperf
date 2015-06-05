#include "hurl/hurl.h"
#include <string.h>
#include <dns_support.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "webperf.h"
#include <assert.h>

char *json_escape(char *str);
void cdn_detect(ElementStat *stat,
                DNSResolverState *dns_state);

void stat_set_dns_trigger(HURLPath *path,
                          HURLConnection *connection)
{
    ElementStat *stat = (ElementStat *)path->tag;
    ElementStat *trigger_stat;
    HURLPath *trigger = connection->server->domain->dns_trigger;

    if (stat->dns_trigger != NULL)
    {
        trigger_stat = (ElementStat *)trigger->tag;
        log_debug(__func__,
                  "DNS trigger already set: %s",
                  trigger_stat->url_hash);
        return;
    }

    /* At this point the domain name must have been resolved and the trigger therefore be set */
    assert(connection->server->domain->dns_trigger != NULL);

    /* Like all other paths, the one that triggered DNS resolution must also have a tag. */
    trigger_stat = (ElementStat *)trigger->tag;

    assert(trigger_stat != NULL);
    if (trigger == path)
    {
        log_debug(__func__, "SKIP-PATH");
        return;
    }
    if (strcmp(trigger_stat->url_hash, stat->url_hash) == 0)
    {
        log_debug(__func__,
                  "SKIP-HASH: '%s' != '%s'",
                  trigger_stat->url,
                  stat->url);
        log_debug(__func__, "Pointer comparison: %p != %p", trigger, path);
        return;
    }
    /* The element that triggered DNS resolution must never have a DNS trigger itself. */
    assert(trigger_stat->dns_trigger == NULL);

    if (trigger != path)
    {
        /* This path did not trigger DNS resolution. */
        stat->dns_trigger = strdup(trigger_stat->url_hash);
        log_debug(__func__,
                  "#DNS %s RESOLVED BY %s ",
                  stat->url_hash,
                  trigger_stat->url_hash);
    }
}

int stat_redirect(HURLPath *path,
                  int response_code,
                  char *redirect_url)
{
    ElementStat *stat = (ElementStat *)path->tag;
    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
    }
    /* Copy redirection URL */
    stat->http->redirect_url = strdup(redirect_url);

    /* Use HURL behavior which should reflect test configuration */
    return test->manager->follow_redirect;
}

hurl_hook_error_t stat_pre_connect(HURLPath *path,
                                   HURLConnection *connection)
{
    ElementStat *stat = (ElementStat *)path->tag;

    /* TODO: Check if first element has been downloaded? If not then wait for it. */
    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
    }

    gettimeofday(&stat->http->begin_connect, NULL);

    log_debug(__func__,
              "Began connecting @ %f %s%s",
              timeval_to_msec(&stat->http->begin_connect),
              path->server->domain->domain,
              path->path);

    /* Always allow connect */
    return HURL_HOOK_OK;
}
void stat_post_connect(HURLPath *path,
                       HURLConnection *connection,
                       int retval)
{
    ElementStat *stat = (ElementStat *)path->tag;

    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
    }
    stat_set_dns_trigger(path, connection);

    stat->http->connect_result = retval;
    log_debug(__func__,
              "Setting reused begin_connect for '%s%s'",
              path->server->domain->domain,
              path->path);
    memcpy(&stat->http->begin_connect,
           &connection->begin_connect,
           sizeof(struct timeval));
}

int stat_send_request(HURLPath *path,
                      HURLConnection *connection,
                      int pipelined)
{
    ElementStat *stat = (ElementStat *)path->tag;
    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
        log_debug(__func__,
                  "Initialized stat->http of %s%s",
                  connection->server->domain->domain,
                  path->path);
    }

    stat_set_dns_trigger(path, connection);

    log_debug(__func__,
              "Setting reused begin_connect for '%s%s'",
              path->server->domain->domain,
              path->path);
    memcpy(&stat->http->begin_connect,
           &connection->begin_connect,
           sizeof(struct timeval));

    /* Save connection information
     * It is necessary to updated this information at this point since a request may have been tried on another connection previously.
     * We want to capture the metrics for the connection that was actually used.
     */
    stat->http->connect_time = connection->connect_time;
    stat->http->connect_time_ssl = connection->connect_time_ssl;
    stat->http->connection_reused = connection->reused;
    stat->http->pipelined = pipelined;

    /* Reset download size */
    stat->http->download_size = 0;

    /* Always allow request to be sent. */
    return 1;
}

void stat_header_received(HURLPath *path,
                          int response_code,
                          HURLHeader *headers,
                          size_t header_len)
{
    HURLHeader *h;
    ElementStat *stat = (ElementStat *)path->tag;
    struct tm date;
    Buffer *json = NULL;
    char *tmp;
    char *escaped;
    int tmp_len;

    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
    }

    if (!buffer_init(&json, 1024, 256))
    {
        return;
    }

    buffer_insert_strlen(json, "{");

    stat->http->response_code = response_code;
    stat->http->header_size = header_len;

    /* Check if header data should be ignored. */

    h = headers;
    while (h != NULL)
    {
        if (strcasecmp("date", h->key) == 0)
        {
            strptime(h->value, "%a, %d %b %Y %T %z", &date);
            stat->http->date = mktime(&date);
        }
        else if (strcasecmp("expires", h->key) == 0)
        {
            strptime(h->value, "%a, %d %b %Y %T %z", &date);
            stat->http->expiry_date = mktime(&date);
        }
        else if (test->stats.http.all_headers
            || hurl_header_exists(test->stat_headers, h->key))
        {
            escaped = json_escape(h->value);
            tmp_len = strlen(escaped) + strlen(h->key) + strlen("\"\":\"\",")
                + 1;
            tmp = malloc(sizeof(char) * tmp_len);
            snprintf(tmp, tmp_len, "\"%s\":\"%s\",", h->key, escaped);
            buffer_insert_strlen(json, tmp);
            free(escaped);
            free(tmp);
        }
        /* Specifically extract content type header */
        if (strcasecmp("content-type", h->key) == 0)
        {
            stat->http->content_type = allocstrcpy(h->value,
                                                   strlen(h->value),
                                                   1);
        }
        h = h->next;

    }
    /* Remove last comma */
    if (json->data_len > 1)
    {
        buffer_rewind(json, 1);
    }
    buffer_insert_strlen(json, "}");
    buffer_trim(json);
    stat->http->headers = json->head;
    free(json);
}

void cdn_detect(ElementStat *stat,
                DNSResolverState *dns_state)
{
    int i, j;
    HURLDomain *domain = stat->path->server->domain;
    CDNProvider *cdn = calloc(1, sizeof(CDNProvider));
    for (i = dns_state->nrof_responses - 1; i >= 0; i--)
    {
        DNSMessage *r = dns_state->responses[i];
        for (j = 0; j < r->nrof_answers; j++)
        {
            DNSRecord *a = r->answers[j];
            if (a->type == CNAME)
            {
                if (strstr(a->data, ".edgesuite.net")
                    || strstr(a->data, "g.akamai.net"))
                {
                    /* Akamai detected */
                    *cdn = CDN_AKAMAI;
                    domain->tag = cdn;
                    log_debug(__func__, "Akamai CDN detected.");
                    return;
                }
                else if (strstr(a->data, ".footprint.net"))
                {
                    /* Level 3 detected */
                    *cdn = CDN_LEVEL3;
                    domain->tag = cdn;
                    log_debug(__func__, "Level 3 CDN detected.");
                    return;
                }
                else if (strstr(a->data, ".llnwd.net"))
                {
                    /* Limelight detected */
                    *cdn = CDN_LIMELIGHT;
                    domain->tag = cdn;
                    log_debug(__func__, "Limelight CDN detected.");
                    return;
                }
            }
        }
    }
    free(cdn);
}

void dns_resolve_wrapper(HURLDomain *domain,
                         HURLPath *path)
{
    int retval, i;
    char *final_qname = NULL;
    DNSRecord *record;
    DNSMessage *response = NULL;
    DNSResolverState state;
    struct timeval begin_resolve, end_resolve, exec_time;
    ElementStat *stat = (ElementStat *)path->tag;
    int nrof_addresses = 0;

    log_debug(__func__, "Resolving %s", domain->domain);
    log_debug(__func__,
              "Resolution triggered by %s%s",
              domain->domain,
              path->path);

    /* Check if domain string is actually and IP address */
    domain->addresses = calloc(1, sizeof(struct sockaddr *));
    domain->addresses[0] = calloc(1, sizeof(struct sockaddr));

    if (inet_pton(AF_INET,
                  domain->domain,
                  &((struct sockaddr_in *)domain->addresses[0])->sin_addr) == 1)
    {
        /* The string was actually an IPv4 address */
        nrof_addresses++;
        ((struct sockaddr_in *)domain->addresses[0])->sin_family = AF_INET;
    }
    else if (inet_pton(AF_INET6,
                       domain->domain,
                       &((struct sockaddr_in6 *)domain->addresses[0])->sin6_addr)
        == 1)
    {
        /* The string was actually an IPv6 address */
        nrof_addresses++;
        ((struct sockaddr_in6 *)domain->addresses[0])->sin6_family = AF_INET6;
    }
    else
    {
        /* The string was not an IPv4 or IPv6 address -- continue with DNS lookup */
        free(domain->addresses);
    }

    if (nrof_addresses > 0)
    {
        log_debug(__func__, "URL contained IP address. Skipping DNS lookup...");
        stat->no_hostname = 1;
        domain->nrof_addresses = nrof_addresses;
        domain->dns_state = DNS_STATE_RESOLVED;
        return;
    }

    /* Copy resolver state template. */
    memcpy(&state, test->dns_state_template, sizeof(DNSResolverState));

    gettimeofday(&begin_resolve, NULL);
    retval = dns_resolve(test->cache,
                         &state,
                         domain->domain,
                         test->dns_query_type,
                         &final_qname);
    gettimeofday(&end_resolve, NULL);
    log_debug(__func__, "DNS resolv retval: %d", retval);
    if (retval == DNS_OK)
    {
        domain->dns_state = DNS_STATE_RESOLVED;
        response = state.responses[state.nrof_responses - 1];
        domain->nrof_addresses = dns_count_rr(test->dns_query_type,
                                              ANSWERS,
                                              response);

        /* Allocate memory for address structures */
        if ((domain->addresses = calloc(domain->nrof_addresses,
                                        sizeof(struct sockaddr *))) == NULL)
        {
            domain->dns_state = DNS_STATE_ERROR;
            return;
        }
        for (i = 0; i < response->nrof_answers; i++)
        {
            record = response->answers[i];
            record_debug(__func__, record);
            if (record->type == A)
            {
                domain->addresses[nrof_addresses] =
                    calloc(1, sizeof(struct sockaddr));
                domain->addresses[nrof_addresses++]->sa_family = AF_INET;
                memcpy(&((struct sockaddr_in * ) domain->addresses[i])->sin_addr.s_addr,
                       record->data,
                       record->data_len);
            }
            else if (record->type == AAAA)
            {
                domain->addresses[nrof_addresses] =
                    calloc(1, sizeof(struct sockaddr));
                domain->addresses[nrof_addresses++]->sa_family = AF_INET6;
                memcpy(&((struct sockaddr_in6 * ) domain->addresses[i])->sin6_addr,
                       record->data,
                       record->data_len);
            }
        }

        /* Detect CDN provider */
        cdn_detect(stat, &state);

    }
    else
    {
        domain->dns_state = DNS_STATE_ERROR;
        gettimeofday(&stat->end_transfer, NULL);
    }

    if ((stat->dns = calloc(1, sizeof(DNSStat))) == NULL)
    {
        /* Out of memory */
        /* Free DNS resolver queries and responses. */
        dns_state_reset(&state);
        return;
    }

    /* Save return value */
    stat->dns->return_code = retval;

    /* Calculate DNS execution time. */
    timersub(&end_resolve, &begin_resolve, &exec_time);
    stat->dns->exec_time = timeval_to_msec(&exec_time);
    memcpy(&stat->dns->begin_resolve, &begin_resolve, sizeof(struct timeval));

    /* Get DNS network time. */
    stat->dns->network_time = state.stats.network_time;

    /* Save message and data counters. */
    stat->dns->msg_tx = state.stats.packet_tx;
    stat->dns->msg_rx = state.stats.packet_rx;
    stat->dns->data_tx = state.stats.data_tx;
    stat->dns->data_rx = state.stats.data_rx;

    /* Get query name and final query name */
    stat->dns->qname = strdup(domain->domain);
    stat->dns->qname_final = final_qname; /* Reusing pointer, so dont free() it! */

    /* Get number of domain names resolved in order to resolve the target domain name. */
    stat->dns->queries = state.nrof_queries;

    if (retval == 0)
    {
        /* Get number of A and AAAA records. */
        stat->dns->nrof_answers_a = dns_count_rr(A, ANSWERS, response);
        stat->dns->nrof_answers_aaaa = dns_count_rr(AAAA, ANSWERS, response);

        /* Get first A record and its TTL */
        if ((record = dns_message_find_rr(response, ANSWERS, final_qname, A))
            != NULL)
        {
            stat->dns->answer_a = dns_record_rdata_str(record);
            stat->dns->answer_a_ttl = record->ttl;
        }
        else
        {
            stat->dns->answer_a = calloc(1, sizeof(char));
            stat->dns->answer_a_ttl = -1;
        }

        /* Get first AAAA record and its TTL */
        if ((record = dns_message_find_rr(response, ANSWERS, final_qname, AAAA))
            != NULL)
        {
            stat->dns->answer_aaaa = dns_record_rdata_str(record);
            stat->dns->answer_aaaa_ttl = record->ttl;
        }
        else
        {
            stat->dns->answer_aaaa = calloc(1, sizeof(char));
            stat->dns->answer_aaaa_ttl = -1;
        }
    }
    else
    {
        stat->dns->answer_a = calloc(1, sizeof(char));
        stat->dns->answer_a_ttl = -1;
        stat->dns->answer_aaaa = calloc(1, sizeof(char));
        stat->dns->answer_aaaa_ttl = -1;
    }

    /* Dump DNS trace */
    if (test->stats.dns.trace)
    {
        stat->dns->trace = dns_trace_json(&state);
    }

    /* Free DNS resolver queries and responses. */
    dns_state_reset(&state);
}

void stat_transfer_complete(HURLPath *path,
                            HURLConnection *connection,
                            HURLTransferResult result,
                            size_t content_length,
                            size_t overhead)
{
    struct timeval diff;
#ifdef __linux__
    unsigned int tcp_stats_len = sizeof(struct tcp_info);
#endif
    ElementStat *stat = (ElementStat *)path->tag;

    assert(stat->no_hostname || result == HURL_XFER_DNS
        || (!stat->dns_trigger && stat->dns)
        || (stat->dns_trigger && !stat->dns));

    if (stat->dns_trigger)
    {
        log_debug(__func__,
                  "%s has a DNS trigger: %s",
                  stat->url_hash,
                  stat->dns_trigger);
    }

    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
    }

    /* Save time of completion */
    gettimeofday(&stat->end_transfer, NULL);

    /* Calculate transfer time */
    timersub(&stat->end_transfer, &stat->begin_transfer, &diff);
    stat->http->download_time = timeval_to_msec(&diff);

    /* Calculate ready time */
    timersub(&stat->end_transfer, &test->manager->bgof_exec, &diff);
    stat->http->ready_time = timeval_to_msec(&diff);

    /* Save overhead size - HTTP header + chunking  */
    stat->http->overhead = overhead;

    /* Save tranfer result code */
    stat->http->result = result;

#ifdef __linux__
    if (test->stats.http.tcp_stats)
    {
        if ((stat->http->tcp_stats = calloc(1, sizeof(struct tcp_info))) != NULL)
        {
            if (getsockopt(connection->sock, SOL_TCP, TCP_INFO, (void *) stat->http->tcp_stats, &tcp_stats_len) != 0)
            {
                log_debug(__func__, "Failed to get TCP stats.");
            }
        }
    }
#endif

    /* Fix time to first body byte. */
    if (content_length == 0)
    {
        stat->http->bgof_body = stat->http->bgof_header;
    }
}

void stat_request_sent(HURLPath *path,
                       HURLConnection *connection)
{
    ElementStat *stat = (ElementStat *)path->tag;
    log_debug(__func__,
              "Request sent: %s%s",
              connection->server->domain->domain,
              path->path);
    assert(stat->http != NULL);

    /* Record timestamp of when request was sent. */
    gettimeofday(&stat->begin_transfer, NULL);

    /* TODO: This might be redundant but I'm not sure. */
    gettimeofday(&stat->http->request_sent, NULL);

    assert(stat->no_hostname || (!stat->dns_trigger && stat->dns)
        || (stat->dns_trigger && !stat->dns));

    if (connection->reused)
    {
        log_debug(__func__,
                  "Setting reused begin_connect for '%s%s'",
                  path->server->domain->domain,
                  path->path);
        memcpy(&stat->http->begin_connect,
               &connection->begin_connect,
               sizeof(struct timeval));
    }
}

char *path_filename(HURLPath *path)
{
    char *tmp = NULL;
    char filename[PATH_MAX];
    int i, j = 0;
    int path_len = strlen(path->path);
    if (!getcwd(filename, sizeof(filename)))
    {
        return NULL;
    }
    j = strlen(filename);
    filename[j++] = '/';
    filename[j] = '\0';
    for (i = 1; i < path_len; i++)
    {
        if (path->path[i] == '/' || isspace(path->path[i])
            || isblank(path->path[i]))
        {
            filename[j++] = '-';
        }
        else
        {
            filename[j++] = path->path[i];
        }
    }
    /* Optimize memory allocation */
    tmp = allocstrcpy(filename, j, 1);
    return tmp;

}
/**
 * save the body of the elements
 */
void stat_body_recv(HURLPath *path,
                    char *data,
                    size_t data_len)
{
    char *filename;
    int filename_len;
    ElementStat *stat = (ElementStat *)path->tag;

    assert(stat->no_hostname || (!stat->dns_trigger && stat->dns)
        || (stat->dns_trigger && !stat->dns));

    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
    }

    /* Update download size */
    stat->http->download_size += data_len;

    /* Save data to file */
    if (test->stats.http.save_body)
    {
        if (stat->fp == 0)
        {
            filename_len = strlen(test->body_path) + 1 + strlen(stat->url_hash)
                + strlen(".body") + 1;
            if ((filename = malloc(sizeof(char) * filename_len)) != NULL)
            {
                snprintf(filename,
                         filename_len,
                         "%s/%s.body",
                         test->body_path,
                         stat->url_hash);
                /* Open output file */
                if ((stat->fp = open(filename,
                                     O_WRONLY | O_CREAT,
                                     S_IRUSR | S_IWUSR)) == -1)
                {
                    log_debug(__func__,
                              "Failed to open file '%s': %s",
                              filename,
                              strerror(errno));
                    free(filename);
                    stat->fp = -1; /* Indicate error. */
                    return;
                }
                else
                {
                    log_debug(__func__, "Output path: %s", filename);
                }
            }
            else
            {
                /* Out of memory */
                stat->fp = -1;
                return;
            }
        }
        else if (stat->fp < 0)
        {
            /* We failed to open the file before so let's not try again. */
            return;
        }

        /* Ready to write */
        if (data_len > 0)
        {
            /* log_debug(__func__, "Trying to write %d bytes to file.", data_len); */
            /* Write data */
            ssize_t write_len = write(stat->fp, data, data_len);
            if (write_len != (ssize_t)data_len)
            {
                log_debug(__func__,
                          "Failed to write to '%s': %s",
                          stat->url_hash,
                          strerror(errno));
            }
        }
        else
        {
            /* Close file */
            close(stat->fp);
            stat->fp = 0;
        }
    }
}

void stat_response_code(HURLPath *path,
                        HURLConnection *connection,
                        int response_code,
                        char *response_code_text)
{
    ElementStat *stat = (ElementStat *)path->tag;
    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
    }
    stat->http->response_code = response_code;
}

void stat_response_latency(HURLPath *path,
                           HURLConnection *conn,
                           char *data,
                           size_t data_len)
{
    char *eof_header;
    int first_recv = 0;
#ifndef NDEBUG
    struct timeval diff, now;
#endif
    ElementStat *stat = (ElementStat *)path->tag;

    /* Initialize HTTP statistics */
    if (!stat->http)
    {
        stat->http = calloc(1, sizeof(HTTPStat));
    }

    if (stat->http->bgof_header > 0 && stat->http->bgof_body > 0)
    {
        /* The statistics of interest have already been recorded. */
        return;
    }

    /* Find end of header */
    if (stat->http->header_len == 0)
    {
        eof_header = strstr(data, "\r\n\r\n"); /* TODO Use header offset instead? */
        stat->http->header_len = eof_header - data + 4;
        first_recv = 1;
    }

    if (stat->http->bgof_header == 0)
    {
        /* First header byte received */
        gettimeofday(&now, NULL);
        timersub(&now, &stat->http->request_sent, &diff);
        stat->http->bgof_header = timeval_to_msec(&diff);
        log_debug(__func__,
                  "First header bytes received after %f ms.",
                  stat->http->bgof_header);
    }
    if (stat->http->bgof_body == 0 && stat->http->header_len > 0)
    {
        if (stat->http->header_len < data_len)
        {
            /* First content byte received. */
            if (!first_recv)
            {
                /* The first header and body bytes were NOT received at the same time. */
                gettimeofday(&now, NULL);
            }
            timersub(&now, &stat->http->request_sent, &diff);
            stat->http->bgof_body = timeval_to_msec(&diff);
            log_debug(__func__,
                      "First body bytes received after %f ms.",
                      stat->http->bgof_body);
        }
    }
}

/* TODO: I don't think this function is being used at all */
void stat_transfer_failed(HURLPath *path,
                          HURLConnection *conn,
                          size_t content_len,
                          size_t overhead)
{
    ElementStat *stat = (ElementStat *)path->tag;
    gettimeofday(&stat->end_transfer, NULL);
}
