#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "hurl/hurl.h"
#include "hurl/internal.h"

struct addrinfo resolver_hints_init()
{
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
        .ai_protocol = 0,
        .ai_canonname = NULL,
        .ai_addr = NULL,
        .ai_next = NULL
    };
    return hints;
}

void hurl_resolve(HURLDomain *domain)
{
    struct addrinfo *records, *r;
    struct addrinfo resolver_hints = resolver_hints_init();

    int rc = getaddrinfo(domain->domain, NULL, &resolver_hints, &records);
    if (rc != 0)
    {
        hurl_debug(__func__, "[ %s ] Resolver error: %s", domain->domain,
                   gai_strerror(rc));
        domain->dns_state = DNS_STATE_ERROR;
        return;
    }

    domain->nrof_addresses = 0;
    r = records;
    while (r != NULL)
    {
        domain->nrof_addresses++;
        r = r->ai_next;
    }

    hurl_debug(__func__,
               "[ %s ] Number of addresses: %d",
               domain->domain,
               domain->nrof_addresses);

    if (domain->nrof_addresses > 0)
    {
        domain->addresses = calloc(domain->nrof_addresses,
                                   sizeof(struct sockaddr *));
        if (!domain->addresses)
        {
            domain->dns_state = DNS_STATE_ERROR;
            return;
        }

        int i = 0;
        r = records;
        while (r != NULL)
        {
            domain->addresses[i] = calloc(1, sizeof(struct sockaddr));
            if (!domain->addresses[i])
            {
                domain->dns_state = DNS_STATE_ERROR;
                return;
            }

            memcpy(domain->addresses[i++], r->ai_addr, sizeof(struct sockaddr));

            char address_str[INET6_ADDRSTRLEN];
            if (AF_INET == r->ai_addr->sa_family)
            {
                const void* addr =
                    &((struct sockaddr_in *)r->ai_addr)->sin_addr;
                inet_ntop(AF_INET, addr, address_str, INET6_ADDRSTRLEN);
            }
            else
            {
                const void* addr =
                    &((struct sockaddr_in6*)r->ai_addr)->sin6_addr;
                inet_ntop(AF_INET6, addr, address_str, INET6_ADDRSTRLEN);
            }

            hurl_debug(__func__, "[ %s ] %s", domain->domain, address_str);
            r = r->ai_next;
        }

        freeaddrinfo(records);
        domain->dns_state = DNS_STATE_RESOLVED;
    }
    else
    {
        domain->dns_state = DNS_STATE_ERROR;
    }
}

unsigned char split_domain_name(char *name,
                                char *labels[])
{
    unsigned char nrof_labels = 0;
    char *name_copy = strdup(name);
    char *tmp = name_copy;
    char *progress;
    char *label;

    while ((label = strtok_r(tmp, ".", &progress)) != NULL)
    {
        if (nrof_labels == 127)
        {
            break;
        }

        labels[nrof_labels++] = strdup(label);
        tmp = NULL;
    }

    free(name_copy);
    return nrof_labels;
}
