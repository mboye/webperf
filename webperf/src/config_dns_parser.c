#include <stdlib.h>
#include "dns_core.h"
#include "dns_support.h"
#include "dns_cache.h"
#include "internal/config_parser_common.h"
#include "webperf.h"

#define DNS_TIMEOUT_MIN_MS 1

static config_parser_rc_t config_dns_timeout_parse(const char *value)
{
    char *value_copy = strdup(value);
    char *tokenizer_init = value_copy;
    char *tokenizer_offset = NULL;
    char *token;

    size_t timeout_index = 0;

    config_parser_rc_t rc = CONFIG_PARSER_ERROR;

    while ((token = strtok_r(tokenizer_init, " ", &tokenizer_offset)) != NULL)
    {
        tokenizer_init = NULL;

        if (timeout_index >= sizeof(test->dns_state_template->timeout))
        {
            LOG_DEBUG("Warning: Number of supported DNS timeout values exceeded (%d).",
                   DNS_MAX_SEND_COUNT);
            break;
        }

        rc = parse_uint(token,
                        &test->dns_state_template->timeout[timeout_index],
                        DNS_TIMEOUT_MIN_MS);

        if (rc == CONFIG_PARSER_OK)
        {
            LOG_DEBUG("Timeout #%d is %u ms",
                      timeout_index,
                      test->dns_state_template->timeout[timeout_index]);
            timeout_index++;
        }
        else
        {
            LOG_DEBUG("Failed to parse DNS timeout value '%s'.", token);
            break;
        }
    }

    free(value_copy);

    return rc;
}

static config_parser_rc_t config_dns_query_type_parse(const char *value)
{
    if (strcasecmp(value, "v4") == 0)
    {
        test->dns_query_type = A;
    }
    else if (strcasecmp(value, "v6") == 0)
    {
        test->dns_query_type = AAAA;
    }
    else
    {
        return CONFIG_PARSER_ERROR;
    }

    return CONFIG_PARSER_OK;
}

static config_parser_rc_t config_dns_network_preference_parse(const char *value)
{
    NetworkPreference preference = DEFAULT;

    if (strcasecmp(value, "v4") == 0)
    {
        preference = IPv4;
    }
    else if (strcasecmp(value, "v6") == 0)
    {
        preference = IPv6;
    }
    else if (strcasecmp(value, "v4v6") == 0)
    {
        preference = IPv46;
    }
    else if (strcasecmp(value, "v6v4") == 0)
    {
        preference = IPv64;
    }
    else if (strcasecmp(value, "default") == 0)
    {
        preference = DEFAULT;
    }
    else
    {
        return CONFIG_PARSER_ERROR;
    }

    test->dns_state_template->nwp = preference;

    return CONFIG_PARSER_OK;
}

config_parser_rc_t config_dns_parse(char *dns_key,
                                    char *value)
{
    if (strcasecmp(dns_key, "resolvconf") == 0)
    {
        int rc = dns_load_resolv_conf(test->cache, value);
        if (rc != DNS_OK)
        {
            return CONFIG_PARSER_ERROR;
        }

        test->dns_state_template->recurse = 1;

        return CONFIG_PARSER_OK;
    }
    else if (strcasecmp(dns_key, "timeout") == 0)
    {
        return config_dns_timeout_parse(value);
    }
    else if (strcasecmp(dns_key, "loadCache") == 0)
    {
        int rc = dns_cache_load(&test->cache, value);
        if (rc != DNS_OK)
        {
            return CONFIG_PARSER_ERROR;
        }
        else
        {
            return CONFIG_PARSER_OK;
        }
    }
    else if (strcasecmp(dns_key, "recurse") == 0)
    {
        int recurse;

        config_parser_rc_t rc = config_parse_boolean(&recurse, value);
        if (rc == CONFIG_PARSER_OK)
        {
            test->dns_state_template->recurse = (unsigned short)recurse;
        }

        return rc;
    }
    else if (strcasecmp(dns_key, "networkPreference") == 0)
    {
        return config_dns_network_preference_parse(value);
    }
    else if (strcasecmp(dns_key, "queryType") == 0)
    {
        return config_dns_query_type_parse(value);
    }
    else
    {
        return CONFIG_PARSER_ERROR;
    }
}
