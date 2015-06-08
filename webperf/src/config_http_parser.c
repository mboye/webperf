#include <stdlib.h>
#include "hurl/hurl.h"
#include "internal/config_parser_common.h"
#include "webperf.h"

static config_parser_rc_t parse_feature_support(HTTPFeatureSupport* result,
                                                const char *value)
{
    int setting;
    config_parser_rc_t rc = config_parse_boolean(&setting, value);

    if (rc == CONFIG_PARSER_OK)
    {
        *result = (setting ? SUPPORTED : UNSUPPORTED);
    }

    return rc;
}

static config_parser_rc_t config_parse_http_header(const char* value)
{
    char *header_key = NULL;
    char *header_value = NULL;

    int split_rc = hurl_header_split_line(value,
                                          strlen(value),
                                          &header_key,
                                          &header_value);

    if (split_rc) {
        // FIXME: Check return code
        hurl_header_add(&test->manager->headers,
                        header_key,
                        header_value);
    }
    else
    {
        LOG_DEBUG("Failed to parse HTTP header '%s'", value);
    }

    free(header_key);
    free(header_value);

    return (split_rc ? CONFIG_PARSER_OK : CONFIG_PARSER_ERROR);
}

config_parser_rc_t config_http_parse(const char* http_key,
                                     const char* value)
{
    if (strcasecmp(http_key, "persistentConnections") == 0)
    {
        return parse_feature_support(&test->manager->feature_persistence, value);
    }
    else if (strcasecmp(http_key, "pipelining") == 0)
    {
        return parse_feature_support(&test->manager->feature_pipelining, value);
    }
    else if (strcasecmp(http_key, "maxPipelining") == 0)
    {
        return parse_uint(value, &test->manager->max_pipeline, 1);
    }
    else if (strcasecmp(http_key, "maxConnections") == 0)
    {
        return parse_uint(value, &test->manager->max_connections, 1);
    }
    else if (strcasecmp(http_key, "maxDomainConnections") == 0)
    {
        return parse_uint(value, &test->manager->max_domain_connections, 1);
    }
    else if (strcasecmp(http_key, "connectTimeout") == 0)
    {
        return parse_int(value, &test->manager->connect_timeout, 1);
    }
    else if (strcasecmp(http_key, "sendTimeout") == 0)
    {
        return parse_int(value, &test->manager->send_timeout, 1);
    }
    else if (strcasecmp(http_key, "recvTimeout") == 0)
    {
        return parse_int(value, &test->manager->recv_timeout, 1);
    }
    else if (strcasecmp(http_key, "maxRetries") == 0)
    {
        return parse_uint(value, &test->manager->max_retries, 0);
    }
    else if (strcasecmp(http_key, "header") == 0)
    {
        return config_parse_http_header(value);
    }
    else if (strcasecmp(http_key, "maxRedirects") == 0)
    {
        return parse_uint(value, &test->manager->max_redirects, 0);
    }
    else if (strcasecmp(http_key, "saveBody") == 0)
    {
        if (strlen(value)  == 0)
        {
            return CONFIG_PARSER_ERROR;
        }

        if (test->body_path)
        {
            free(test->body_path);
        }

        test->body_path = strdup(value);
        test->stats.http.save_body = 1;

        LOG_DEBUG("Saving downloaded files to '%s'", test->body_path);

        return CONFIG_PARSER_OK;
    }
    else if (strcasecmp(http_key, "CAFile") == 0)
    {
        if (strlen(value) == 0)
        {
            return CONFIG_PARSER_ERROR;
        }

        if (test->manager->ca_file)
        {
            free(test->manager->ca_file);
        }

        test->manager->ca_file = strdup(value);

        LOG_DEBUG("OpenSSL will load CAs from '%s'", test->manager->ca_file);

        return CONFIG_PARSER_OK;
    }
    else
    {
        return CONFIG_PARSER_ERROR;
    }
}
