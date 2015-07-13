#include <hurl/hurl.h>
#include <hurl/internal/hurl_parse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

void hurl_parsed_url_free(HURLParsedURL *url)
{
    free(url->hostname);
    free(url->path);
    free(url->protocol);
}

hurl_url_parser_error_t parse_protocol(HURLParsedURL *parsed_url,
                                       const char* bgof_url)
{
    parsed_url->protocol = NULL;
    parsed_url->port = 0;

    char* eof_protocol = strstr(bgof_url, "://");
    if (!eof_protocol)
    {
        return HURL_URL_PARSER_ERROR_PROTOCOL;
    }

    ssize_t protocol_len =  eof_protocol - bgof_url;
    if (protocol_len == 0)
    {
        return HURL_URL_PARSER_ERROR_PROTOCOL;
    }

    int is_http = (strncasecmp("http", bgof_url, strlen("http")) == 0);
    int is_https = (strncasecmp("https", bgof_url, strlen("https")) == 0);

    if (!is_http && !is_https)
    {
        return HURL_URL_PARSER_ERROR_PROTOCOL;
    }

    protocol_len++;
    parsed_url->protocol = malloc(sizeof(char) * (size_t)protocol_len);
    snprintf(parsed_url->protocol, protocol_len, "%s", bgof_url);

    return HURL_URL_PARSE_OK;
}

hurl_url_parser_error_t parse_hostname(HURLParsedURL* parsed_url,
                                       const char* bgof_hostname,
                                       const char* eof_url)
{
    parsed_url->hostname = NULL;

    char* bgof_path = strstr(bgof_hostname, "/");
    char* bgof_port = strstr(bgof_hostname, ":");

    const char *eof_hostname;
    if (bgof_port)
    {
        if (bgof_port < bgof_path)
        {
            eof_hostname = bgof_port;
        }
        else
        {
            eof_hostname = bgof_path;
        }
    }
    else if (bgof_path)
    {
        eof_hostname = bgof_path;
    }
    else
    {
        eof_hostname = eof_url;
    }

    ssize_t hostname_len = eof_hostname - bgof_hostname;
    if (hostname_len == 0)
    {
        return HURL_URL_PARSER_ERROR_HOSTNAME;
    }

    hostname_len++;
    parsed_url->hostname = malloc(sizeof(char) * (size_t)hostname_len);
    if (!parsed_url->hostname)
    {
        return HURL_URL_PARSER_ERROR_MEMORY;
    }

    snprintf(parsed_url->hostname, hostname_len, "%s", bgof_hostname);

    return HURL_URL_PARSER_ERROR_NONE;
}

hurl_url_parser_error_t parse_port(HURLParsedURL* parsed_url,
                                   const char* eof_hostname,
                                   const char* eof_url)
{
    uint16_t* port = &parsed_url->port;

    if (eof_hostname[0] == '/' ||
        eof_hostname == eof_url)
    {
        if (strcasecmp("http", parsed_url->protocol) == 0)
        {
            *port = 80;
        }
        else if (strcasecmp("https", parsed_url->protocol) == 0)
        {
            *port = 443;
        }

        return HURL_URL_PARSER_ERROR_NONE;
    }
    else
    {
        assert(eof_hostname[0] == ':');

        const char* bgof_port = eof_hostname + 1;
        char* eof_port;

        char* bgof_path = strstr(bgof_port, "/");
        if (bgof_path)
        {
            eof_port = bgof_path;
        }
        else
        {
            eof_port = (char *)eof_url;
        }

        unsigned long parsed_port = strtoul(bgof_port, &eof_port, 10);

        int is_valid_port = parsed_port > 0 &&
                            parsed_port < UINT16_MAX;

        if (is_valid_port)
        {
            *port = (uint16_t)parsed_port;
            return HURL_URL_PARSER_ERROR_NONE;
        }
        else
        {
            *port = 0;
            return HURL_URL_PARSER_ERROR_PORT;
        }
    }
}

hurl_url_parser_error_t parse_path(HURLParsedURL *result,
                                   const char* eof_hostname,
                                   const char* eof_url)
{
    assert(eof_hostname);

    char* bgof_path = strstr(eof_hostname, "/");
    if(bgof_path)
    {
        ssize_t path_len = eof_url - bgof_path + 1;

        result->path = malloc(sizeof(char) * (size_t)path_len);
        if (!result->path)
        {
            return HURL_URL_PARSER_ERROR_MEMORY;
        }

        snprintf(result->path, path_len, "%s", bgof_path);
    }
    else
    {
        result->path = strdup("/");
    }

    return HURL_URL_PARSER_ERROR_NONE;
}

hurl_url_parser_error_t hurl_parse_url(const char* url,
                                       HURLParsedURL* parsed_url)
{
    typedef enum parsing_state_e {
        PARSE_PROTOCOL,
        PARSE_HOSTNAME,
        PARSE_PORT,
        PARSE_PATH,
        PARSE_COMPLETE
    } parsing_state_t;

    memset(parsed_url, 0, sizeof(HURLParsedURL));

    const char* eof_url = url + strlen(url);
    const char* eof_hostname = NULL;
    hurl_url_parser_error_t rc = HURL_URL_PARSER_ERROR_NONE;

    for (parsing_state_t state = PARSE_PROTOCOL; state != PARSE_COMPLETE; state++)
    {
        switch (state)
        {
            case PARSE_PROTOCOL:
                rc = parse_protocol(parsed_url, url);
                break;
            case PARSE_HOSTNAME:
            {
                const char* bgof_hostname = url +
                                            strlen(parsed_url->protocol) +
                                            strlen("://");

                rc = parse_hostname(parsed_url, bgof_hostname, eof_url);
            }
                break;
            case PARSE_PORT:
                eof_hostname = url +
                               strlen(parsed_url->protocol) +
                               strlen("://") +
                               strlen(parsed_url->hostname);

                rc = parse_port(parsed_url, eof_hostname, eof_url);
                break;
            case PARSE_PATH:
                rc = parse_path(parsed_url, eof_hostname, eof_url);
                break;
            case PARSE_COMPLETE:
                break;
        }

        if (rc != HURL_URL_PARSER_ERROR_NONE)
        {
            free(parsed_url->protocol);
            free(parsed_url->hostname);
            free(parsed_url->path);

            return rc;
        }
    }

    return HURL_URL_PARSER_ERROR_NONE;
}
