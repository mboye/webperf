#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>
#include "internal/config_parser_common.h"
#include "webperf.h"

static config_parser_rc_t config_timestamp_parse(const char* timestamp)
{
    if (strcasecmp(timestamp, "now") == 0)
    {
        test->timestamp = time(NULL);
    }
    else
    {
        // TODO: Better error handling
        test->timestamp = strtol(timestamp, NULL, 10);
        if (test->timestamp < 0)
        {
            return CONFIG_PARSER_ERROR;
        }
    }

    return CONFIG_PARSER_OK;
}

static int is_unsupported_url_type(char* line)
{
    return (strncasecmp("data:", line, strlen("data:")) == 0);
}

static config_parser_rc_t config_load_urls(const char *file)
{
    ElementStat *element;
    ElementStat *prev_element = test->elements_tail;
    HURLPath *path_created;

    char* urls_data = config_read(file);
    if (!urls_data)
    {
        return CONFIG_PARSER_ERROR;
    }

    char* tokenizer_init = urls_data;
    char* tokenizer_offset = NULL;

    char* url;
    unsigned int line_number = 0;
    while ((url = strtok_r(tokenizer_init, "\n", &tokenizer_offset)) != NULL)
    {
        tokenizer_init = NULL;

        line_number++;

        if (is_comment_line(url))
        {
            continue;
        }

        LOG_DEBUG("URL line: %s", url);

        if (is_unsupported_url_type(url))
        {
            continue;
        }

        if (strlen(url) > 0)
        {
            if (!prev_element)
            {
                element = calloc(1, sizeof(ElementStat));
                test->elements = element;
            }
            else
            {
                element = calloc(1, sizeof(ElementStat));
                element->previous = prev_element;
                prev_element->next = element;
            }

            element->url = strdup(url);

            if (!(path_created = hurl_add_url(test->manager, 0, url, NULL)))
            {
                LOG_DEBUG("Failed to add target URL: %s", url);

                if (element->previous)
                {
                    prev_element = element->previous;
                    prev_element->next = NULL;
                }
                else
                {
                    free(test->elements);
                    test->elements = NULL;
                }

                stat_free(element);
            }
            else
            {
                LOG_DEBUG("Added target URL: %s", url);

                test->nrof_elements++;
                path_created->tag = element;

                element_url_hash(element, path_created);

                element->path = path_created;
                element->http = calloc(1, sizeof(HTTPStat));
                element->http->tls = path_created->server->tls;
                element->http->domain =
                    strdup(path_created->server->domain->domain);
                element->http->port = path_created->server->port;
                element->http->path = strdup(path_created->path);

                prev_element = element;
            }
        }
    }

    test->elements_tail = prev_element;

    return CONFIG_PARSER_OK;
}

config_parser_rc_t config_test_parse(const char* test_key,
                                     const char *value)
{
    if (strcasecmp(test_key, "loadURLs") == 0)
    {
        return config_load_urls(value);
    }
    else if (strcasecmp(test_key, "tag") == 0)
    {
        return config_string_set(&test->tag, value);
    }
    else if (strcasecmp(test_key, "timestamp") == 0)
    {
        return config_timestamp_parse(value);
    }
    else if (strcasecmp(test_key, "timeout") == 0)
    {
        return parse_uint(value, &test->exec_timeout, 1);
    }
    else if (strcasecmp(test_key, "outputFormat") == 0)
    {
        return parse_uint(value, &test->stats.output_format, 0);
    }
    else if (strcasecmp(test_key, "alwaysPrintOutput") == 0)
    {
        return config_parse_boolean(&test->always_print_output, value);
    }
    else
    {
        return CONFIG_PARSER_ERROR;
    }
}
