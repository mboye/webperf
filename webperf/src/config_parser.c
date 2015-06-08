#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "config_parser.h"
#include "internal/config_parser_common.h"
#include "webperf.h"

static int is_end_of_key(const char c)
{
    return (c == '=');
}

static config_parser_rc_t parse_key_value(char **key, char **value, const char *line)
{
    *key = NULL;
    *value = NULL;

    size_t line_length = strlen(line);

    for (size_t j = 0; j < line_length; j++)
    {
        if (is_end_of_key(line[j]))
        {
            size_t key_length = j;
            *key = malloc(sizeof(char) * (key_length + 1));
            memcpy(*key, line, sizeof(char) * key_length);
            (*key)[key_length] = '\0';

            size_t value_length = line_length - key_length - 1;
            *value = malloc(sizeof(char) * (value_length + 1));
            memcpy(*value, line + key_length + 1, value_length);
            (*value)[value_length] = '\0';

            return CONFIG_PARSER_OK;
        }
    }

    return CONFIG_PARSER_ERROR;
}

config_parser_rc_t config_parse(char *config_file) {
    char *config_data = config_read(config_file);

    if (!config_data)
    {
        return CONFIG_PARSER_ERROR;
    }

    int line_number = 0;
    char *tokenizer_offset = NULL;
    char *tokenizer_init = config_data;
    char *config_line;

    while ((config_line = strtok_r(tokenizer_init, "\n", &tokenizer_offset)) != NULL)
    {
        tokenizer_init = NULL;
        line_number++;

        if (is_comment_line(config_line))
        {
            continue;
        }

        LOG_DEBUG("Configuration line: %s", config_line);

        char *config_key;
        char *config_value;

        int kv_parse_rc =
            parse_key_value(&config_key, &config_value, config_line);

        if (kv_parse_rc != CONFIG_PARSER_OK)
        {
            printf("Failed to parse key-value pair on line %d\n", line_number);
            return CONFIG_PARSER_ERROR;
        }

        config_parser_rc_t parser_rc = CONFIG_PARSER_ERROR;

        if (strncmp("dns.", config_key, 4) == 0)
        {
            parser_rc = config_dns_parse(config_key + strlen("dns."),
                                         config_value);
        }
        else if (strncmp("http.", config_key, strlen("http.")) == 0)
        {
            parser_rc = config_http_parse(config_key + strlen("http."),
                                          config_value);
        }
        else if (strncmp("test.", config_key, strlen("test.")) == 0)
        {
            parser_rc = config_test_parse(config_key + strlen("http."),
                                          config_value);
        }
        else if (strncmp("stats.", config_key, strlen("stats.")) == 0)
        {
            parser_rc = config_stats_parse(config_key + strlen("stats."),
                                           config_value);
        }

        if (parser_rc != CONFIG_PARSER_OK)
        {
            LOG_DEBUG("Configuration parsing failed on line %d: %s",
                      line_number,
                      config_line);

            return CONFIG_PARSER_ERROR;
        }
    }

    return CONFIG_PARSER_OK;
}
