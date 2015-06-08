#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "config_parser.h"

#ifndef WEBPERF_INCLUDE_INTERNAL_CONFIG_PARSER_COMMON_H_
#define WEBPERF_INCLUDE_INTERNAL_CONFIG_PARSER_COMMON_H_

config_parser_rc_t config_dns_parse(char *dns_key,
                                    char *value);

config_parser_rc_t config_http_parse(const char* http_key,
                                     const char* value);

config_parser_rc_t config_test_parse(const char* test_key,
                                     const char *value);

config_parser_rc_t config_stats_parse(const char* stats_key,
                                      const char *value);

static inline int is_comment_line(const char *line)
{
    return (line == NULL ||
            line[0] == '#');
}

static inline config_parser_rc_t parse_int(const char *value_str,
                                           int *result,
                                           int min)
{
    long value = strtol(value_str, NULL, 10);
    if (value == LONG_MIN ||
        value > INT_MAX ||
        value < min)
    {
        return CONFIG_PARSER_ERROR;
    }
    else
    {
        *result = (int)value;
        return CONFIG_PARSER_OK;
    }
}

static inline config_parser_rc_t parse_uint(const char *value_str,
                                            unsigned int *result,
                                            const unsigned int min)
{
    unsigned long value = strtoul(value_str, NULL, 10);
    if (value == ULONG_MAX ||
        value > UINT_MAX ||
        value < min)
    {
        return CONFIG_PARSER_ERROR;
    }
    else
    {
        *result = (unsigned int)value;
        return CONFIG_PARSER_OK;
    }
}

static inline config_parser_rc_t config_parse_boolean(int *boolean,
                                const char *value)
{
    int yes = strcasecmp("yes", value) == 0 ||
              strcasecmp("true", value) == 0 ||
              strcasecmp("on", value) == 0;

    int no = strcasecmp("no", value) == 0 ||
               strcasecmp("false", value) == 0 ||
               strcasecmp("off", value) == 0;

    if (yes)
    {
        *boolean = 1;
    }
    else if (no)
    {
        *boolean = 0;
    }
    else
    {
        return CONFIG_PARSER_ERROR;
    }

    return CONFIG_PARSER_OK;
}

static inline config_parser_rc_t config_string_set(char** setting,
                                                   const char *value)
{
    if (strlen(value) == 0)
    {
        return CONFIG_PARSER_ERROR;
    }

    if (*setting)
    {
        free(*setting);
    }

    *setting = strdup(value);
    return CONFIG_PARSER_OK;
}

static inline char* config_read(const char* file) {
    char* config_data = NULL;

    struct stat file_properties;
    if (stat(file, &file_properties) != 0)
    {
        return NULL;
    }

    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        goto error;
    }

    size_t file_size = (size_t)file_properties.st_size;
    config_data = malloc(file_size);

    size_t remaining_bytes = file_size;
    size_t offset_bytes = 0;
    while (remaining_bytes > 0)
    {
        ssize_t bytes_read = read(fd, config_data + offset_bytes, remaining_bytes);
        if (bytes_read == 0)
        {
            break;
        }
        else if (bytes_read < 0)
        {
            goto error;
        }
    }

    close(fd);

    return config_data;

error:
    free(config_data);

    if (fd > 0)
    {
        close(fd);
    }

    printf("Failed to open/read '%s': %s\n", file, strerror(errno));
    return NULL;
}

#endif /* WEBPERF_INCLUDE_INTERNAL_CONFIG_PARSER_COMMON_H_ */
