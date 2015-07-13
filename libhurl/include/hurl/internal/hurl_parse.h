#ifndef HURL_PARSE_H_
#define HURL_PARSE_H_

#include <stdint.h>

typedef enum hurl_url_parser_error_e
{
    HURL_URL_PARSER_ERROR_NONE,
    HURL_URL_PARSER_ERROR_MEMORY,
    HURL_URL_PARSER_ERROR_PROTOCOL,
    HURL_URL_PARSER_ERROR_HOSTNAME,
    HURL_URL_PARSER_ERROR_PORT,
    HURL_URL_PARSER_HOSTNAME_LENGTH
} hurl_url_parser_error_t;

typedef struct hurl_parsed_url
{
    char *protocol;
    char *hostname;
    uint16_t port;
    char *path;
} HURLParsedURL;

void hurl_parsed_url_free(HURLParsedURL *url);

hurl_url_parser_error_t parse_protocol(HURLParsedURL *parsed_url,
                                       const char* bgof_url);

hurl_url_parser_error_t parse_hostname(HURLParsedURL* parsed_url,
                                       const char* bgof_hostname,
                                       const char* eof_url);

hurl_url_parser_error_t parse_port(HURLParsedURL* parsed_url,
                                   const char* eof_hostname,
                                   const char* eof_url);

hurl_url_parser_error_t parse_path(HURLParsedURL *result,
                                   const char* eof_hostname,
                                   const char* eof_url);

hurl_url_parser_error_t hurl_parse_url(const char* url,
                                       HURLParsedURL* parsed_url);

#endif
