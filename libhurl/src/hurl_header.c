#include <stdlib.h>
#include <limits.h>
#include "hurl/hurl.h"
#include "hurl/internal.h"

void hurl_headers_free(HURLHeader *bgof_headers)
{
    HURLHeader *h = bgof_headers, *next;
    while (h != NULL)
    {
        next = h->next;
        free(h->key);
        free(h->value);
        free(h);
        h = next;
    }
}

HURLHeader *hurl_headers_copy(HURLHeader *headers)
{
    HURLHeader *h = headers, *copy = NULL, *c, *copy_tail = NULL;
    while (h != NULL)
    {
        if ((c = calloc(1, sizeof(HURLHeader))) == NULL)
        {
            hurl_headers_free(copy);
            return NULL;
        }
        if ((c->key = hurl_allocstrcpy(h->key, strlen(h->key), 1)) == NULL)
        {
            free(c);
            hurl_headers_free(copy);
        }
        if ((c->value = hurl_allocstrcpy(h->value, strlen(h->value), 1)) == NULL)
        {
            free(c->key);
            free(c);
            hurl_headers_free(copy);
        }

        if (copy_tail == NULL)
        {
            copy = c;
            copy_tail = copy;
        }
        else
        {
            copy_tail->next = c;
            c->previous = copy_tail;
            copy_tail = c;
        }
        h = h->next;
    }
    return copy;
}

char *hurl_header_get(HURLHeader *headers,
                      const char *key)
{
    HURLHeader *h;
    if (headers == NULL)
    {
        return NULL;
    }
    h = headers;
    while (h != NULL)
    {
        if (strcasecmp(h->key, key) == 0)
        {
            return h->value;
        }
        h = h->next;
    }
    return NULL;
}

int hurl_header_split_line(const char *line,
                           size_t line_len,
                           char **key,
                           char **value)
{
    int i = 0;
    int bgof_value = 0;
    int value_len = -1;
    for (i = 0; i < (int)line_len - 1; i++)
    {
        /* Find end of key. */
        /* if (!bgof_value && line[i] == ':' && line[i + 1] == ' ') { */
        if (!bgof_value && line[i] == ':')
        {
            if ((*key = hurl_allocstrcpy(line, (size_t)i, 1)) != NULL)
            {
                if (line[i + 1] == ' ')
                {
                    bgof_value = i + 2;
                    i++;
                }
                else
                {
                    bgof_value = i + 1;
                }
            }
            else
            {
                return 0;
            }
        }
        else if (bgof_value && line[i] == '\r' && line[i + 1] == '\n')
        {
            /* HTTP newline */
            value_len = (int)(i - bgof_value);
        }
        else if (bgof_value && line[i] == '\n')
        {
            /* Regular newline */
            value_len = i - bgof_value;
        }

    }
    if (bgof_value)
    {
        if (value_len == -1)
        {
            /* Line terminator is missing */
            value_len = (int)line_len - bgof_value;
        }
        if ((*value = hurl_allocstrcpy(line + bgof_value, (size_t)value_len, 1))
            == NULL)
        {
            free(*key);
            *key = NULL;
            *value = NULL;
            return 0;
        }
        else
        {
            /* hurl_debug(__func__, "HEADER: %s => %s", *key, *value); */
            return 1;
        }
    }
    return 0;
}

int hurl_header_exists(HURLHeader *headers,
                       char *key)
{
    HURLHeader *h_search;
    for (h_search = headers; h_search != NULL; h_search = h_search->next)
    {
        if (strcasecmp(key, h_search->key) == 0)
        {
            return 1;
        }
    }
    return 0;
}

int hurl_header_add(HURLHeader **headers,
                    const char *key,
                    const char *value)
{
    HURLHeader *header, *h = NULL;
    int updated = 0;

    /* Check for duplicate headers. */
    h = *headers;
    while (h != NULL && h->next != NULL)
    {
        if (strcasecmp(h->key, key) == 0)
        {
            /* Duplicate detected: Overwrite previous value. */
            free(h->value);
            h->value = hurl_allocstrcpy(value, strlen(value), 1);
            updated = 1;
            break;
        }
        h = h->next;
    }
    if (!updated)
    {
        if ((header = calloc(1, sizeof(HURLHeader))) == NULL)
        {
            return 0;
        }
        header->key = hurl_allocstrcpy(key, strlen(key), 1);
        header->value = hurl_allocstrcpy(value, strlen(value), 1);
        /* Add header to linked list. */
        if (h != NULL)
        {
            h->next = header;
            header->previous = h;
        }
        else
        {
            /* This is the first item in the list. */
            *headers = header;
        }
        return 1;
    }
    else
    {
        return 1;
    }
}

int hurl_header_str(HURLHeader *headers,
                    char *buffer,
                    size_t buffer_len)
{
    HURLHeader *h = headers;
    size_t print_len = 0;
    size_t header_len;
    while (h != NULL && print_len < buffer_len)
    {
        /* size of key + ": " + size of value + "\r\n" + final "\r\n" + \0 */
        header_len = strlen(h->key) + 2 + strlen(h->value) + 2 + 2 + 1;
        if (buffer_len >= print_len + header_len)
        {
            print_len += (size_t)snprintf(buffer + print_len,
                                          buffer_len - print_len,
                                          "%s: %s\r\n",
                                          h->key,
                                          h->value);
        }
        else
        {
            /* The buffer is full. */
            return -1;
        }
        h = h->next;
    }
    /* Add final \r\n */
    print_len += (size_t)snprintf(buffer + print_len,
                                  buffer_len - print_len,
                                  "\r\n");
    return (int)print_len;
}

int hurl_parse_response_code(char *line,
                             char **code_text)
{
    long response_code;
    char *str, *copy, *part, *eof_part;
    char *split_str_ptr = NULL;
    int offset = 0;
    copy = hurl_allocstrcpy(line, strlen(line), 1);
    str = copy;

    /* Get response code. */
    part = strtok_r(str, " ", &split_str_ptr);
    offset += strlen(part) + 1;
    part = strtok_r(NULL, " ", &split_str_ptr);
    offset += strlen(part);
    response_code = (int)strtol(part, &eof_part, 10);
    if (response_code == LONG_MIN || response_code == LONG_MAX
        || response_code <= 0 || response_code > INT_MAX)
    {
        free(copy);
        hurl_debug(__func__, "Failed to parse response code.");
        return -1;
    }
    /* Get response code text. */
    if (code_text != NULL && strlen(line + offset + 1) > 0)
    {
        *code_text = hurl_allocstrcpy(line + offset + 1,
                                      strlen(line + offset + 1),
                                      1);
    }
    free(copy);
    return response_code;
}
