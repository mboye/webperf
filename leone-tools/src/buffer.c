#include "leone_tools.h"
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef __linux
#include <endian.h>
#elif __APPLE__
#include <machine/endian.h>
#endif

int buffer_init(struct buffer **buf,
                size_t size,
                size_t increment)
{
    struct buffer *tmp;
    if ((tmp = malloc(sizeof(struct buffer))) == NULL)
    {
        return 0;
    }
    if ((tmp->head = malloc(size)) == NULL)
    {
        free(tmp);
        return 0;
    }
    tmp->cursor = tmp->head;
    tmp->increment = increment;
    tmp->tail = tmp->head + size;
    tmp->size = size;
    tmp->data_len = 0;
    *tmp->head = '\0';

    /* Set pointer. */
    *buf = tmp;
    return 1;
}

/* Reallocates buffer to its minimum size including string termination \0. */
char buffer_trim(struct buffer *buf)
{
    assert(buf!=NULL);
    if (buf->data_len > 0)
    {
        ssize_t adjustment = (ssize_t)buf->data_len - (ssize_t)buf->size;
        return buffer_resize(buf, adjustment);
    }
    else
    {
        free(buf->head);
        if ((buf->head = calloc(1, sizeof(char))) != NULL)
        {
            buf->cursor = buf->head;
            buf->data_len = 0;
            buf->size = 1;
            buf->tail = buf->head + buf->size;
            return 1;
        }
    }
    return 0;

}

void buffer_free(struct buffer *buf)
{
    /* Free buffer storage. */
    free(buf->head);
    /* Free buffer structure. */
    free(buf);
}

void buffer_rewind(struct buffer *buf,
                   unsigned int count)
{
    /* Sanity check. */
    assert(buf != NULL);
    assert(buf->data_len >= count);
    /* log_debug(__func__, "Rewinding buffer with %u B.", count); */
    /* Update pointers. */
    buf->data_len -= count;
    buf->cursor -= count;
    /* Terminate string. */
    *buf->cursor = '\0';
}

void buffer_reset(struct buffer *buf)
{
    assert(buf!=NULL);
    buf->data_len = 0;
    buf->cursor = buf->head;
    buf->cursor[0] = '\0';
}

void buffer_insert(struct buffer *buf,
                   const char *data,
                   size_t data_len)
{
    /* Check if there is enough space in buffer. */
    size_t buffer_space = buf->size - buf->data_len - 1;
    if (buffer_space < data_len)
    {
        size_t adjustment = (1 + data_len / buf->increment) * buf->increment;
        buffer_resize(buf, adjustment);
    }

    /* Insert data into buffer. */
    memcpy(buf->cursor, data, data_len);
    /* Update pointers. */
    buf->cursor += data_len;
    buf->data_len += data_len;
    /* Terminate string. */
    *buf->cursor = '\0';
    /* log_debug(__func__, "Insert OK."); */
}

void buffer_insert_strlen(struct buffer *buf,
                          const char *data)
{
    buffer_insert(buf, data, strlen(data));
}

void buffer_insert_short(struct buffer *buf,
                         unsigned short value)
{
    buffer_insert(buf, (char *)&value, 2);
    /* TODO: This was changed, so if every breaks this is the problem. */
}

void buffer_insert_int(struct buffer *buf,
                       unsigned int value)
{
    buffer_insert(buf, (char *)&value, 4);
}

char buffer_resize(struct buffer *buf,
                   ssize_t adjustment)
{
    char *tmp;
    ssize_t new_buffer_size = (ssize_t)buf->size + adjustment + 1;
    assert(new_buffer_size > 0);

    /* New buffer size must be greater than zero. */
    if ((tmp = realloc(buf->head, (size_t)new_buffer_size)) != NULL)
    {
        buf->size += adjustment;
        buf->head = tmp;
        buf->tail = buf->head + buf->size;
        buf->cursor = buf->head + buf->data_len;
        *buf->cursor = '\0';
        return 1;
    }
    return 0;
}

char buffer_cut_head(struct buffer *buf,
                     unsigned int adjustment)
{
    size_t new_size;
    char *tmp;
    assert(buf!=NULL);
    assert(adjustment <= buf->data_len);
    /* Remove bytes from the beginning of buffer. */
    new_size = buf->data_len - adjustment + 1;
    /* Allocate new buffer. */
    if ((tmp = calloc(new_size, sizeof(char))) != NULL)
    {
        /* Copy old data. */
        memcpy(tmp, buf->head + adjustment, buf->data_len - adjustment);
        tmp[new_size] = '\0';
        /* Free old buffer. */
        free(buf->head);
        buf->head = tmp;
        buf->size += new_size - 1;
        buf->tail = buf->head + buf->size;
        buf->data_len -= adjustment;
        buf->cursor = buf->head + buf->data_len;
        return 1;
    }
    return 0;

}

void buffer_snprintf(struct buffer *buf,
                     unsigned int n,
                     const char *template,
                     ...)
{
    char *str;
    va_list args;

    /* Create formated string */
    str = malloc(sizeof(char) * n);
    va_start(args, template);
    vsnprintf(str, n - 1, template, args);
    va_end(args);

    /* Insert string into buffer */
    buffer_insert(buf, str, strlen(str));
    free(str);

}
