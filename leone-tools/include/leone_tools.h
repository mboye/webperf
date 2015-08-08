#ifndef LEONE_TOOLS_H_
#define LEONE_TOOLS_H_
#include <sys/time.h>
#include <stdarg.h>
#include <stdio.h>

/* Return smallest of two values. */
#define MIN(X,Y) X > Y ? Y : X

/* Return largest of two values. */
#define MAX(X,Y) X < Y ? Y : X

/* Write debug line containing calling thread ID, function, and a message. */
void log_debug(const char *func,
               const char *msg,
               ...);

/* Auto-expanding buffer structure. */
typedef struct buffer Buffer;
struct buffer
{
    char *head; /* Beginning of buffer. */
    char *cursor; /* Next unused byte in buffer. */
    char *tail; /* End of allocated memory. */
    size_t size; /* Size of allocated memory. Not size of data in buffer.  */
    size_t data_len; /* Size of data stored in buffer. Not size of allocated memory. */
    size_t increment; /* Minimum size to expand buffer with when calling realloc(). */
};

/* Expand buffer memory allocation.
 Adjustment > 0 => increase buffer size.
 Adjustment < 0 => reduce buffer size. */
char buffer_resize(struct buffer *buf,
                   ssize_t adjustment);

/* Insert data into buffer. */
void buffer_insert(struct buffer *buf,
                   const char *data,
                   size_t data_len);

/* Insert NULL-terminated data into buffer and use strlen() to determine length of data. */
void buffer_insert_strlen(struct buffer *buf,
                          const char *data);

/* Insert short value into buffer. */
void buffer_insert_short(struct buffer *buf,
                         unsigned short value);

/* Insert integer value into buffer. */
void buffer_insert_int(struct buffer *buf,
                       unsigned int value);

void buffer_free(struct buffer *buf);

/* Initialize buffer.
 Capacity: initial buffer size.
 Increment: minimum additional memory to allocate when buffer runs out of space. */
int buffer_init(struct buffer **buf,
                size_t capacity,
                size_t increment);

/* Deletes data from the end of a buffer. */
void buffer_rewind(struct buffer *buf,
                   unsigned int count);

/* Reallocates buffer to its minimum size including NULL-terminator. */
char buffer_trim(struct buffer *buf);

/* Rewind buffer to the beginning. */
void buffer_reset(struct buffer *buf);

/* Deletes data from beginning of buffer. */
char buffer_cut_head(struct buffer *buf,
                     unsigned int adjustment);

/* Create printf formated string and add it to buffer. */
void buffer_snprintf(struct buffer *buf,
                     unsigned int n,
                     const char *fmt,
                     ...); /* Formats a string using like printf and inserts it into buffer */

/* Allocate memory and copy string to it. */
char *allocstrcpy(const char *str,
                  size_t str_len,
                  size_t alloc_padding);

#endif /* LEONE_TOOLS_H_ */
