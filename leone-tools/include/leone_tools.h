#ifndef LEONE_TOOLS_H_
#define LEONE_TOOLS_H_
#include <sys/time.h>
#include <stdarg.h>

/* Return smallest of two values. */
#define MIN(X,Y) X > Y ? Y : X

/* Return largest of two values. */
#define MAX(X,Y) X < Y ? Y : X

typedef struct ht HashTable;
struct ht {
	struct ht_entry **bins; /* Hash table bins. */
	unsigned short nrof_bins;
	unsigned int (*key)(void *); /* Pointer to key function. */
	int (*compare)(void *, void *);
	void (*free)(void *);
};

typedef struct ht_entry HashTableEntry;
struct ht_entry {
	void *key;
	void *value;
	HashTableEntry *prev, *next;
};

/* Insert key-value pair into hash table. */
void *ht_insert(HashTable *table, void *key, void *value);

/* Remove key-value pair from hash table. */
void ht_remove(HashTable *table, void *key);

/* Initialize hash table. */
HashTable *ht_init(unsigned short nrof_bins, unsigned int (*keyfunc)(void *), int (*comparefunc)(void *, void *), void (*freefunc)(void *));

/* Retrieve value from hash table using key. */
void *ht_get(HashTable *table, void *key);

/* Get hash table bin. */
HashTableEntry *ht_get_bin(HashTable *table, unsigned short bin);

/* Free hash table structure. */
void ht_free(HashTable *table);

/* Write debug line containing calling thread ID, function, and a message. */
void log_debug(const char *func, const char *msg, ...);

/* Auto-expanding buffer structure. */
typedef struct buffer Buffer;
struct buffer {
	char *head; /* Beginning of buffer. */
	char *cursor; /* Next unused byte in buffer. */
	char *tail; /* End of allocated memory. */
	unsigned int size; /* Size of allocated memory. Not size of data in buffer.  */
	unsigned int data_len; /* Size of data stored in buffer. Not size of allocated memory. */
	unsigned int increment; /* Minimum size to expand buffer with when calling realloc(). */
};

/* Expand buffer memory allocation.
	 Adjustment > 0 => increase buffer size.
	 Adjustment < 0 => reduce buffer size. */
char buffer_resize(struct buffer *buf, int adjustment);

/* Insert data into buffer. */
void buffer_insert(struct buffer *buf, char *data, unsigned int data_len);

/* Insert NULL-termianted data into buffer and use strlen() to determine length of data. */
void buffer_insert_strlen(struct buffer *buf, char *data);

/* Insert short value into buffer. */
void buffer_insert_short(struct buffer *buf, unsigned short value);

/* Insert integer value into buffer. */
void buffer_insert_int(struct buffer *buf, unsigned int value);

/* Frees memory used by buffer structure.
   free_data == 0 => Only free contron structure.
   free_data == 1 => Free buffer contents in addition to control structure. */
void buffer_free(struct buffer *buf);

/* Initialize buffer.
   Capacity: initial buffer size.
	 Increment: minimum additional memory to allocate when buffer runs out of space. */
int buffer_init(struct buffer **buf, unsigned int capacity, unsigned int increment);

/* Deletes data from the end of a buffer. */
void buffer_rewind(struct buffer *buf, unsigned int count);

/* Reallocates buffer to its minimum size including NULL-terminator. */
char buffer_trim(struct buffer *buf);

/* Rewind buffer to the beginning. */
void buffer_reset(struct buffer *buf);

/* Deletes data from beginning of buffer. */
char buffer_cut_head(struct buffer *buf, unsigned int adjustment);

/* Create printf formated string and add it to buffer. */
void buffer_snprintf(struct buffer *buf, unsigned int n, const char *fmt, ...); /* Formats a string using like printf and inserts it into buffer */

/* Allocate memory and copy string to it. */
char *allocstrcpy(char *str, unsigned int str_len, unsigned int alloc_padding);

#endif /* LEONE_TOOLS_H_ */
