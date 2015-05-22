/*
 * ht.c
 *
 *  Created on: Mar 15, 2013
 *      Author: root
 */

#include <stdlib.h>
#include <assert.h>
#include "leone_tools.h"

void ht_free(HashTable *table) {
	int i;
	HashTableEntry *entry, *entry_next;
	assert(table != NULL);
	for (i = 0; i < table->nrof_bins; i++) {
		entry = table->bins[i];
		while (entry != NULL ) {
			/* Free value of entry. */
			if (table->free != NULL ) {
				table->free(entry->value);
			} else {
				free(entry->value);
			}
			entry_next = entry->next;
			/* Free entry itself. */
			free(entry->key);
			free(entry);
			entry = entry_next;
		}
	}
	free(table->bins); /* Free bins. */
	free(table);
}

HashTableEntry *ht_get_bin(HashTable *table, unsigned short bin) {
	assert(table != NULL);
	assert(bin < table->nrof_bins);
	return table->bins[bin];
}

void *ht_insert(HashTable *table, void *key, void *value) {
	unsigned int table_key;
	HashTableEntry *entry, *last_entry;
	assert(table != NULL);
	assert(value != NULL);

	/*log_debug(__func__, "Key: '%s' => %d", (char *) key, table->key(key)); */

	table_key = table->key(key) % table->nrof_bins;
	last_entry = table->bins[table_key];
	if (last_entry != NULL ) {
		while (1) {
			/* Check that key is unique within the bin. */
			if (table->compare(last_entry->key, key) == 0) {
				/* Key is not unique, so the value cannot be inserted. */
				return last_entry->value; /* ERROR */
			}
			/* Set next entry. */
			if (last_entry->next != NULL ) {
				last_entry = last_entry->next;
			} else {
				break;
			}
		}
		entry = calloc(1, sizeof(HashTable));
		entry->key = key;
		entry->value = value;
		/* Link new entry with last entry in bin. */
		last_entry->next = entry;
		entry->prev = last_entry;
		return NULL ; /* OK */
	} else {
		entry = calloc(1, sizeof(HashTable));
		entry->key = key;
		entry->value = value;
		table->bins[table_key] = entry;
		return NULL ; /* OK */
	}
}

void ht_remove(HashTable *table, void *key) {
	HashTableEntry *entry, *prev, *next;
	unsigned int table_key;
	assert(table != NULL);
	assert(key != NULL);
	/* Get actual table key using key() function. */
	table_key = table->key(key) % table->nrof_bins;
	entry = table->bins[table_key];
	while (entry != NULL ) {
		/* Search linked list for a key match using the compare() function. */
		if (table->compare(entry->key, key) == 0) {
			/* An element with matching key has been found. */
			/* Link previous and next element together. */
			prev = entry->prev;
			next = entry->next;
			prev->next = next;
			next->prev = prev;

			/* Free entry. */
			if (table->free != NULL ) {
				table->free(entry->value);
			} else {
				free(entry->value);
			}
		}
	}
}

void *ht_get(HashTable *table, void *key) {
	unsigned int table_key;
	HashTableEntry *entry;
	assert(table != NULL);
	assert(key != NULL);
	/* Get actual table key using key() function. */
	table_key = table->key(key) % table->nrof_bins;

	for (entry = table->bins[table_key]; entry != NULL ; entry = entry->next) {
		/* Search linked list for a key match using the compare() function. */
		if (table->compare(entry->key, key) == 0) {
			/* An element with matching key has been found. */
			return entry->value; /* Return pointer to the value of the entry - THIS IS NOT A COPY. */
		}
	}
	return NULL ;
}
HashTable *ht_init(unsigned short nrof_bins, unsigned int (*keyfunc)(void *), int (*comparefunc)(void *, void *), void (*freefunc)(void *)) {
	HashTable *table;

	/* Check function pointers. */
	if (keyfunc == NULL || comparefunc == NULL )
		return NULL ;

	/* Allocate memory for hash table controller. */
	if ((table = calloc(1, sizeof(HashTable))) == NULL ) {
		log_debug(__func__, "Out of memory.");
		return NULL ;
	}

	table->key = keyfunc;
	table->compare = comparefunc;
	table->free = freefunc;
	table->nrof_bins = nrof_bins;
	table->bins = calloc(nrof_bins, sizeof(HashTableEntry *));

	return table;

}
