/*
 * hurl_header.h
 *
 *  Created on: Jan 5, 2015
 *      Author: Magnus
 */

#ifndef INCLUDE_HURL_HEADER_H_
#define INCLUDE_HURL_HEADER_H_

/* Add header key-value pair to list of headers. */
int hurl_header_add(HURLHeader **headers, char *key, char *value);

/* Get value of header in list of headers. */
char *hurl_header_get(HURLHeader *headers, char *key);

/* Free memory used by list of headers. */
void hurl_headers_free(HURLHeader *bgof_headers);

/* Split HTTP header line into key and value. */
int hurl_header_split_line(char *line, size_t line_len, char **key, char **value);

/* Check if header key is present in a list of headers. */
int hurl_header_exists(HURLHeader *headers, char *key);


#endif /* INCLUDE_HURL_HEADER_H_ */
