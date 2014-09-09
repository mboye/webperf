
**HURL Design**
===
This document aims to explain the design of HURL so that others contribute to the continued development of the library.

Use of threads
---
HURL relies on threads for all parallel operations.
When a URL is added to to HURL using [hurl_add_url()](#hurl_add_url) a tree structure is created with the [HURLManager](#HURLManager) structure as the root. When a URL is added three structures are created ad linked to a HURLManager: ```HURLDomain -> HURLServer -> HURLPath``` .

HURLDomain and HURLServer structures are initialized as needed.

When calling [hurl_exec() ](#hurl_exec) a thread is created for each distinct [HURLDomain](#HURLDomain) structure by calling pthread_create() with [hurl_domain_exec()](#hurl_domain_exec) as the function to start in the new thread, and a pointer to a [HURLDomain](#HURLDomain) structure.


Connection limits
---
>How are connection limits calculated?

___


**hurl_core.h**
===

Initialize HURL manager
---
```
HURLManager *hurl_manager_init();
```
**Example**
```
HURLManager *manager = hurl_manager_init();
```

Add URL to be downloaded
---
```
HURLPath *hurl_add_url(HURLManager *manager, int allow_duplicate, char *url, void *tag);
```
**Example 1**
```C
/* Create tag */
char *tag = malloc(sizeof(char)*6);
snprintf(tag, 6, "hello");
/* Allow duplicates. */
hurl_add_url(manager, 1, "http://www.github.com/", tag);
```
**Example 2**
```C
/* Don't allow duplicates and postpone tagging. */
HURLPath *path = hurl_add_url(manager, 0, "http://www.github.com/", NULL);
if(path != NULL) {
	/* The URL was added. */
	path->tag = tag;
} else {
	/* The tag was not added. */
}
```
Execute HURL
---
```C
int hurl_exec(HURLManager *manager);
```
**Example**
```C
if(hurl_exec(manager) == 1) {
	/* OK */
} else {
	/* ERROR */
}
```
Parse URL
---
Parses a URL string into protocol, hostname, port, and path.
```C
int hurl_parse_url(char *url, HURLParsedURL **result);
```
**Example**
```C
HURLParsedURL *parsed_url;
if(hurl_parse_url("http://www.github.com/", &parsed_url)) {
	/* Parsing OK */
} else {
	/* Parsing ERROR */
}
```
Free parsed URL structure
---
Frees the data structure of a parsed URL.
```C
void hurl_parsed_url_free(HURLParsedURL *url);
```
**Example**
```C
hurl_parsed_url_free(parsed_url);
```
Find domain
---
Find the [HURLDomain](#HURLDomain) structure of a domain name.
```
HURLDomain *hurl_get_domain(HURLManager *manager, char *domain);
```
**Example**
```
	HURLDomain *domain = hurl_get_domain(manager, "www.google.com");
```
Find server
---
Find the [HURLServer](#HURLServer) structure of a server.
```
HURLServer *hurl_get_server(HURLDomain *domain, unsigned short port, int tls);
```
**Example**
```
/* Find a server for www.github.com running on port 80 without TLS.  */
HURLServer *server = hurl_get_server("www.github.com",80, 0);
if(server) {
	/* Server found. */
} else {
	/* Server not found. */
}
```
Add header
---
Adds a header to a linked list of [HURLHeader](#HURLHeader) structures.
If a header with the same key exists its value is overwritten.
```
int hurl_header_add(HURLHeader **headers, char *key, char *value);
```
**Example**
```
/* Find a server for www.github.com running on port 80 without TLS.  */
if(hurl_header_add(manager->headers, "User-Agent", "hurl/x.yy")) {
	printf("Header added.\n");
} else {
	printf("Header not added.\n");
	/* TODO: Does this ever happen? */
}
```
Find header
---
Finds a header in a linked list of [HURLHeader](#HURLHeader) structures and returns its value.
Keys are **not** case sensitive and if the key is not found NULL is returned.
```
char *hurl_header_get(HURLHeader *headers, char *key);
```
**Example**
```
/* Find 'User-Agent' header  */
char *header_value = hurl_header_get(manager->headers, "user-agent");
if(header_value) {
	printf("Header found: %s\n", header_value);
} else {
	printf("Header not found.\n");
}
```
Free headers
---
Frees all elements in a linked list of [HURLHeader](#HURLHeader) structures.
```
void hurl_headers_free(HURLHeader *bgof_headers);
```
**Example**
```
hurl_headers_free(manager->headers);
```
Split HTTP header line
---
Splits a HTTP header line into key and value.
```
int hurl_header_split_line(char *line, size_t line_len, char **key, char **value);
```
**Example**
```
char *key, *value, line[64];
snprintf(line, sizeof(line), "Content-Type: text/html");
if(hurl_header_split_line(line, strlen(line), &key, &value)) {
	printf("Header line parsed; key=%s value=%s\n", key, value);
} else {
	printf("Failed to parse header line.\n");
}
```
Does header exist?
---
Checks whether a certain HTTP header exists in a linked list of [HURLHeader](#HURLHeader) structures.
Keys are **not** case sensitive.
```
int hurl_header_exists(HURLHeader *headers, char *key);
```
**Example**
```
if(hurl_header_exists(manager->header, "Cache-Control")) {
	printf("The header exists.\n");
} else {
	printf("The header does NOT exist.\n");
}
```
Free HURL structures
---
The following functions are used to clean up memory used by HURL.
Typically, only ```hurl_manager_free()``` is used as it cleans up everything.
```
void hurl_manager_free(HURLManager *manager);
void hurl_domain_free(HURLManager *manager, HURLDomain *domain);
void hurl_server_free(HURLManager *manager, HURLServer *server);
void hurl_path_free(HURLManager *manager, HURLPath *path);
void hurl_connection_free(HURLConnection *connection);
```
**Example**
```
/* Initialize HURL manager */
HURLManager *manager = hurl_manager_init();
/* Use HURL ... */
...
/* Free memory when done. */
hurl_manager_free(manager);
```
Get domain queue length
---
Counts the number of [HURLPath](#HURLPath) structures under a [HURLDomain](#HURLDomain) structure.
```
int hurl_domain_nrof_paths(HURLDomain *domain, enum HURLDownloadState state);
```
**Example**
```
/* Initialize HURL manager */
HURLManager *manager = hurl_manager_init();
/* Add URLs */
hurl_add_url(manager, 1, "http://www.github.com/", NULL);
hurl_add_url(manager, 1, "http://www.stackoverflow.com/", NULL);
hurl_add_url(manager, 1, "http://www.stackoverflow.com/test/", NULL);
/* Download files. */
hurl_exec(manager);
/* Find domain. */
HURLDomain *domain = hurl_get_domain(manager, "www.stackoverflow.com");
/* Count files. */
int n = hurl_domain_nrof_paths(domain, DOWNLOAD_STATE_COMPLETED);
printf("%d files from www.stackoverflow.com were downloaded.\n", n);
/* Clean up. */
hurl_manager_free(manager);
```
Get queue length
---
Counts the number of [HURLPath](#HURLPath) structures handled by a [HURLManager](#HURLManager)  structure.
```
int hurl_nrof_paths(HURLManager *manager, enum HURLDownloadState state);
```
**Example**
```
/* Initialize HURL manager */
HURLManager *manager = hurl_manager_init();
/* Add URLs */
hurl_add_url(manager, 1, "http://www.facebook.com/", NULL);
hurl_add_url(manager, 1, "http://www.google.com/", NULL);
hurl_add_url(manager, 1, "http://www.aalto.fi/", NULL);
/* Download files. */
hurl_exec(manager);
int n = hurl_nrof_paths(manager, DOWNLOAD_STATE_COMPLETED);
printf("%d files were downloaded.\n", n);
/* Clean up. */
hurl_manager_free(manager);
```
Allocate memory and copy string
---
Allocates memory using calloc() and copies a string.
```
char *hurl_allocstrcpy(char *str, size_t str_len, unsigned int alloc_padding);
```
**Example**
```
/* Set padding to 1 to create null-terminated string. */
char *url = hurl_allocstrcpy("http://www.example.com/", strlen("http://www.example.com/"), 1);
```
Write debug message to stderr
---
Writes a debug message with calling function (\__func__), thread ID, and a formatted string.
```
void hurl_debug(const char *func, const char *msg, ...);
```
**Example**
```
if(connect(sockfd, addr, addr_len) < 0) {
	hurl_debug(__func__, "Connect failed: %s", strerror(errno));
	/* Output example
	 * [1731745536] hurl_connect(): Connect failed: error message'
	 */
}
```
Print status of HURL execution
---
Writes a debug message with calling function (\__func__), thread ID, and a formatted string.
```
void hurl_print_status(HURLManager *manager, FILE *fp);
```
**Example**
```
hurl_print_status(manager, stderr);
```
Start domain manager
---
Handles download scheduling of files on a specific domain.
```
void *hurl_domain_exec(void *domain_ptr);
```
**Example**
```
int *result = (int *)hurl_domain_exec((void *)domain);
```


