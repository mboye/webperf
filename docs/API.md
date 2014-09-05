
hurl_core.h
===

Initialize hurl
---
```
HURLManager *hurl_manager_init();
```
**Example**
```
HURLManager *manager = hurl_manager_init();
```

Find domain
---
```
	HURLDomain *hurl_get_domain(HURLManager *manager, char *domain);
```
**Example**
```
	HURLDomain *domain = hurl_get_domain(manager, "www.google.com");
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
int hurl_exec(HURLManager *manager);
int hurl_parse_url(char *url, HURLParsedURL **result);
void hurl_parsed_url_free(HURLParsedURL *url);
HURLDomain *hurl_get_domain(HURLManager *manager, char *domain);
HURLServer *hurl_get_server(HURLDomain *domain, unsigned short port, int tls);
int hurl_header_add(HURLHeader **headers, char *key, char *value);
char *hurl_header_get(HURLHeader *headers, char *key);
void hurl_headers_free(HURLHeader *headers);
int hurl_header_split_line(char *line, size_t line_len, char **key, char **value);
int hurl_header_exists(HURLHeader *headers, char *key);
void hurl_manager_free(HURLManager *manager);
void hurl_domain_free(HURLManager *manager, HURLDomain *domain);
void hurl_server_free(HURLManager *manager, HURLServer *server);
void hurl_path_free(HURLManager *manager, HURLPath *path);
void hurl_connection_free(HURLConnection *connection);
int hurl_domain_nrof_paths(HURLDomain *domain, enum HURLDownloadState state);
int hurl_nrof_paths(HURLManager *manager, enum HURLDownloadState state);
char *hurl_allocstrcpy(char *str, size_t str_len, unsigned int alloc_padding);
void hurl_debug(const char *func, const char *msg, ...);
void hurl_print_status(HURLManager *manager, FILE *fp);
void *hurl_domain_exec(void *domain_ptr);
