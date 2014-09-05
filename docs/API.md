
hurl_core.h
===

Initialize hurl manager
```
HURLManager *hurl_manager_init();
```
Example
```
HURLManager *hurl_manager_init();
```

Find domain
```
Prototype:
	HURLDomain *hurl_get_domain(HURLManager *manager, char *domain);
Example:
	HURLDomain *domain = hurl_get_domain(manager, "www.google.com");
```


HURLPath *hurl_add_url(HURLManager *manager, int allow_duplicate, char *url, void *tag);
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
