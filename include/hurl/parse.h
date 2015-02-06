#ifndef HURL_PARSE_H_
#define HURL_PARSE_H_

typedef struct hurl_parsed_url {
	char *protocol; /* Protocol: http or https */
	char *hostname; /* Host/domain name */
	unsigned short port; /* Server port. Default is port 80 for HTTP and 443 for HTTPS */
	char *path; /* Path e.g. /index.html */
} HURLParsedURL;

int hurl_parse_url(char *url, HURLParsedURL **result);

void hurl_parsed_url_free(HURLParsedURL *url);

#endif /* HURL_PARSE_H_ */
