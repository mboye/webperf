#include <hurl/hurl_parse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void hurl_parsed_url_free(HURLParsedURL *url) {
	free(url->hostname);
	free(url->path);
	free(url->protocol);
	free(url);
}

int hurl_parse_url(char *url_ptr, HURLParsedURL **result) {
	char *bgof_hostname = NULL, *eof_hostname = NULL;
	char *eof_protocol = NULL;
	char *bgof_port = NULL, *eof_port = NULL;
	char *eof_url = NULL;
	char *bgof_path = NULL;

	/* Allocate copy of URL on stack */
	char *url = alloca(sizeof(char) * (strlen(url_ptr) + 1));
	memcpy(url, url_ptr, strlen(url_ptr));
	url[strlen(url_ptr)] = '\0';

	(*result) = calloc(1, sizeof(HURLParsedURL));
	if ((*result) == NULL) {
		/* Out of memory. */
		free(url);
		return HURL_URL_PARSE_ERROR;
	}

	eof_url = url + strlen(url);

	/* Find protocol. */
	eof_protocol = strstr(url, "://");
	if (eof_protocol == NULL) {
		free(*result);
		hurl_debug(__func__, "Could not find :// in URL.");
		return HURL_URL_PARSE_ERROR;
	}

	if (eof_protocol - url <= 0) {
		/* Missing protocol. */
		free(*result);
		hurl_debug(__func__, "Could not find protocol in URL.");
		return HURL_URL_PARSE_ERROR;
	}

	(*result)->protocol = hurl_allocstrcpy(url, (size_t) (eof_protocol - url), 1);
	/* hurl_debug(__func__, "Protocol: %s", (*result)->protocol); */

	if (strlen((*result)->protocol) + 3 == strlen(url)) {
		hurl_parsed_url_free(*result);
		hurl_debug(__func__, "Could not find hostname in URL.");
		return HURL_URL_PARSE_ERROR;
	}
	/* Find hostname */
	bgof_hostname = eof_protocol + 3;
	bgof_port = strstr(bgof_hostname, ":");
	bgof_path = strstr(bgof_hostname, "/");

	if (bgof_port && bgof_path) {
		/* URL contains both port and path. */
		if (bgof_port < bgof_path) {
			/* ":" came before "/", so URL does contain port number. */
			bgof_path = strstr(bgof_port, "/");
			eof_hostname = bgof_port;
			eof_port = bgof_path;
		} else {
			/* ":" came after "/", so URL does not contain port number. */
			bgof_port = NULL;
			eof_hostname = bgof_path;
		}
	} else if (bgof_port && !bgof_path) {
		/* URL contains port but no path. */
		eof_port = eof_url;
		eof_hostname = bgof_port;
	} else if (!bgof_port && bgof_path) {
		/* URL contains path but no port. */
		eof_hostname = bgof_path;
	} else {
		/* URL contains neither port nor path. */
		eof_hostname = eof_url;
	}

	/* Parse port number. */
	if (bgof_port && eof_port) {
		(*result)->port = (unsigned short) strtol(bgof_port + 1, &eof_port, 10);
		if ((*result)->port <= 0 || (*result)->port > 65535) {
			/* Invalid port number. */
			hurl_parsed_url_free(*result);
			hurl_debug(__func__, "Invalid port number.");
			return 0;
		}
	} else {
		if (strcasecmp((*result)->protocol, "https") == 0) {
			(*result)->port = 443;
		} else {
			(*result)->port = 80;
		}
	}

	/*hurl_debug(__func__, "Port: %u", (*result)->port);*/

	if (eof_hostname - bgof_hostname <= 0) {
		/* Empty hostname. */
		hurl_parsed_url_free(*result);
		hurl_debug(__func__, "Empty hostname.");
		return HURL_URL_PARSE_ERROR;
	}
	(*result)->hostname = hurl_allocstrcpy(bgof_hostname, (size_t) (eof_hostname - bgof_hostname), 1);

	if (bgof_path) {
		(*result)->path = hurl_allocstrcpy(bgof_path, (size_t) (eof_url - bgof_path), 1);
	} else {
		(*result)->path = hurl_allocstrcpy("/", 1, 1);
	}

	/*
	 hurl_debug(__func__, "Hostname: %s", (*result)->hostname);
	 hurl_debug(__func__, "Path: %s", (*result)->path);
	 */
	return HURL_URL_PARSE_OK;

}

