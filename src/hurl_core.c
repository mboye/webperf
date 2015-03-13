#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "hurl/hurl.h"
#include "hurl/internal.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

HURLManager *hurl_manager_init() {
	HURLManager *manager;
	/* Ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	if ((manager = calloc(1, sizeof(HURLManager))) != NULL) {
		manager->feature_pipelining = SUPPORTED;
		manager->feature_tls = SUPPORTED;
		manager->max_connections = HURL_MAX_CONNECTIONS;
		manager->max_domain_connections = HURL_MAX_DOMAIN_CONNECTIONS;
		manager->max_pipeline = HURL_MAX_PIPELINE_REQUESTS;
		manager->keep_alive = HURL_KEEP_ALIVE; /* Keep-alive is currently not supported. */
		manager->max_retries = HURL_MAX_RETRIES;
		manager->connect_timeout = HURL_TIMEOUT;
		manager->send_timeout = HURL_TIMEOUT;
		manager->recv_timeout = HURL_TIMEOUT;
		manager->recv_buffer_len = 0;
		manager->http_version = 1.1f;
		manager->follow_redirect = 1;
		manager->max_redirects = HURL_MAX_REDIRECTS;
		pthread_mutex_init(&manager->lock, NULL);
		pthread_cond_init(&manager->condition, NULL);

#ifndef HURL_NO_SSL
		/* Initialize OpenSSL */
		SSL_load_error_strings();
		ERR_load_crypto_strings();
		SSL_library_init();
		manager->ca_path = NULL;
		manager->ca_file = NULL;
#endif
		return manager;
	} else {
		return NULL;
	}
}

HURLDomain *hurl_get_domain(HURLManager *manager, char *domain) {
	HURLDomain *d, *last;
	d = manager->domains;
	last = NULL;
	/* Find domain. */
	while (d != NULL) {
		if (strcasecmp(d->domain, domain) == 0) {
			/* Match found, so stop searching. */
			return d;
		}
		last = d;
		d = d->next;
	}
	/* The domain does not exist, so create it. */
	if ((d = calloc(1, sizeof(HURLDomain))) == NULL) {
		/* Out of memory. */
		return NULL;
	}
	if ((d->domain = hurl_allocstrcpy(domain, strlen(domain), 1)) == NULL) {
		/* Out of memory. */
		return NULL;
	}
	d->manager = manager;
	pthread_mutex_init(&d->dns_lock, NULL);

	/* Add server to linked list. */
	if (last != NULL) {
		last->next = d;
	} else {
		/* This is the first item in the list. */
		manager->domains = d;
	}
	/* Increment number of unique domains. */
	manager->nrof_domains++;

	/* At this points the domain exists. */
	return d;
}

HURLServer *hurl_get_server(HURLDomain *domain, unsigned short port, int tls) {
	HURLServer *s, *last = NULL;
	/* Find server with matching port number. */
	s = domain->servers;
	while (s != NULL) {
		if (s->port == port && s->tls == tls) {
			/* Match found, so stop searching. */
			return s;
		}
		last = s;
		s = s->next;
	}

	/* The server does not exists, so create it. */
	if ((s = calloc(1, sizeof(HURLServer))) == NULL) {
		return NULL;
	}

	s->domain = domain;
	s->port = port;
	s->tls = tls;
	s->pipeline_errors = 0;

	/* Add server to linked list. */
	if (last != NULL) {
		last->next = s;
		s->previous = last;
	} else {
		/* This is the first item in the list. */
		domain->servers = s;
	}

	/* At this point the server has been created. */
	return s;
}

HURLPath *hurl_add_url(HURLManager *manager, int allow_duplicate, char *url, void *tag) {
	hurl_url_parser_error_t parser_rc;
	HURLParsedURL *parsed_url;
	HURLDomain *domain;
	HURLServer *server;
	HURLPath *path, *p = NULL, *last = NULL;
	int tls;
	if ((parser_rc = hurl_parse_url(url, &parsed_url)) != HURL_URL_PARSER_ERROR_NONE) {
		/* Failed to parse URL. */
		return NULL;
	}

	/* Check if connection should use TLS. */
	tls = strcmp(parsed_url->protocol, "https") == 0 ? 1 : 0;

	/* Get lock. */
	pthread_mutex_lock(&manager->lock);
	hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());

	/* Get domain */
	if ((domain = hurl_get_domain(manager, parsed_url->hostname)) == NULL) {
		/* Release lock. */
		pthread_mutex_unlock(&manager->lock);
		hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
		hurl_parsed_url_free(parsed_url);
		return NULL;
	}

	/* Get server */
	if ((server = hurl_get_server(domain, parsed_url->port, tls)) == NULL) {
		/* Release lock. */
		pthread_mutex_unlock(&manager->lock);
		hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
		hurl_parsed_url_free(parsed_url);
		return NULL;
	}

	/* Check for duplicates */
	if (!allow_duplicate) {
		p = server->paths;
		while (p != NULL) {
			if (strcasecmp(p->path, parsed_url->path) == 0) {
				/* Duplicate path found */
				hurl_debug(__func__, "Duplicate path detected. Ignoring it...");
				hurl_parsed_url_free(parsed_url);
				pthread_mutex_unlock(&manager->lock);
				return NULL;
			}
			last = p;
			p = p->next;
		}
	}

	/* Create path structure */
	if ((path = calloc(1, sizeof(HURLPath))) == NULL) {
		/* Out of memory. */
		/* Release lock. */
		pthread_mutex_unlock(&manager->lock);
		hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
		hurl_parsed_url_free(parsed_url);
		return NULL;
	}

	/* Copy path */
	if ((path->path = hurl_allocstrcpy(parsed_url->path, strlen(parsed_url->path), 1)) == NULL) {
		/* Out of memory. */
		/* Release lock. */
		pthread_mutex_unlock(&manager->lock);
		hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
		hurl_parsed_url_free(parsed_url);
		return NULL;
	}

	/* Set reverse pointer to domain structure. */
	path->server = server;
	path->state = DOWNLOAD_STATE_PENDING;

	/* Set tag pointer */
	path->tag = tag;

	/* Find last path in linked list. */
	p = server->paths;
	while (p != NULL) {
		last = p;
		p = p->next;
	}

	if (last != NULL) {
		last->next = path;
		path->previous = last;
	} else {
		/* This is the first item in the list. */
		server->paths = path;
	}

	/* Increment number of paths for the server and domain. */
	server->nrof_paths++;
	domain->nrof_paths++;

	/* Release lock. */
	pthread_mutex_unlock(&manager->lock);
	hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());

	hurl_parsed_url_free(parsed_url);
	return path;

}

int hurl_nrof_paths(HURLManager *manager, HURLDownloadState state) {
	HURLDomain *d;
	int count = 0;
	d = manager->domains;
	while (d != NULL) {
		count += hurl_domain_nrof_paths(d, state);
		d = d->next;
	}
	return count;
}

int hurl_exec(HURLManager *manager) {
	void *thread_result_ptr;
	int nrof_domain_paths = 0, nrof_paths = 0;
	HURLDomain *domain;
	struct timeval eof_exec, exec_time;

	gettimeofday(&manager->bgof_exec, NULL);
	hurl_debug(__func__, "Began execution @ %f", timeval_to_msec(&manager->bgof_exec));
	/* Loop until everything has been downloaded. */
	for (;;) {
		/* Get lock. */
		pthread_mutex_lock(&manager->lock);
		hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());

		nrof_paths = hurl_nrof_paths(manager, DOWNLOAD_STATE_PENDING);
		if (nrof_paths == 0) {
			pthread_mutex_unlock(&manager->lock);
			hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
			break;
		}

		hurl_debug(__func__, "Remaining paths: %u", nrof_paths);

		/* Calculate connection limit per domain. */
		domain = manager->domains;
		while (domain != NULL) {
			if ((nrof_domain_paths = hurl_domain_nrof_paths(domain, DOWNLOAD_STATE_PENDING)) > 0) {
				domain->max_connections = (unsigned int) roundf((((float) nrof_domain_paths / (float) nrof_paths)) * (float) manager->max_connections);
				if (domain->max_connections <= 0) {
					/* Always allow one connection. */
					domain->max_connections = 1;
				}
				/* Set connection limit to number of files if more connections were allowed. */
				if (domain->max_connections > domain->nrof_paths) {
					domain->max_connections = domain->nrof_paths;
				}
				/* Enforce per domain connection limit. */
				if (domain->max_connections > manager->max_domain_connections) {
					domain->max_connections = manager->max_domain_connections;
				}
				hurl_debug(__func__, "Max connections: %s => %u", domain->domain, domain->max_connections);
			} else {
				/* Prevent a connection thread from being started for this domain. */
				domain->max_connections = 0;
			}
			domain = domain->next;
		}

		/* Initialize thread synchronization condition: Global number of connections. */
		pthread_cond_init(&manager->condition, NULL);

		/* Release lock. */
		pthread_mutex_unlock(&manager->lock);
		hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());

		/* Start domain managers. */
		domain = manager->domains;
		while (domain != NULL) {
			if (domain->max_connections > 0) {
				if (pthread_create(&domain->thread, NULL, hurl_domain_exec, domain) != 0) {
					/* Failed to start thread. */
					hurl_debug(__func__, "Failed to create thread for '%s'", domain->domain);
				} else {
					domain->thread_running = 1;
				}
			}
			domain = domain->next;
		}

		/* Wait for all domain execution threads to finish. */
		domain = manager->domains;
		while (domain != NULL) {
			if (domain->thread_running) {
				pthread_join(domain->thread, &thread_result_ptr);
				domain->thread_running = 0;
				hurl_debug(__func__, "Thread %s joined.", domain->domain);
			}
			domain = domain->next;
		}

		hurl_debug(__func__, "Completed: %d", hurl_nrof_paths(manager, DOWNLOAD_STATE_COMPLETED));
		hurl_debug(__func__, "In progress: %d", hurl_nrof_paths(manager, DOWNLOAD_STATE_IN_PROGRESS));

	}
	gettimeofday(&eof_exec, NULL);
	timersub(&eof_exec, &manager->bgof_exec, &exec_time);
	manager->exec_time = timeval_to_msec(&exec_time);
	return 1;
}




HURLPath *hurl_server_dequeue(HURLServer *server) {
	HURLPath *path;
	path = server->paths;
	while (path != NULL) {
		if (path->state == DOWNLOAD_STATE_PENDING) {
			/* Change state to prevent threads from downloading the same file. */
			path->state = DOWNLOAD_STATE_IN_PROGRESS;
			break;
		}
		path = path->next;
	}
	/* All files have been processed or are currently being processed by other threads. */
	if (path != NULL) {
		hurl_debug(__func__, "Next item in queue: %s%.32s", path->server->domain->domain, path->path);
	} else {
		hurl_debug(__func__, "Next item in queue: EMPTY");
	}
	return path;
}

ssize_t hurl_recv(HURLConnection *connection, char *buffer, size_t buffer_len) {
	struct pollfd poll_sock;
	int recv_len = -1;

#ifndef HURL_NO_SSL
	int ssl_error;
#endif

	bzero(&poll_sock, sizeof(struct pollfd));
	poll_sock.fd = connection->sock;
	poll_sock.events = POLLIN | POLL_PRI;
	for (;;) {
		switch (poll(&poll_sock, 1, (int) connection->server->domain->manager->recv_timeout)) {
		case -1:
			/* Poll failed. */
			hurl_debug(__func__, "[ %s:%u ] Poll failed.", connection->server->domain->domain, connection->server->port);
			return -1;
		case 0:
			/* Poll timed out. */
			hurl_debug(__func__, "[ %s:%u ] Connection timed out.", connection->server->domain->domain, connection->server->port);
			return -1;
		case 1:
			/* The socket is ready to receive data. */
			if (poll_sock.revents & POLLIN) {
				if (connection->server->tls) {
#ifndef HURL_NO_SSL
					/* Secure connection. */
					if ((recv_len = SSL_read(connection->ssl_handle, buffer, (int) buffer_len)) > 0) {
						/* Return number of bytes received. */
						/* hurl_debug(__func__, "[ %s:%u ] SSL read: %d", connection->server->domain->domain, connection->server->port, recv_len); */
						return recv_len;
					} else if (recv_len == 0) {
						hurl_debug(__func__, "[ %s:%u ] The SSL connection was closed by the server.", connection->server->domain->domain,
								connection->server->port);
						/* TODO: Is this the right state? */
						connection->state = CONNECTION_STATE_CLOSED;
						return 0;
					} else {
						ssl_error = SSL_get_error(connection->ssl_handle, recv_len);
						if (ssl_error != SSL_ERROR_WANT_READ) {
							if (ssl_error == SSL_ERROR_SYSCALL) {
								hurl_debug(__func__, "[ %s:%u ] SSL read error (syscall): %s", connection->server->domain->domain, connection->server->port,
										strerror(errno));
							} else {
								hurl_debug(__func__, "[ %s:%u ] SSL read error: %d", connection->server->domain->domain, connection->server->port, ssl_error);
								hurl_connection_close(connection, CONNECTION_STATE_ERROR); /* TODO: ERROR instead? */
								return -1;
							}
						}
					}
#endif
				} else {
					/* Normal connection. */
					if ((recv_len = (int) recv(connection->sock, buffer, buffer_len,
					MSG_NOSIGNAL)) > 0) {
						/* Return number of bytes received. */
						return recv_len;
					} else if (recv_len == 0) {
						hurl_debug(__func__, "[ %s:%u ] The connection was closed by the server.", connection->server->domain->domain,
								connection->server->port);
						connection->state = CONNECTION_STATE_CLOSED;
						return 0;
					} else {
						hurl_debug(__func__, "[ %s:%u ] recv() error: %s\n", connection->server->domain->domain, connection->server->port, strerror(errno));
						hurl_connection_close(connection, CONNECTION_STATE_ERROR); /* TODO: ERROR instead? */
						return -1;
					}
				}
			}
		}
	}
	return -1;
}

ssize_t hurl_send(HURLConnection *connection, char *buffer, size_t buffer_len) {
	struct pollfd poll_sock;
	size_t data_sent = 0;
	ssize_t send_len;
	bzero(&poll_sock, sizeof(struct pollfd));
	poll_sock.fd = connection->sock;
	poll_sock.events = POLLOUT;
	while (data_sent < buffer_len) {
		switch (poll(&poll_sock, 1, connection->server->domain->manager->send_timeout)) {
		case -1:
			/* Poll failed. */
			hurl_debug(__func__, "[ %s:%u ] Poll failed.", connection->server->domain->domain, connection->server->port);
			return -1;
		case 0:
			/* Poll timed out. */
			hurl_debug(__func__, "[ %s:%u ] Connection timed out.", connection->server->domain->domain, connection->server->port);
			return -1;
		case 1:
			if (poll_sock.revents & POLLOUT) {
				/* Ready to send data. */
				if (connection->server->tls) {
					/* This is a secure connection. */
#ifndef HURL_NO_SSL
					if ((send_len = SSL_write(connection->ssl_handle, buffer, (int) buffer_len)) > 0) {
						hurl_debug(__func__, "[ %s:%u ] SSL write: %d", connection->server->domain->domain, connection->server->port, send_len);
						data_sent += (size_t) send_len;
					} else {
						hurl_debug(__func__, "[ %s:%u ] Failed to send.", connection->server->domain->domain, connection->server->port);
						hurl_connection_close(connection, CONNECTION_STATE_ERROR);
						return -1;
					}
#endif

				} else {
					/* This is a normal connection. */
					if ((send_len = send(connection->sock, buffer + data_sent, buffer_len - data_sent, MSG_NOSIGNAL)) <= 0) {
						/* Send failed. */
						hurl_debug(__func__, "[ %s:%u ] Failed to send.", connection->server->domain->domain, connection->server->port);
						hurl_connection_close(connection, CONNECTION_STATE_ERROR);
						return -1;
					} else {
						/* Update data left to send. */
						data_sent += (size_t) send_len;
					}
				}
			}
		}
	}
	return (ssize_t) data_sent;
}

#ifndef HURL_NO_SSL
int hurl_verify_ssl_scope(char *expected_domain, char *actual_domain) {
	char *expected_labels[127], *actual_labels[127];
	unsigned char nrof_expected_labels = 0, nrof_actual_labels = 0;
	char *expected_label, *actual_label;
	int i = 0, verifications = 0;
	int wildcard = 0;

	/* hurl_debug(__func__, "Checking SSL scope: '%s' vs. '%s'", expected_domain, actual_domain); */

	memset(expected_labels, 0, sizeof(char *) * 127);
	memset(actual_labels, 0, sizeof(char *) * 127);
	nrof_expected_labels = split_domain_name(expected_domain, expected_labels);
	nrof_actual_labels = split_domain_name(actual_domain, actual_labels);

	/* Compare labels. */
	i = 0;
	while (i < nrof_expected_labels) {
		expected_label = expected_labels[nrof_expected_labels - i - 1];

		if (wildcard) {
			verifications++;

		} else if (i < nrof_actual_labels) {
			actual_label = actual_labels[nrof_actual_labels - i - 1];
			/* hurl_debug(__func__, "%s <=> %s", expected_label, actual_label); */
			/* Check for wildcards. */
			if (strcmp(actual_label, "*") == 0 && i == nrof_actual_labels - 1) {
				/* The certificate contains a wildcard. */
				wildcard = 1;
				verifications++;
			} else if (strcasecmp(expected_label, actual_label) == 0) {
				verifications++;
			}
		}
		i++;
	}
	return verifications == nrof_expected_labels ? 1 : 0;
}

#endif
void hurl_connection_close(HURLConnection *connection, HURLConnectionState state) {
	if (connection->state == CONNECTION_STATE_CLOSED || connection->state == CONNECTION_STATE_ERROR) {
		/* The connection is already closed. */
		return;
	}
	if (connection->server->tls) {
#ifndef HURL_NO_SSL
		/* Shutdown SSL first. */
		if (connection->state != CONNECTION_STATE_CLOSED) {
			SSL_shutdown(connection->ssl_handle);
			/* Then close socket. */
			shutdown(connection->sock, SHUT_RDWR);
		}
		/* Free SSL structures. */
		if (connection->ssl_handle != NULL) {
			SSL_free(connection->ssl_handle);
			connection->ssl_handle = NULL;
		}
		if (connection->ssl_context != NULL) {
			SSL_CTX_free(connection->ssl_context);
			connection->ssl_context = NULL;
		}
#endif
	} else {
		/* Shutdown connection. */
		shutdown(connection->sock, SHUT_RDWR);
	}
	/* Mark connection as closed. */
	connection->state = state;
}



void hurl_print_status(HURLManager *manager, FILE *fp) {
	HURLDomain *domain;
	HURLServer *server;
	HURLPath *path;
	int ssl_paths = 0, ssl_errors = 0;
	int pipeline_errors = 0;
	int completed = 0, failed = 0, pending = 0, total = 0;
	char *url;
	size_t url_len;
	pthread_mutex_lock(&manager->lock);
	domain = manager->domains;
	while (domain != NULL) {
		server = domain->servers;
		while (server != NULL) {
			pipeline_errors += server->pipeline_errors;
			path = server->paths;
			while (path != NULL) {
				url_len = strlen(domain->domain) + strlen(path->path) + 512;
				url = malloc(sizeof(char) * url_len);
				if (server->tls) {
					snprintf(url, url_len, "https://%s:%u%s", domain->domain, server->port, path->path);
				} else {
					snprintf(url, url_len, "http://%s:%u%s", domain->domain, server->port, path->path);
				}
				total++;
				if (path->server->tls) {
					ssl_paths++;
				}
				if (path->state == DOWNLOAD_STATE_PENDING) {
					fprintf(fp, "Pending:\t%s", url);
					pending++;
				} else if (path->state == DOWNLOAD_STATE_IN_PROGRESS) {
					fprintf(fp, "In progress:\t%s", url);
					pending++;
				} else if (path->state == DOWNLOAD_STATE_COMPLETED) {
					fprintf(fp, "Completed:\t%s", url);
					completed++;
				} else if (path->state == DOWNLOAD_STATE_ERROR) {
					fprintf(fp, "Failed:\t%s", url);
					if (path->server->tls && path->server->domain->dns_state == DNS_STATE_RESOLVED) {
						ssl_errors++;
					}
					failed++;
				} else {
					fprintf(fp, "Unknown:\t%s", url);
				}
				path = path->next;
				fprintf(fp, "\n");
				free(url);
			}
			server = server->next;
		}
		domain = domain->next;
		fprintf(fp, "\n");
	}
	pthread_mutex_unlock(&manager->lock);
	fprintf(fp, "\n\nNumber of files: %d\n", total);
	fprintf(fp, "Completed:       %d\n", completed);
	fprintf(fp, "Failed:          %d\n", failed);
	fprintf(fp, "Pending:         %d\n", pending);
	fprintf(fp, "Pipeline errors: %d\n", pipeline_errors);
	fprintf(fp, "SSL files:       %d\n", ssl_paths);
	fprintf(fp, "SSL errors:      %d\n", ssl_errors);
}

void hurl_manager_free(HURLManager *manager) {
	HURLDomain *next, *domain;
	domain = manager->domains;
	while (domain != NULL) {
		next = domain->next;
		hurl_domain_free(manager, domain);
		domain = next;
	}
	free(manager->ca_file);
	free(manager->ca_path);
	hurl_headers_free(manager->headers);
	free(manager);

	/* free OpenSSL stuff */
	/* ref: http://stackoverflow.com/questions/11759725/opensslssl-library-init-memory-leak */
#ifndef HURL_NO_SSL
	CONF_modules_free();
	ERR_remove_state(0);
	CONF_modules_unload(1);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	/* compression_methods has one haunting leak, don't know how to fix it */
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#endif
}

float record_time_msec(struct timeval *begin)
{
    struct timeval end;
    struct timeval diff;
    gettimeofday(&end, NULL);
    timersub(&end, begin, &diff);
    return timeval_to_msec(&diff);
}
