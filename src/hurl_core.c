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
#include "hurl_core.h"

#ifndef HURL_NO_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#endif

void *hurl_connection_exec(void *connection_ptr);
HURLPath *hurl_server_dequeue(HURLServer *server);
int hurl_connection_response(HURLConnection *connection, HURLPath *path, char **buffer, size_t *buffer_len, size_t *data_len,
		enum HTTPFeatureSupport *feature_persistence);
int hurl_connection_request(HURLConnection *connection, HURLPath *path);
void hurl_resolve(HURLDomain *domain); /* Default DNS resolution. */

int hurl_header_str(HURLHeader *headers, char *buffer, size_t buffer_len);
HURLHeader *hurl_headers_copy(HURLHeader *headers);

/* unsigned int hurl_domain_nrof_paths(HURLDomain *domain); */
ssize_t hurl_send(HURLConnection *connection, char *buffer, size_t buffer_len);
ssize_t hurl_recv(HURLConnection *connection, char *buffer, size_t buffer_len);

int hurl_connect(HURLConnection *connection);
void hurl_connection_close(HURLConnection *connection, enum HURLConnectionState state);
int hurl_verify_ssl_scope(char *expected_domain, char *actual_domain);
unsigned char split_domain_name(char *name, char *labels[]);
int hurl_parse_response_code(char *line, char **code_text);

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

void hurl_debug(const char *func, const char *msg, ...) {
#ifndef NDEBUG
	char template[1024];
	va_list args;
	snprintf(template, sizeof template, "[%u] %s(): %s\n", (unsigned int) pthread_self(), func, msg);
	va_start(args, msg);
	vfprintf(stderr, template, args);
	va_end(args);
	fflush(stderr);
#endif
}

char *hurl_allocstrcpy(char *str, size_t str_len, unsigned int alloc_padding) {
	char *newstr;
	if (str != NULL) {
		if ((newstr = calloc(str_len + alloc_padding, sizeof(char))) == NULL) {
			exit(EXIT_FAILURE);
		}
		memcpy(newstr, str, str_len);
		return newstr;
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
	HURLParsedURL *parsed_url;
	HURLDomain *domain;
	HURLServer *server;
	HURLPath *path, *p = NULL, *last = NULL;
	int tls;
	if (!hurl_parse_url(url, &parsed_url)) {
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

int hurl_domain_nrof_paths(HURLDomain *domain, enum HURLDownloadState state) {
	HURLServer *s;
	HURLPath *p;
	int count = 0;
	s = domain->servers;
	while (s != NULL) {
		p = s->paths;
		while (p != NULL) {
			if (p->state == state) {
				count++;
			}
			p = p->next;
		}
		s = s->next;
	}
	return count;
}

int hurl_nrof_paths(HURLManager *manager, enum HURLDownloadState state) {
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

void *hurl_domain_exec(void *domain_ptr) {
	HURLDomain *domain = (HURLDomain *) domain_ptr;
	HURLConnection *connection = NULL, *last_connection = NULL, *next;
	HURLServer *server;
	void *thread_result_ptr;
	int i;
	hurl_debug(__func__, "[ %s ] Domain thread started.", domain->domain);

	/* Start connection controllers for servers. */
	server = domain->servers;
	while (server != NULL) {
		/* Calculate the number of connections to allow for this server.*/
		server->max_connections = (unsigned int) roundf((((float) server->nrof_paths / (float) domain->nrof_paths)) * (float) domain->max_connections);
		if (server->max_connections <= 0) {
			server->max_connections = 1;
		}
		hurl_debug(__func__, "[ %s:%u ] max. connections = %u", server->domain->domain, server->port, server->max_connections);
		for (i = 0; i < (int) server->max_connections; i++) {
			/* Create connection for server. */
			if ((connection = calloc(1, sizeof(HURLConnection))) == NULL) {
				/* Out of memory. */
				return 0;
			}
			connection->server = server;

			/* Add connection to linked list */
			if (last_connection != NULL) {
				last_connection->next = connection;
				connection->previous = last_connection;
			} else {
				server->connections = connection;
			}
			last_connection = connection;

			/* Start connection thread. */
			pthread_create(&connection->thread, NULL, hurl_connection_exec, connection);
			connection = connection->next;
		}

		server = server->next;
	}

	/* Wait for all connection execution threads to finnish. */
	server = domain->servers;
	while (server != NULL) {
		connection = server->connections;
		while (connection != NULL) {
			next = connection->next;
			pthread_join(connection->thread, &thread_result_ptr);
			hurl_debug(__func__, "[%s] Domain thread ended.", connection->server->domain->domain);
			hurl_connection_free(connection);
			connection = next;
		}

		server = server->next;
	}

	pthread_exit(NULL);
}

void *hurl_connection_exec(void *connection_ptr) {
	HURLConnection *connection = (HURLConnection *) connection_ptr;
	HURLServer *server = connection->server;
	HURLDomain *domain = server->domain;
	HURLManager *manager = domain->manager;
	HURLPath *path = NULL;
	int connect_retval;
	char *buffer = NULL;
	size_t buffer_len = 0, data_len = 0;
	enum HTTPFeatureSupport feature_persistence = UNKNOWN_SUPPORT, feature_pipelining = UNKNOWN_SUPPORT;
	unsigned int i;
	HURLPath **queue;
	unsigned int queue_len = 0;
	unsigned int max_pipeline = domain->manager->max_pipeline;
	int response_retval;
	struct timeval eof_resolution, resolution_time;

	hurl_debug(__func__, "[ %s:%u ] Connection thread started.", domain->domain, server->port);
	/* Enforce global connection limit. */
	pthread_mutex_lock(&manager->lock);
	hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());

	/* Wait for permission to establish connection. */
	while (domain->manager->connections >= domain->manager->max_connections) {
		pthread_cond_wait(&manager->condition, &manager->lock);
		/*	hurl_debug(__func__, "CONDITIONAL LOCK: Checking active connections counter."); */
	}

	/* Increment number of global connections. */
	domain->manager->connections++;

	hurl_debug(__func__, "[ %s:%u ] %d out of %d connections in use.", domain->domain, server->port, manager->connections, manager->max_connections);

	/* Check if there are any files left to download. */
	if ((path = hurl_server_dequeue(server)) == NULL) {
		/* Nothing for this connection thread to do. */
		hurl_debug(__func__, "[ %s:%u ] No files left to download.", domain->domain, server->port);
		/* Decrement active connections counter ** We already have the lock ** . */
		hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());
		domain->manager->connections--;
		pthread_mutex_unlock(&manager->lock);
		hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
		hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
		pthread_exit(NULL);
	}

	pthread_mutex_unlock(&manager->lock);
	hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());

	/* Get DNS lock. */
	pthread_mutex_lock(&domain->dns_lock);
	hurl_debug(__func__, "Thread %u got DNS lock.", (unsigned int) pthread_self());

	/* Resolve domain name. */
	if (domain->dns_state == DNS_STATE_UNRESOLVED) {
		hurl_debug(__func__, "Resolving domain name.");
		assert(domain->dns_trigger == NULL);
		domain->dns_trigger = path;
		gettimeofday(&domain->bgof_resolution, NULL);
		if (manager->hook_resolve != NULL) {
			/* Override DNS resolution. */
			manager->hook_resolve(domain, path);
		} else {
			/* Use default DNS resolution. */
			hurl_resolve(domain);
		}
		/* Calculate resolution time */
		gettimeofday(&eof_resolution, NULL);
		timersub(&eof_resolution, &domain->bgof_resolution, &resolution_time);
		domain->resolution_time = timeval_to_msec(&resolution_time);
		hurl_debug(__func__, "[ %s:%u ] Domain name resolved in %f ms", domain->domain, server->port, domain->resolution_time);

	} else {
		hurl_debug(__func__, "[ %s:%u ] Domain name has already been resolved.", domain->domain, server->port);
	}
	/* Release DNS lock. */
	pthread_mutex_unlock(&domain->dns_lock);
	hurl_debug(__func__, "Thread %u released DNS lock.", (unsigned int) pthread_self());

	/* Abort if DNS resolution failed. */
	if (domain->dns_state == DNS_STATE_ERROR) {
		hurl_debug(__func__, "[ %s:%u ] DNS resolution failed. Aborting...", domain->domain, server->port);
		pthread_mutex_lock(&manager->lock);
		/* Decrement active connections counter. */
		domain->manager->connections--;
		/* Mark file as failed. */
		path->state = DOWNLOAD_STATE_ERROR;
		/* Call transfer failed hook. */
		if (manager->hook_transfer_complete) {
			manager->hook_transfer_complete(path, connection, HURL_XFER_DNS, 0, 0);
		}
		pthread_mutex_unlock(&manager->lock);
		pthread_exit(NULL);
	}

	/* As long as there are files to download. */
	while (path != NULL) {
		/* Call pre-connect hook */
		if (manager->hook_pre_connect != NULL && !manager->hook_pre_connect(path, connection)) {
			/* Do not connect to this server. */
			path = hurl_server_dequeue(server);
			continue;
		}
		/* Connect to server. */
		if ((connect_retval = hurl_connect(connection)) != CONNECTION_ERROR) {
			/* Call post connect hook */
			if (manager->hook_post_connect != NULL) {
				manager->hook_post_connect(path, connection, connect_retval);
			}
			/* Is pipelining supported? */
			if (domain->manager->feature_pipelining == SUPPORTED && feature_persistence == SUPPORTED && feature_pipelining != UNSUPPORTED) {
				/* Try to pipeline requests over persistent connection. */
				queue = calloc(max_pipeline, sizeof(HURLPath *));
				hurl_debug(__func__, "[ %s:%u ] Attempting to pipeline requests.", domain->domain, server->port);

				/* Get lock. */
				pthread_mutex_lock(&server->domain->manager->lock);
				hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());

				/* Create pipeline queue. */
				queue_len = 0;
				while (queue_len < max_pipeline && path != NULL) {
					/* Call pre-request hook */
					if (manager->hook_send_request == NULL || (manager->hook_send_request != NULL && manager->hook_send_request(path, connection, 1))) {
						/* Add path to queue. */
						queue[queue_len++] = path;
					}
					/* Get next file to download. */
					if (queue_len + 1 < max_pipeline) {
						path = hurl_server_dequeue(server);
					}
				}

				/* Release lock. */
				pthread_mutex_unlock(&server->domain->manager->lock);
				hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());

				/* Send pipelined requests. */
				for (i = 0; i < queue_len; i++) {
					path = queue[i];
					/* Attempt to send request. */
					if (!hurl_connection_request(connection, path)) {
						/* Change state of path to retry download. */
						path->state = DOWNLOAD_STATE_PENDING;
						break;
					}
				}

				/* Receive pipelined responses. */
				for (i = 0; i < queue_len; i++) {
					path = queue[i];
					/* Receive pipelined response. */
					if ((response_retval = hurl_connection_response(connection, path, &buffer, &buffer_len, &data_len, &feature_persistence)) > 0) {
						/* The entire response was received. */
						gettimeofday(&path->response_received, NULL);
						hurl_debug(__func__, "[ %s:%u%.32s ] Response received. ", domain->domain, server->port, path->path);

					} else if (response_retval == 0) {
						/* The file was received and the server closed the connection. */
						gettimeofday(&path->response_received, NULL);
						if (i < queue_len) {
							/* This was not the last request, so something went wrong. */
							hurl_debug(__func__, "[ %s:%u%.32s ] Connection closed by server.", domain->domain, server->port, path->path);
						}
						break;
					} else {
						gettimeofday(&path->response_received, NULL);
						/* Error */
						hurl_debug(__func__, "[ %s:%u%.32s ] Error. ", domain->domain, server->port, path->path);
						break;
					}
				}
				/* Get lock. */
				pthread_mutex_lock(&manager->lock);
				hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());

				/* Update download states. */
				for (i = 0; i < queue_len; i++) {
					path = queue[i];
					if (path->state == DOWNLOAD_STATE_IN_PROGRESS) {
						/* All pipelined requests were not answered. */
						server->pipeline_errors++;
						feature_pipelining = UNSUPPORTED;
						path->state = DOWNLOAD_STATE_PENDING;
					}
				}

				/* Get next file to download. */
				path = hurl_server_dequeue(server);

				/* Free queue */
				free(queue);

				/* Release lock. */
				pthread_mutex_unlock(&manager->lock);
				hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());

				continue;
			} else {
				/* Send single requets over persistent or non-persistent connection. */
				/* Send HTTP request. */
				if (manager->hook_send_request == NULL || (manager->hook_send_request != NULL && manager->hook_send_request(path, connection, 0))) {
					if (hurl_connection_request(connection, path)) {
						/* Receive HTTP response. */
						if (hurl_connection_response(connection, path, &buffer, &buffer_len, &data_len, &feature_persistence) >= 0) {
							gettimeofday(&path->response_received, NULL);
							if (domain->manager->feature_persistence == UNSUPPORTED || feature_persistence == UNSUPPORTED) {
								/* Persistent connections not allowed: close connection */
								hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
								hurl_debug(__func__, "[ %s:%u ] Connection closed by client.", domain->domain, server->port);
							}

							/* Get lock. */
							pthread_mutex_lock(&manager->lock);
							hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());

							/* Get next file to download. */
							path = hurl_server_dequeue(server);

							/* Release lock. */
							pthread_mutex_unlock(&manager->lock);
							hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
							continue;
						}
					} else {
						/* Failed to send request */
						/* TODO: Handle failed request transmission. */ 
					}
				} else {
					/* We were not allowed to send the request */
					pthread_mutex_lock(&manager->lock);
					path->state = DOWNLOAD_STATE_ERROR;
					pthread_mutex_unlock(&manager->lock);

					/* Call transfer failed hook. */
					if (manager->hook_transfer_complete) {
						manager->hook_transfer_complete(path, connection, HURL_XFER_HOOK, 0, 0);
					}

				}
			}
		} else {
			/* Call post connect hook */
			if (manager->hook_post_connect != NULL) {
				manager->hook_post_connect(path, connection, connect_retval);
			}

			/* Fatal error: Could not connect to any servers. */
			hurl_debug(__func__, "[ %s:%u ] Failed to connect.", domain->domain, connection->server->port);
			/* Get lock, update download state, and release lock. */
			pthread_mutex_lock(&manager->lock);
			hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());

			path->state = DOWNLOAD_STATE_ERROR;
			/* Call transfer failed hook. */
			if (manager->hook_transfer_complete) {
				manager->hook_transfer_complete(path, connection, HURL_XFER_CONNECT, 0, 0);
			}
			pthread_mutex_unlock(&manager->lock);
			hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
		}

		/* Get next file to download. */
		pthread_mutex_lock(&manager->lock);
		path = hurl_server_dequeue(server);
		pthread_mutex_unlock(&manager->lock);

	}
	/* Decrement active connections counter. */
	pthread_mutex_lock(&manager->lock);
	hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());
	domain->manager->connections--;
	/* Notify waiting threads of change in number of connections. */
	pthread_cond_broadcast(&domain->manager->condition);
	pthread_mutex_unlock(&manager->lock);
	hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());
	/* Free memory */
	free(buffer);
	/* End connection thread. */
	pthread_exit(NULL);
}

int hurl_connect(HURLConnection *connection) {
	struct sockaddr address;
	unsigned int address_len;
	int sock_flags;
	struct pollfd poll_sock;
	int sock_errno;
	unsigned int sock_errno_len;
	int timeout = connection->server->domain->manager->connect_timeout;
	HURLServer *server = connection->server;
	HURLDomain *domain = connection->server->domain;
	int i;
	int connect_retval;
	HURLManager *manager = connection->server->domain->manager;
	unsigned int sockopt_len = sizeof(manager->recv_buffer_len);
	struct timeval end_connect, connect_time;
	struct timeval ssl_begin_connect, ssl_end_connect, connect_time_ssl;
	int poll_retval;

#ifndef HURL_NO_SSL
	int ssl_error;
	int ssl_connected = 0;
	char ssl_error_str[256];
	X509 *server_cert;
	X509_NAME *subject_name;
	STACK_OF(GENERAL_NAME) *san_names = NULL;
	int san_names_nb;
	char common_name[256];
	int certificate_ok = 0;
#endif

	/* Zero SSL timing. */
	bzero(&ssl_begin_connect, sizeof(struct timeval));
	bzero(&ssl_end_connect, sizeof(struct timeval));

#ifdef HURL_NO_SSL
	if(connection->server->tls) {
		hurl_debug(__func__, "Cannot connect: no SSL support.");
		return CONNECTION_ERROR;
	}
#endif

	/* Check if a connection is already open. */
	if (connection->state == CONNECTION_STATE_CONNECTED) {
		hurl_debug(__func__, "[ %s:%u ] Reusing connection.", domain->domain, server->port);
		connection->reused = 1;
		return CONNECTION_REUSED;
	}

	if (connection->state == CONNECTION_STATE_ERROR) {
		hurl_debug(__func__, "[ %s:%u ] Previous attempts to connect to this server have failed. Aborting...", domain->domain, server->port);
		return CONNECTION_ERROR;
	}

	/* Change connection state. */
	connection->state = CONNECTION_STATE_IN_PROGRESS;
	connection->reused = 0;

	for (i = 0; i < (int) domain->nrof_addresses; i++) {
		/* Ignore IP addresses where connect() failed. */
		if (domain->addresses[i] == NULL) {
			continue;
		}
		/* Copy address to we can fix the port number before calling connect() */
		memcpy(&address, domain->addresses[i], sizeof(struct sockaddr));

		/* Create socket and connect to server. */
		if (address.sa_family == AF_INET) {
			address_len = sizeof(struct sockaddr_in);

			/* IPv4 */
			if ((connection->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				hurl_debug(__func__, "[%s][%u] Failed to create socket: %s", domain->domain, server->port, strerror(errno));
				continue;
			}

			/* Set port number. */
			((struct sockaddr_in*) &address)->sin_port = htons(server->port);
		} else {
			assert(address.sa_family == AF_INET6);
			address_len = sizeof(struct sockaddr_in6);
			/* IPv6 */
			if ((connection->sock = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
				hurl_debug(__func__, "[%s][%u] Failed to create IPv6 socket: %s", domain->domain, server->port, strerror(errno));
				continue;
			}
			/* Set port number. */
			((struct sockaddr_in6 *) &address)->sin6_port = htons(server->port);
		}

		/* Get socket flags. */
		if ((sock_flags = fcntl(connection->sock, F_GETFL, 0)) < 0) {
			hurl_debug(__func__, "Failed to get socket flags - %s.", strerror(
			errno));
			continue;
		}

		/* Change socket to use non-blocking IO. */
		if ((fcntl(connection->sock, F_SETFL, sock_flags | O_NONBLOCK)) < 0) {
			hurl_debug(__func__, "Failed to switch socket to non-blocking mode - %s.", strerror(errno));
			continue;
		}

		/* Connect to server. */
		hurl_debug(__func__, "[ %s:%u ] Connecting to server...", domain->domain, server->port);
		gettimeofday(&connection->begin_connect, NULL);
		if (connect(connection->sock, &address, address_len) < 0) {
			if (errno != EINPROGRESS) {
				hurl_debug(__func__, "[ %s:%u ] Failed to connect: %s", domain->domain, server->port, strerror(errno));
				continue;
			}
		}

		/* Setup polling parameters. */
		bzero(&poll_sock, sizeof(struct pollfd));
		poll_sock.fd = connection->sock;
		poll_sock.events = POLLOUT;

		/* Wait for connection to become ready. */
		switch ((poll_retval = poll(&poll_sock, 1, (int) timeout))) {
		case -1:
			/* Poll failed. */
			hurl_debug(__func__, "[ %s:%u ] Failed to poll with retval %d - %s", domain->domain, server->port, poll_retval, strerror(errno));
			continue;
		default:
		case 0:
			/* Poll timed out. */
			hurl_debug(__func__, "[ %s:%u ] The connection timed out.", domain->domain, server->port);
			continue;
		case 1:
			/* The socket is ready to send data. */
			if (poll_sock.revents & POLLOUT) {
				/* Check if an error occurred. */
				sock_errno_len = sizeof(sock_errno);
				if (getsockopt(connection->sock, SOL_SOCKET, SO_ERROR, &sock_errno, &sock_errno_len) < 0) {
					/* Failed to retrieve socket status. */
					hurl_debug(__func__, "[ %s:%u ] Failed to get socket status - %s", domain->domain, server->port, strerror(errno));
					continue;
				} else {
					if (sock_errno != 0) {
						/* Failed to connect. */
						hurl_debug(__func__, "[ %s:%u ] Failed to connect: %s", domain->domain, server->port, strerror(sock_errno));
						continue;
					}
				}
			}
			break;
		}
		hurl_debug(__func__, "[ %s:%u ]  Connected to server.", domain->domain, server->port);

#ifndef HURL_NO_SSL
		/* Switch to secure connection? */
		if (connection->server->tls) {
			hurl_debug(__func__, "Switching to TLS.");
			gettimeofday(&ssl_begin_connect, NULL);
			/* Context is SSL v. 2 or 3. */
			connection->ssl_context = SSL_CTX_new(SSLv23_client_method());
			if (connection->ssl_context == NULL) {
				hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
				return CONNECTION_ERROR;;
			}

			/* Enable verification of server certificate. */
			if (!SSL_CTX_load_verify_locations(connection->ssl_context, connection->server->domain->manager->ca_file,
					connection->server->domain->manager->ca_path)) {
				hurl_debug(__func__, "Failed to load SSL certificates.");
				hurl_connection_close(connection, CONNECTION_STATE_ERROR);
				return CONNECTION_ERROR;
			}

			SSL_CTX_set_verify(connection->ssl_context,
			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

			/* Create SSL handle for connection. */
			connection->ssl_handle = SSL_new(connection->ssl_context);
			if (connection->ssl_handle == NULL) {
				hurl_debug(__func__, "SSL error.");
				hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
				return CONNECTION_ERROR;
			}

			/* Associate SSL handle with open TCP connection. */
			if (!SSL_set_fd(connection->ssl_handle, connection->sock)) {
				hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
				return CONNECTION_ERROR;
			}

			poll_sock.events = POLLIN | POLLOUT;
			while (!ssl_connected) {
				switch (poll(&poll_sock, 1, (int) server->domain->manager->connect_timeout)) {
				case -1:
					/* Poll failed. */
					hurl_debug(__func__, "Failed to poll - %s\n", strerror(errno));
					hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
					return CONNECTION_ERROR;
				default:
				case 0:
					/* Poll timed out. */
					hurl_debug(__func__, "The connection timed out.\n");
					hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
					return CONNECTION_ERROR;
				case 1:
					/* The socket is ready. */

					/* Establish SSL connection on top of TCP connection. */
					if ((connect_retval = SSL_connect(connection->ssl_handle)) != 1) {
						ssl_error = SSL_get_error(connection->ssl_handle, connect_retval);
						if (ssl_error == SSL_ERROR_WANT_READ) {
							poll_sock.events = POLLIN;
							/* hurl_debug(__func__, "SSL wants READ"); */
						} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
							poll_sock.events = POLLOUT;
							/* hurl_debug(__func__, "SSL wants WRITE"); */
						} else {
							ERR_error_string_n((unsigned long) ssl_error, ssl_error_str, sizeof(ssl_error_str));
							hurl_debug(__func__, "SSL connect error: %s", ssl_error_str);
							hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
							return CONNECTION_ERROR;
						}
					} else {
						hurl_debug(__func__, "The SSL connection is ready.");
						ssl_connected = 1;
					}
				}
			}

			/* Verify common name of certificate. */
			/* TODO: Dont verify certificate for URLs with IP addresses. */
			server_cert = SSL_get_peer_certificate(connection->ssl_handle);
			subject_name = X509_get_subject_name(server_cert);
			if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name, sizeof(common_name)) != -1) {
				hurl_debug(__func__, "Checking certificate common name.");
				/* Check if common name is *.domain.com */
				if (hurl_verify_ssl_scope(connection->server->domain->domain, common_name)) {
					certificate_ok = 1;
				} else {
					hurl_debug(__func__, "SSL: Expected %s but got %s", connection->server->domain->domain, common_name);
				}
			} else {
				hurl_debug(__func__, "Could not get common name of certificate.");
			}

			if (!certificate_ok) {
				/* Check "Subject Alternative Name" */
				if ((san_names = X509_get_ext_d2i(server_cert,
				NID_subject_alt_name, NULL, NULL)) != NULL) {
					hurl_debug(__func__, "Checking certificate for Subject Alternative Names");

					/* Get number of names. */
					san_names_nb = sk_GENERAL_NAME_num(san_names);

					for (i = 0; i < san_names_nb; i++) {
						const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
						if (current_name->type == GEN_DNS) {
							char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);

							/* Check for malicious \0 characters in name. */
							if (ASN1_STRING_length(current_name->d.dNSName) != (int) strlen(dns_name)) {
								break;
							} else {
								/* Compare DNS name in certificate with expected name. */
								hurl_debug(__func__, "SAN Check: '%s' vs. '%s'", connection->server->domain->domain, dns_name);
								if (hurl_verify_ssl_scope(connection->server->domain->domain, dns_name)) {
									certificate_ok = 1;
									break;
								}
							}
						}
					}
					sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
				}
			}

			gettimeofday(&ssl_end_connect, NULL);

			if (certificate_ok) {
				hurl_debug(__func__, "Certificate verified.");
				/* Change connection state. */
				connection->state = CONNECTION_STATE_CONNECTED;
			} else {
				hurl_debug(__func__, "Certificate verification failed.");
				hurl_connection_close(connection, CONNECTION_STATE_ERROR);
				return CONNECTION_ERROR;
			}

		} else {
			/* Change connection state. */
			connection->state = CONNECTION_STATE_CONNECTED;
		}
#endif
		/* Record end of connect procedure. */
		gettimeofday(&end_connect, NULL);

		/* Get size of receive buffer. */
		if (manager->recv_buffer_len == 0) {
			if (getsockopt(connection->sock, SOL_SOCKET, SO_RCVBUF, (void *) &manager->recv_buffer_len, &sockopt_len) == 0) {
				hurl_debug(__func__, "Receive buffer size: %d", manager->recv_buffer_len);
			} else {
				hurl_debug(__func__, "Failed to get receive buffer size: %s", strerror(errno));
			}
		}

		/* Calculate and save connection times */
		timersub(&end_connect, &connection->begin_connect, &connect_time);
		timersub(&ssl_end_connect, &ssl_begin_connect, &connect_time_ssl);
		connection->connect_time = timeval_to_msec(&connect_time);
		connection->connect_time_ssl = timeval_to_msec(&connect_time_ssl);

		/* Connection is ready. */
		return CONNECTION_NEW;
	}

	/* It was not possible to establish a connection. */
	connection->state = CONNECTION_STATE_ERROR;
	return CONNECTION_ERROR;
}

void hurl_resolve(HURLDomain *domain) {
	struct addrinfo *resolver_result, *resolver_answer, resolver_hints;
	int resolver_retval, i;
	char address_str[INET6_ADDRSTRLEN];

	/* Initialize resolvers hints (REQUIRED) */
	memset(&resolver_hints, 0, sizeof(struct addrinfo));
	resolver_hints.ai_family = AF_UNSPEC;
	resolver_hints.ai_socktype = SOCK_STREAM;
	resolver_hints.ai_flags = AI_PASSIVE;
	resolver_hints.ai_protocol = 0;
	resolver_hints.ai_canonname = NULL;
	resolver_hints.ai_addr = NULL;
	resolver_hints.ai_next = NULL;

	/* Resolve domain name */
	if ((resolver_retval = getaddrinfo(domain->domain, NULL, &resolver_hints, &resolver_result)) == 0) {
		/* Count number of answers. */
		domain->nrof_addresses = 0;
		for (resolver_answer = resolver_result; resolver_answer != NULL; resolver_answer = resolver_answer->ai_next) {
			domain->nrof_addresses++;
		}
		hurl_debug(__func__, "[ %s ] Number of addresses: %d", domain->domain, domain->nrof_addresses);
		if (domain->nrof_addresses > 0) {

			/* Allocate pointer space. */
			if ((domain->addresses = calloc(domain->nrof_addresses, sizeof(struct sockaddr *))) == NULL) {
				/* Out of memory. */
				domain->dns_state = DNS_STATE_ERROR;
				return;
			}
			i = 0;
			for (resolver_answer = resolver_result; resolver_answer != NULL; resolver_answer = resolver_answer->ai_next) {
				if ((domain->addresses[i] = calloc(1, sizeof(struct sockaddr))) == NULL) {
					/* Out of memory. */
					domain->dns_state = DNS_STATE_ERROR;
					return;
				}
				memcpy(domain->addresses[i], resolver_answer->ai_addr, sizeof(struct sockaddr));

				if (domain->addresses[i]->sa_family == AF_INET) {
					inet_ntop(AF_INET, &((struct sockaddr_in *) domain->addresses[i])->sin_addr, address_str, INET6_ADDRSTRLEN);
					hurl_debug(__func__, "[ %s ] %s", domain->domain, address_str);
				} else {
					inet_ntop(AF_INET6, &((struct sockaddr_in6 *) domain->addresses[i])->sin6_addr, address_str, INET6_ADDRSTRLEN);
					hurl_debug(__func__, "[ %s ] %s", domain->domain, address_str);
				}
				i++;
			}
			freeaddrinfo(resolver_result);
			domain->dns_state = DNS_STATE_RESOLVED;
		} else {
			domain->dns_state = DNS_STATE_ERROR;
		}
	} else {
		/* Resolution failed. */
		hurl_debug(__func__, "[ %s ] Resolver error: %s", domain->domain, gai_strerror(resolver_retval));
		domain->dns_state = DNS_STATE_ERROR;
	}
}

int hurl_connection_request(HURLConnection *connection, HURLPath *path) {
	size_t request_len = 0, max_request_len;
	char *request;
	HURLHeader *headers;
	HURLManager *manager = connection->server->domain->manager;
	int header_len;

	max_request_len = strlen(path->path) + strlen(path->server->domain->domain) + 512;

	if ((request = calloc(max_request_len, sizeof(char))) == NULL) {
		hurl_debug(__func__, "Out of memory.");
		return 0;
	}

	/* File path. */
	request_len += (size_t) snprintf(request + request_len, max_request_len - request_len, "GET %s HTTP/1.1\r\n", path->path);

	/* Copy custom headers headers. */
	headers = hurl_headers_copy(manager->headers);

	/* Set headers only controlled by hURL. */

	/* Host header. */
	hurl_header_add(&headers, "Host", path->server->domain->domain);

	/* Connection. */
	if (manager->feature_persistence == SUPPORTED) {
		hurl_header_add(&headers, "Connection", "keep-alive");
	} else {
		hurl_header_add(&headers, "Connection", "close");
	}

	/* End of header. */
	header_len = hurl_header_str(headers, request + request_len, max_request_len - request_len);

	/* Free headers */
	hurl_headers_free(headers);

	if (header_len > 0) {
		request_len += (size_t) header_len;

		if (hurl_send(connection, request, request_len) != (int) request_len) {
			free(request);
			hurl_debug(__func__, "[ %s:%u%.32s ] Failed to send request.", connection->server->domain->domain, connection->server->port, path->path);
			return 0;
		}

		/* Record time when request was sent. */
		gettimeofday(&path->request_sent, NULL);

		/* Call hook. */
		if (manager->hook_request_sent != NULL) {
			manager->hook_request_sent(path, connection);
		}

		/* The request was sent. */
		hurl_debug(__func__, "[ %s:%u%.32s ] Request sent.", connection->server->domain->domain, connection->server->port, path->path);
		free(request);
		return 1;
	} else {
		/* Request buffer is too small. */
		hurl_debug(__func__, "ERROR: Request buffer was too small. Could not send request.");
		free(request);
		return 0;
	}
}
/* Warning: labels array size should always be 127 */
unsigned char split_domain_name(char *name, char *labels[]) {
	unsigned char nrof_labels = 0;
	char *name_tmp, *name_split_ptr, *label;
	name_tmp = strdup(name);
	while ((label = strtok_r(name_tmp, ".", &name_split_ptr)) != NULL) {
		if (nrof_labels == 127) {
			hurl_debug(__func__, "WARNING: Max labels reached.");
			break;
		}
		labels[nrof_labels] = strdup(label);
		if (name_tmp != NULL)
			name_tmp = NULL;
		nrof_labels++;
	}
	free(name_tmp);
	return nrof_labels;
}

int hurl_parse_response_code(char *line, char **code_text) {
	long response_code;
	char *str, *copy, *part, *eof_part;
	char *split_str_ptr = NULL;
	int offset = 0;
	copy = hurl_allocstrcpy(line, strlen(line), 1);
	str = copy;

	/* Get response code. */
	part = strtok_r(str, " ", &split_str_ptr);
	offset += strlen(part) + 1;
	part = strtok_r(NULL, " ", &split_str_ptr);
	offset += strlen(part);
	response_code = (int) strtol(part, &eof_part, 10);
	if (response_code == LONG_MIN || response_code == LONG_MAX || response_code <= 0 || response_code > INT_MAX) {
		free(copy);
		hurl_debug(__func__, "Failed to parse response code.");
		return -1;
	}
	/* Get response code text. */
	if (code_text != NULL && strlen(line + offset + 1) > 0) {
		*code_text = hurl_allocstrcpy(line + offset + 1, strlen(line + offset + 1), 1);
	}
	free(copy);
	return response_code;
}

int hurl_connection_response(HURLConnection *connection, HURLPath *path, char **buffer, size_t *buffer_len, size_t *data_len,
		enum HTTPFeatureSupport *feature_persistence) {
	char *line;
	ssize_t recv_len = 1; /* Set to 1 to enter receive loop first time */
	char *eof_header = NULL;
	size_t header_len = 0;
	unsigned int header_line = 0;
	char *bgof_line, *eof_line;
	size_t line_len;
	size_t received = 0;
	size_t content_len = 0;
	size_t hook_recv_body_offset = 0;
	char *content_type = NULL;
	char *bgof_value;
	char *tmp;
	size_t next_buffer_len;
	int response_code = 0;
	char *response_code_text = NULL;
	char *redirect_location = NULL;
	char *transfer_encoding = NULL;
	int chunked_encoding = 0;
	char *chunk_ptr = NULL;
	size_t chunk_len = 0;
	char chunk_len_hex[16];
	size_t k;
	size_t unprocessed_len = 0;
	int chunk_len_len = 0;
	unsigned int nrof_chunks = 0;
	HURLManager *manager = connection->server->domain->manager;
	unsigned int receive_buffer_len = manager->recv_buffer_len;
	char *receive_buffer = malloc(sizeof(char) * receive_buffer_len);
	HURLHeader *headers = NULL;
	char *key, *value;
	size_t overhead = 0;
	int transfer_complete = 0;
	char *redirect_url = NULL;
	const char *extra_slash;
	size_t redirect_url_len;
	HURLPath *path_created;
	size_t body_recv_len = 0;

	/* Allocate buffer. */
	if (*buffer == NULL) {
		*buffer = malloc(sizeof(char) * receive_buffer_len);
		**buffer = '\0';
		*buffer_len = receive_buffer_len;
		*data_len = 0;
	} else {
		received = *data_len;
		hurl_debug(__func__, "[ %s:%u%.32s ] %ld bytes already in buffer.", connection->server->domain->domain, connection->server->port, path->path, received);
	}

	hurl_debug(__func__, "[ %s:%u%.32s ] Waiting for response.", path->server->domain->domain, connection->server->port, path->path);

	/* While receiving data or if socket was not ready. */
	while (recv_len > 0) {
		if ((recv_len = hurl_recv(connection, receive_buffer, receive_buffer_len)) > 0) {
			/* Expand connection buffer if necessary. */
			if (*buffer_len - *data_len <= (unsigned long) recv_len) {
				/* Buffer needs more space. */
				next_buffer_len = *data_len + (size_t) recv_len;
				if ((tmp = realloc(*buffer, next_buffer_len + 1)) != NULL) {
					*buffer = tmp;
					*buffer_len = next_buffer_len;
				} else {
					hurl_debug(__func__, "Out of memory.");
					return 0;
				}
			}

			/* Copy received data into connection buffer. */
			memcpy(*buffer + *data_len, receive_buffer, (size_t) recv_len);
			*data_len += (size_t) recv_len;
			*(*buffer + *data_len) = '\0';

			/* Call recv() hook */
			if (manager->hook_recv) {
				manager->hook_recv(path, connection, *buffer, *data_len);
			}

			if (eof_header == NULL && (eof_header = strstr(*buffer, "\r\n\r\n")) != NULL) {
				/* Header received. */
				header_len = (size_t) (eof_header - *buffer + 4);

				/* Call header received hook */
				if (manager->hook_header_recv) {
					manager->hook_header_recv(path, *buffer, header_len);
				}

				hurl_debug(__func__, "[ %s:%u%.32s ] Header received.", path->server->domain->domain, connection->server->port, path->path);
				/* Parse header. */
				bgof_line = *buffer;
				while (bgof_line < eof_header) {
					if ((eof_line = strstr(bgof_line, "\r\n")) == NULL) {
						break;
					}
					line_len = (size_t) (eof_line - bgof_line);
					line = hurl_allocstrcpy(bgof_line, line_len, 1);
					eof_line = line + line_len;
					header_line++;

					if (strncasecmp(line, "http/1.1", strlen("http/1.1")) == 0) {
						/* Server supports HTTP 1.1 */
						*feature_persistence = SUPPORTED;
						response_code = hurl_parse_response_code(line, &response_code_text);
						if (manager->hook_response_code) {
							manager->hook_response_code(path, connection, response_code, response_code_text);
						}
						hurl_debug(__func__, "[ %s:%u%.32s ] Response code: %d %s", path->server->domain->domain, connection->server->port, path->path,
								response_code, response_code_text);
						free(response_code_text);
					} else if (strncasecmp(line, "http/1.0", strlen("http/1.0")) == 0) {
						/* Server supports HTTP 1.0 */
						*feature_persistence = 0;
						response_code = hurl_parse_response_code(line, &response_code_text);
						if (manager->hook_response_code) {
							manager->hook_response_code(path, connection, response_code, response_code_text);
						}
						hurl_debug(__func__, "[ %s:%u%.32s ] Response code: %d %s", path->server->domain->domain, connection->server->port, path->path,
								response_code, response_code_text);
						free(response_code_text);
					} else if (hurl_header_split_line(line, line_len, &key, &value)) {
						/* Add header to list. */
						hurl_header_add(&headers, key, value);

						/* hurl_debug(__func__, "[%s][%u][%s] HEADER: %s", path->server->domain->domain, server->port, path->path, line); */
						if (strcasecmp(key, "connection") == 0) {
							/* Check how the server will treat this connection. */
							if ((bgof_value = strstr(line, ": ")) != NULL) {
								bgof_value += 2;
								if (strcasecmp(bgof_value, "close") == 0) {
									*feature_persistence = UNSUPPORTED;
								}
							}
						} else if (strcasecmp(key, "content-length") == 0) {
							content_len = (size_t) strtol(value, NULL, 10);
							hurl_debug(__func__, "[ %s:%u%.32s ] Content length: %ld", path->server->domain->domain, connection->server->port, path->path,
									content_len);
						} else if (strcasecmp(key, "content-type") == 0) {
							content_type = hurl_allocstrcpy(value, strlen(value), (size_t) 1);
							hurl_debug(__func__, "[ %s:%u%.32s ] Content type: %s", path->server->domain->domain, connection->server->port, path->path,
									content_type);
						} else if (strcasecmp(key, "location") == 0) {
							redirect_location = hurl_allocstrcpy(value, strlen(value), 1);
							hurl_debug(__func__, "[ %s:%u%.32s ] Redirect location: %s", path->server->domain->domain, connection->server->port, path->path,
									redirect_location);
						} else if (strcasecmp(key, "transfer-encoding") == 0) {
							transfer_encoding = hurl_allocstrcpy(value, strlen(value), 1);
							hurl_debug(__func__, "[ %s:%u%.32s ] Transfer encoding: %s", path->server->domain->domain, connection->server->port, path->path,
									transfer_encoding);
							if (strcasecmp(transfer_encoding, "chunked") == 0) {
								chunked_encoding = 1;
							} else {
								/* Unsupported transfer encoding */
								hurl_debug(__func__, "Bad Transfer-Encoding header. Assuming chunked encoding...");
								chunked_encoding = 1;
							}
						}

						/* Header header key and value */
						free(key);
						free(value);

					} else {
						hurl_debug(__func__, "Header parsing error: '%s'", line);
						free(line);
						free(*buffer);
						*buffer = NULL;
						*data_len = 0;
						/* Get lock, update download state, release lock. */
						pthread_mutex_lock(&manager->lock);
						hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());
						path->state = DOWNLOAD_STATE_ERROR;
						/* Call transfer failed hook. */
						if (manager->hook_transfer_complete) {
							manager->hook_transfer_complete(path, connection, HURL_XFER_PARSING, content_len, header_len + overhead);
						}
						pthread_mutex_unlock(&manager->lock);
						return 0;
					}

					free(line);

					/* Set beginning of next header line. */
					bgof_line += line_len + 2;
				}

				/* Header has been parsed, so call hook. */
				if (manager->hook_header_received != NULL) {
					manager->hook_header_received(path, response_code, headers, header_len);
				}
				hurl_headers_free(headers);

				if (*feature_persistence == SUPPORTED) {
					hurl_debug(__func__, "[%s][%u] Persistent connection.", path->server->domain->domain, connection->server->port);
				} else {
					hurl_debug(__func__, "[%s][%u] Non-persistent connection.", path->server->domain->domain, connection->server->port);
				}

				/* Check response code for redirection. */
				if (response_code >= 300 && response_code < 400) {
					if (redirect_location != NULL) {
						hurl_debug(__func__, "Redirect detected: %.64s", redirect_location);
						/* Create FULL redirection URL */
						if (strncasecmp("http://", redirect_location, strlen("http://")) == 0
								|| strncasecmp("https://", redirect_location, strlen("http://")) == 0) {
							/* This is an absolute URL with */
							hurl_debug(__func__, "Absolute redirection: '%s'", redirect_location);
							redirect_url = strdup(redirect_location);
						} else if (strncmp("//", redirect_location, 2) == 0) {
							/* This is a protocol-independent URL */
							hurl_debug(__func__, "Absolute protocol-less redirection: '%s'", redirect_location);
							redirect_url_len = strlen(redirect_location) + strlen("https://") + 1;
							redirect_url = malloc(sizeof(char) * redirect_url_len);
							if (path->server->tls) {
								snprintf(redirect_url, redirect_url_len, "https:%s", redirect_location);
							} else {
								snprintf(redirect_url, redirect_url_len, "http:%s", redirect_location);
							}
						} else {
							/* Let's assume everything else is a relative path */
							redirect_url_len = strlen("https://") + strlen(path->server->domain->domain) + 1 + strlen(redirect_location) + 1;
							redirect_url = malloc(sizeof(char) * redirect_url_len);
							if (redirect_location[0] == '/') {
								extra_slash = "";
							} else {
								extra_slash = "/";
							}
							if (path->server->tls) {
								snprintf(redirect_url, redirect_url_len, "https://%s%s%s", path->server->domain->domain, extra_slash, redirect_location);
							} else {
								snprintf(redirect_url, redirect_url_len, "http://%s%s%s", path->server->domain->domain, extra_slash, redirect_location);
							}
							hurl_debug(__func__, "Relative redirection: '%s' => '%s'", redirect_location, redirect_url);
						}

						if (path->redirect_count < manager->max_redirects) {
							/* Hook point. Should redirect be followed? */
							if ((manager->hook_redirect == NULL && manager->follow_redirect)
									|| (manager->hook_redirect != NULL && manager->hook_redirect(path, response_code, redirect_url))) {
								/* Follow redirection by adding a new item to download queue.
								 * DO NOT ALLOW DUPLICATES! */
								if ((path_created = hurl_add_url(manager, 0, redirect_url, NULL)) == NULL) {
									hurl_debug(__func__, "Failed to add redirect to download queue.");
								} else {
									/* The path was added, to fix tag */
									path_created->tag = !manager->retag ? path->tag : manager->retag(path_created, path, redirect_url);
									path_created->redirect_count = path->redirect_count + 1;
								}
							}
						} else {
							hurl_debug(__func__, "HTTP redirect loop detected.");
							free(*buffer);
							*buffer = NULL;
							*data_len = 0;
							free(redirect_location);
							pthread_mutex_lock(&manager->lock);
							hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());
							path->state = DOWNLOAD_STATE_ERROR;
							/* Call transfer failed hook. */
							if (manager->hook_transfer_complete) {
								manager->hook_transfer_complete(path, connection, HURL_XFER_REDIRECT_LOOP, content_len, header_len + overhead);
							}
							pthread_mutex_unlock(&manager->lock);
							return 0;
						}
					} else {
						hurl_debug(__func__, "Redirect detected but location header is missing.");
					}
				} else if (response_code < 100) {
					hurl_debug(__func__, "Warning: Bad response code.");
				}

				/* Move eof_header past \r\n\r\n */
				eof_header += 4;

				if (chunked_encoding) {
					chunk_ptr = eof_header;
				}

				/* Release memory allocated above */
				free(redirect_url);
				free(redirect_location);
				free(content_type);
				free(transfer_encoding);
			}

			/* Update total number of bytes received. */
			assert(recv_len >= 0);
			received += (size_t) recv_len;

			if (eof_header != NULL) {
				if (!chunked_encoding) {
					/* Call receive hook */
					if (manager->hook_body_recv != NULL) {
						body_recv_len = header_len + (size_t) recv_len > received ? received - header_len : (size_t) recv_len;
						/* Check if body_recv_len exceeds content length of current response. */
						if (hook_recv_body_offset + body_recv_len > content_len) {
							body_recv_len = content_len - hook_recv_body_offset;
						}
						manager->hook_body_recv(path, *buffer + header_len + hook_recv_body_offset, body_recv_len);
						hook_recv_body_offset += body_recv_len;
					}
				}

				/* Check if the whole file has been received. */
				if (!chunked_encoding && received >= header_len + content_len + overhead) {
					transfer_complete = 1;

					if (manager->hook_transfer_complete != NULL) {
						manager->hook_transfer_complete(path, connection, HURL_XFER_OK, content_len, header_len);
					}

					hurl_debug(__func__, "[ %s:%u%.32s ] Transfer complete: %d bytes received.", path->server->domain->domain, connection->server->port,
							path->path, content_len);
					/* Get lock, update download state, release lock. */
					pthread_mutex_lock(&manager->lock);
					hurl_debug(__func__, "Thread %u got lock.", (unsigned int) pthread_self());
					path->state = DOWNLOAD_STATE_COMPLETED;
					pthread_mutex_unlock(&manager->lock);
					hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());

				} else if (chunked_encoding) {
					/* Chunked transfer encoding. */
					while (header_len + content_len + overhead < received) {
						/* Get chunk size */
						chunk_ptr = *buffer + header_len + content_len + overhead;
						unprocessed_len = received - header_len - content_len - overhead;
						k = 0;
						bzero(chunk_len_hex, sizeof(chunk_len_hex));
						chunk_len_hex[0] = '0';
						chunk_len_hex[1] = 'x';
						chunk_len_len = -1;
						while (k < unprocessed_len) {
							if (k == sizeof(chunk_len_hex) - 1) {
								break;
							}
							if (chunk_ptr[k] == '\r' && chunk_ptr[k + 1] == '\n') {
								chunk_len_len = (int) k;
								break;
							}
							chunk_len_hex[2 + k] = chunk_ptr[k];
							k++;
						}

						if (chunk_len_len == -1) {
							/* The size of the next chunk cannot be read yet. */
							hurl_debug(__func__, "Chunk header incomplete.");
							break;
						}

						chunk_len = (size_t) strtol(chunk_len_hex, NULL, 16);
						/* hurl_debug(__func__, "Chunk str: %.2s => %d", chunk_ptr, chunk_len); */

						/* Check if the entire chunk has been received. */
						if (unprocessed_len < (size_t) chunk_len_len + 2 + chunk_len) {
							break;
						}

						if (chunk_len > 0) {
							nrof_chunks++;
						}

						/* Call receive hook */
						if (manager->hook_body_recv != NULL) {
							manager->hook_body_recv(path, *buffer + header_len + content_len + overhead + chunk_len_len + 2, chunk_len);
						}

						/* Update content length */
						content_len += chunk_len;
						/* Update overhead */
						overhead += ((size_t) chunk_len_len + 2 + 2); /* Size of chunk length + '\r\n' + '\r\n' */

						if (chunk_len == 0) {
							transfer_complete = 1;
							/* Call hook */
							if (manager->hook_transfer_complete != NULL) {
								manager->hook_transfer_complete(path, connection, HURL_XFER_OK, content_len, header_len + overhead);
							}

							/* Download complete. */
							hurl_debug(__func__, "[ %s:%u%.32s ] Transfer complete: %d bytes received.", path->server->domain->domain, connection->server->port,
									path->path, content_len);

							/* Update download state of path. */
							pthread_mutex_lock(&manager->lock);
							path->state = DOWNLOAD_STATE_COMPLETED;
							pthread_mutex_unlock(&manager->lock);
							break;
						}

					}
				}
				if (transfer_complete) {
					/* Call hook - indicate end of data */
					if (manager->hook_body_recv) {
						manager->hook_body_recv(path, NULL, 0);
					}

					/* Free receive buffer */
					free(receive_buffer);
					/* Remove received file from buffer if connection is persistent. */
					if (*feature_persistence == SUPPORTED) {
						if (*data_len < header_len - content_len - overhead) {
							next_buffer_len = 0;
							/* TODO This should not be necessary. There is a bug in counters. */
						} else {
							next_buffer_len = *data_len - header_len - content_len - overhead;
						}
						hurl_debug(__func__, "%u bytes left in buffer.", next_buffer_len);
						tmp = malloc(sizeof(char) * (next_buffer_len + 1));
						memcpy(tmp, *buffer + header_len + content_len + overhead, next_buffer_len);
						tmp[next_buffer_len] = '\0';
						*data_len = next_buffer_len;
						*buffer_len = next_buffer_len;
						free(*buffer);
						*buffer = tmp;
						return 1;
					} else {
						hurl_debug(__func__, "Freeing buffer.");
						free(*buffer);
						*buffer = NULL;
						*data_len = 0;
						hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
						return 0;
					}
				}
				/* In case of HTTP redirection we don't expect to get this far. */
				if (chunked_encoding == 1 && response_code > 400 && response_code < 300) {
					/* Bad chunked encoding */
					hurl_debug(__func__, "HTTP redirect: Failed to detect end of chunked encoding.");
				}
			}
		} else if (recv_len == 0) {
			/* Connection closed prematurely by server. */
			hurl_debug(__func__, "[ %s:%u%.32s ] Transfer failed. Connection closed by server.", path->server->domain->domain, connection->server->port,
					path->path);
			*feature_persistence = UNSUPPORTED;
			free(*buffer);
			*buffer = NULL;
			*data_len = 0;
			/* Call transfer failed hook. */
			if (manager->hook_transfer_complete) {
				manager->hook_transfer_complete(path, connection, HURL_XFER_FAILED, content_len, header_len + overhead);
			}
			/* Free receive buffer */
			free(receive_buffer);
		} else {
			/* Transfer was NOT completed. */
			hurl_debug(__func__, "[ %s:%u%.32s ] Transfer failed.", path->server->domain->domain, connection->server->port, path->path);
			/* Call transfer failed hook. */
			if (manager->hook_transfer_complete) {
				manager->hook_transfer_complete(path, connection, HURL_XFER_FAILED, content_len, header_len + overhead);
			}
			/* Free receive buffer */
			free(receive_buffer);
		}

	}

	/* Update download state of path. */
	pthread_mutex_lock(&manager->lock);
	if (!connection->reused) {
		/* Request was sent on a new connection. */
		if (path->retries < path->server->domain->manager->max_retries) {
			hurl_debug(__func__, "[ %s:%u%.32s ] Retrying download.", path->server->domain->domain, connection->server->port, path->path);
			path->retries++;
			path->state = DOWNLOAD_STATE_PENDING;
		} else {
			path->state = DOWNLOAD_STATE_ERROR;
		}
	} else {
		/* Request was sent on a reused connection. */
		hurl_debug(__func__, "[ %s:%u%.32s ] Request failed on a reused connection. Retrying...", path->server->domain->domain, connection->server->port,
				path->path);
		path->state = DOWNLOAD_STATE_PENDING;
	}
	pthread_mutex_unlock(&manager->lock);
	hurl_debug(__func__, "Thread %u released lock.", (unsigned int) pthread_self());

	free(*buffer);
	*buffer = NULL;

	hurl_connection_close(connection, CONNECTION_STATE_CLOSED);
	return -1;

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
void hurl_connection_close(HURLConnection *connection, enum HURLConnectionState state) {
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

int hurl_header_add(HURLHeader **headers, char *key, char *value) {
	HURLHeader *header, *h = NULL;
	int updated = 0;

	/* Check for duplicate headers. */
	h = *headers;
	while (h != NULL && h->next != NULL) {
		if (strcasecmp(h->key, key) == 0) {
			/* Duplicate detected: Overwrite previous value. */
			free(h->value);
			h->value = hurl_allocstrcpy(value, strlen(value), 1);
			updated = 1;
			break;
		}
		h = h->next;
	}
	if (!updated) {
		if ((header = calloc(1, sizeof(HURLHeader))) == NULL) {
			return 0;
		}
		header->key = hurl_allocstrcpy(key, strlen(key), 1);
		header->value = hurl_allocstrcpy(value, strlen(value), 1);
		/* Add header to linked list. */
		if (h != NULL) {
			h->next = header;
			header->previous = h;
		} else {
			/* This is the first item in the list. */
			*headers = header;
		}
		return 1;
	} else {
		return 1;
	}
}

int hurl_header_str(HURLHeader *headers, char *buffer, size_t buffer_len) {
	HURLHeader *h = headers;
	size_t print_len = 0;
	size_t header_len;
	while (h != NULL && print_len < buffer_len) {
		/* size of key + ": " + size of value + "\r\n" + final "\r\n" + \0 */
		header_len = strlen(h->key) + 2 + strlen(h->value) + 2 + 2 + 1;
		if (buffer_len >= print_len + header_len) {
			print_len += (size_t) snprintf(buffer + print_len, buffer_len - print_len, "%s: %s\r\n", h->key, h->value);
		} else {
			/* The buffer is full. */
			return -1;
		}
		h = h->next;
	}
	/* Add final \r\n */
	print_len += (size_t) snprintf(buffer + print_len, buffer_len - print_len, "\r\n");
	return (int) print_len;
}

void hurl_headers_free(HURLHeader *bgof_headers) {
	HURLHeader *h = bgof_headers, *next;
	while (h != NULL) {
		next = h->next;
		free(h->key);
		free(h->value);
		free(h);
		h = next;
	}
}

HURLHeader *hurl_headers_copy(HURLHeader *headers) {
	HURLHeader *h = headers, *copy = NULL, *c, *copy_tail = NULL;
	while (h != NULL) {
		if ((c = calloc(1, sizeof(HURLHeader))) == NULL) {
			hurl_headers_free(copy);
			return NULL;
		}
		if ((c->key = hurl_allocstrcpy(h->key, strlen(h->key), 1)) == NULL) {
			free(c);
			hurl_headers_free(copy);
		}
		if ((c->value = hurl_allocstrcpy(h->value, strlen(h->value), 1)) == NULL) {
			free(c->key);
			free(c);
			hurl_headers_free(copy);
		}

		if (copy_tail == NULL) {
			copy = c;
			copy_tail = copy;
		} else {
			copy_tail->next = c;
			c->previous = copy_tail;
			copy_tail = c;
		}
		h = h->next;
	}
	return copy;
}

char *hurl_header_get(HURLHeader *headers, char *key) {
	HURLHeader *h;
	if (headers == NULL) {
		return NULL;
	}
	h = headers;
	while (h != NULL) {
		if (strcasecmp(h->key, key) == 0) {
			return h->value;
		}
		h = h->next;
	}
	return NULL;
}

int hurl_header_split_line(char *line, size_t line_len, char **key, char **value) {
	int i = 0;
	int bgof_value = 0;
	int value_len = -1;
	for (i = 0; i < (int) line_len - 1; i++) {
		/* Find end of key. */
		/* if (!bgof_value && line[i] == ':' && line[i + 1] == ' ') { */
		if (!bgof_value && line[i] == ':') {
			if ((*key = hurl_allocstrcpy(line, (size_t) i, 1)) != NULL) {
				if (line[i + 1] == ' ') {
					bgof_value = i + 2;
					i++;
				} else {
					bgof_value = i + 1;
				}
			} else {
				return 0;
			}
		} else if (bgof_value && line[i] == '\r' && line[i + 1] == '\n') {
			/* HTTP newline */
			value_len = (int) (i - bgof_value);
		} else if (bgof_value && line[i] == '\n') {
			/* Regular newline */
			value_len = i - bgof_value;
		}

	}
	if (bgof_value) {
		if (value_len == -1) {
			/* Line terminator is missing */
			value_len = (int) line_len - bgof_value;
		}
		if ((*value = hurl_allocstrcpy(line + bgof_value, (size_t) value_len, 1)) == NULL) {
			free(*key);
			*key = NULL;
			*value = NULL;
			return 0;
		} else {
			/* hurl_debug(__func__, "HEADER: %s => %s", *key, *value); */
			return 1;
		}
	}
	return 0;
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

void hurl_domain_free(HURLManager *manager, HURLDomain *domain) {
	HURLServer *next, *server;
	unsigned int i;
	server = domain->servers;
	while (server != NULL) {
		next = server->next;
		hurl_server_free(manager, server);
		server = next;
	}
	for (i = 0; i < domain->nrof_addresses; i++) {
		free(domain->addresses[i]);
	}
	free(domain->addresses);
	free(domain->domain);
	free(domain);
}

void hurl_server_free(HURLManager *manager, HURLServer *server) {
	HURLPath *next, *path;
	path = server->paths;
	while (path != NULL) {
		next = path->next;
		hurl_path_free(manager, path);
		path = next;
	}
	free(server);
}

void hurl_connection_free(HURLConnection *connection) {
	if (connection->state != CONNECTION_STATE_CLOSED) {
		if (connection->ssl_handle) {
			SSL_free(connection->ssl_handle);
		}
		if (connection->ssl_context) {
			SSL_CTX_free(connection->ssl_context);
		}
	}
	free(connection);
}

void hurl_path_free(HURLManager *manager, HURLPath *path) {
	free(path->path);
	if (manager->free_tag && path->tag != NULL) {
		manager->free_tag(path->tag);
	};
	free(path);
}

int hurl_header_exists(HURLHeader *headers, char *key) {
	HURLHeader *h_search;
	for (h_search = headers; h_search != NULL; h_search = h_search->next) {
		if (strcasecmp(key, h_search->key) == 0) {
			return 1;
		}
	}
	return 0;
}
