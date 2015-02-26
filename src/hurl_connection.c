#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "hurl/hurl.h"
#include "hurl/internal.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

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

void *hurl_connection_exec(void *connection_ptr) {
	HURLConnection *connection = (HURLConnection *) connection_ptr;
	HURLServer *server = connection->server;
	HURLDomain *domain = server->domain;
	HURLManager *manager = domain->manager;
	HURLPath *path = NULL;
	int connect_retval;
	char *buffer = NULL;
	size_t buffer_len = 0, data_len = 0;
	HTTPFeatureSupport feature_persistence = UNKNOWN_SUPPORT, feature_pipelining = UNKNOWN_SUPPORT;
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

int hurl_connection_response(HURLConnection *connection, HURLPath *path, char **buffer, size_t *buffer_len, size_t *data_len,
		HTTPFeatureSupport *feature_persistence) {
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
									path_created->redirect_count = path->redirect_count + 1;
									path_created->redirector = path;
                                    path_created->tag = !manager->retag ? path->tag : manager->retag(path_created, redirect_url);
									
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
