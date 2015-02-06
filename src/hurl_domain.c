#include <stdlib.h>

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
