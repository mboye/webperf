/*
 * hurl_domain.c
 *
 *  Created on: Jan 5, 2015
 *      Author: Magnus
 */
#include <stdlib.h>

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
