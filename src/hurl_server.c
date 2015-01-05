/*
 * hurl_server.c
 *
 *  Created on: Jan 5, 2015
 *      Author: Magnus
 */
#include <stdlib.h>

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
