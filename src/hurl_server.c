#include <hurl/server.h>
#include <hurl/path.h>
#include <hurl/manager.h>
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
