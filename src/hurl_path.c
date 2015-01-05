/*
 * hurl_path.c
 *
 *  Created on: Jan 5, 2015
 *      Author: Magnus
 */
#include <stdlib.h>

void hurl_path_free(HURLManager *manager, HURLPath *path) {
	free(path->path);
	if (manager->free_tag && path->tag != NULL) {
		manager->free_tag(path->tag);
	};
	free(path);
}
