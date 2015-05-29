#include "hurl/hurl.h"
#include "hurl/internal.h"
#include <stdlib.h>

void hurl_server_free(HURLManager *manager,
                      HURLServer *server)
{
    HURLPath *next;
    HURLPath *path = server->paths;

    while (path != NULL)
    {
        next = path->next;
        hurl_path_free(manager, path);
        path = next;
    }

    free(server);
}
