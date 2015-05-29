#include "hurl/hurl.h"
#include "hurl/internal.h"
#include <stdlib.h>

void hurl_path_free(HURLManager *manager,
                    HURLPath *path)
{
    free(path->path);
    if (manager->free_tag && path->tag != NULL)
    {
        manager->free_tag(path->tag);
    };
    free(path);
}
