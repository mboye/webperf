/*
 * example1.c
 *
 *  Created on: Sep 3, 2014
 *      Author: Magnus Boye
 */

#include <stdio.h>
#include <stdlib.h>
#include <hurl_core.h>
#include <sys/time.h>

struct tag
{
    struct timeval begin_transfer, end_transfer;
    int response_code;
    int completed;
    size_t content_length;
};

void transfer_complete(HURLPath *path,
                       HURLConnection *conn,
                       size_t content_length,
                       size_t overhead)
{
    struct tag *t = (struct tag *)path->tag;
    gettimeofday(&t->end_transfer, NULL);
    t->completed = 1;
    t->content_length = content_length;
}

int pre_connect(HURLPath *path,
                HURLConnection *conn)
{
    struct tag *t = (struct tag *)path->tag;
    gettimeofday(&t->begin_transfer, NULL);
    return 1; /* Allow connect */
}

void check_response_code(HURLPath *path,
                         HURLConnection *conn,
                         int respcode,
                         char *resptext)
{
    struct tag *t = (struct tag *)path->tag;
    t->response_code = respcode;
}

int main(int argc,
         char *argv[])
{
    HURLManager *manager;
    struct timeval transfer_time;
    struct tag *t;

    if (argc != 2)
    {
        printf("Usage: example1 <URL>\n");
        exit(EXIT_FAILURE);
    }
    manager = hurl_manager_init();
    t = calloc(1, sizeof(struct tag));
    manager->hook_transfer_complete = transfer_complete;
    manager->hook_pre_connect = pre_connect;
    manager->hook_response_code = check_response_code;
    hurl_add_url(manager, 0, argv[1], t);
    hurl_exec(manager);
    if (t->response_code == 200 && t->completed)
    {
        timersub(&t->end_transfer, &t->begin_transfer, &transfer_time);
        printf("Successfully transferred %lu bytes in %f ms.\n",
               t->content_length,
               timeval_to_msec(&transfer_time));
        hurl_manager_free(manager);
        free(t);
        exit(EXIT_SUCCESS);
    }
    else
    {
        printf("The transfer failed with response code %d.\n",
               t->response_code);
        hurl_manager_free(manager);
        free(t);
        exit(EXIT_FAILURE);
    }
}
