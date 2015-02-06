#ifndef HURL_PATH_H_
#define HURL_PATH_H_

void hurl_path_free(HURLManager *manager, HURLPath *path);

typedef struct hurl_path {
	char *path; /* Path of file e.g. /index.html */
	HURLServer *server; /* Reverse pointer to domain structure. */
	enum HURLDownloadState state; /* Has the file been downloaded? */
	HURLPath *previous, *next; /* Linked list pointers. */
	unsigned int retries; /* Number of retries. */
	void *tag; /*  ointer used to associate user data with path (target). */
	struct timeval request_sent; /* When was a GET request sent for this path. */
	struct timeval response_received; /* When was the response to the GET request received. */
	int redirect_count; /* Number of redirects that have been followed. */
} HURLPath;

#endif /* HURL_PATH_H_ */
