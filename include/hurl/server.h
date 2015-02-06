#ifndef INCLUDE_HURL_SERVER_H_
#define INCLUDE_HURL_SERVER_H_

typedef struct hurl_server {
	HURLDomain *domain; /* Reverse pointer to domain. */
	HURLServer *previous, *next; /* Linked list pointers. */
	unsigned short port; /* Server port number. */
	int tls; /* Connection should use TLS. */
	HURLPath *paths; /* Path of files on server. */
	unsigned int nrof_paths; /* Number of files to be downloaded from domain. */
	HURLConnection *connections; /* Connection structures. */
	unsigned int max_connections; /* Maximum number of connections to this server. */
	enum HURLServerState state; /* Server state. */
	unsigned int pipeline_errors; /* Number of times pipelined requests failed. */
	void *tag;  /* Pointer used to associate user data with server. */
} HURLServer;

typedef enum hurl_server_state {
	SERVER_STATE_OK = 0, /* The server is functional */
	SERVER_STATE_ERROR = -1, /* Something went wrong with the server. */
	SERVER_STATE_SSL_ERROR = -2 /* Failed to secure connection. */
} HURLServerState; 

void hurl_server_free(HURLManager *manager, HURLServer *server);
#endif /* INCLUDE_HURL_SERVER_H_ */
