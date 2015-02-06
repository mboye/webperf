#ifndef INCLUDE_HURL_CONNECTION_H_
#define INCLUDE_HURL_CONNECTION_H_

typedef enum hurl_connection_state {
	CONNECTION_STATE_CLOSED = 0, CONNECTION_STATE_IN_PROGRESS = 1, CONNECTION_STATE_CONNECTED = 2, CONNECTION_STATE_ERROR = -1
} HURLConnectionState;

typedef struct hurl_connection {
	HURLServer *server; /* Reverse pointer to server. */
	int sock; /* Socket number of connection. */
#ifndef HURL_NO_SSL
	SSL *ssl_handle; /* SSL handle. */
	SSL_CTX *ssl_context; /* SSL context. */
#endif
	enum HURLConnectionState state; /* State of socket. */
	unsigned long data_tx, data_rx; /* TODO: Bytes sent and received. */
	unsigned int request_tx; /* TODO: Number of requests sent on connection. */
	HURLConnection *previous, *next; /* Linked list pointers. */
	pthread_t thread; /* Connection thread. */
	float connect_time, connect_time_ssl; /* Time to establish TCP+SSL connection and just SSL connection. */
	struct timeval begin_connect; /* Time when connect() was called. */
	int reused; /* Was the connection reused? */
} HURLConnection;

void hurl_connection_free(HURLConnection *connection);
void *hurl_connection_exec(void *connection_ptr);
int hurl_connect(HURLConnection *connection);
int hurl_connection_request(HURLConnection *connection, HURLPath *path);
int hurl_connection_response(HURLConnection *connection,
			     HURLPath *path,
			     char **buffer,
			     size_t *buffer_len,
			     size_t *data_len,
			     enum HTTPFeatureSupport *feature_persistence);

#endif /* INCLUDE_HURL_CONNECTION_H_ */
