#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>

#include<hurl_connection.h>
#include<hurl_domain.h>
#include<hurl_header.h>
#include<hurl_parse.h>
#include<hurl_path.h>
#include<hurl_server.h>

#ifndef HURL_NO_SSL
#include <openssl/ssl.h>
#endif

#ifndef HURL_CORE_H_
#define HURL_CORE_H_

/* Mac OS X - specific: MSG_NOSIGNAL not defined in OS X */
#if defined(__APPLE__) || defined(__MACH__)
# ifndef MSG_NOSIGNAL
#   define MSG_NOSIGNAL SO_NOSIGPIPE
# endif
#endif

#define HURL_MAX_CONNECTIONS 16 /* Overall connection limit. */
#define HURL_MAX_DOMAIN_CONNECTIONS 6 /* Connection limit per domain name. */
#define HURL_MAX_PIPELINE_REQUESTS 3 /* Maximum number of consecutive HTTP requests to send. */
#define HURL_KEEP_ALIVE 60 /* 60 seconds */
#define HURL_MAX_RETRIES 0 /* Number of download retries. */
#define HURL_MAX_REDIRECTS 2 /* Number of HTTP redirects. */
#define HURL_TIMEOUT 5000 /* Default timeout in ms. */
#define HURL_CA_PATH "/etc/ssl/certs/"

enum HTTPFeatureSupport {
	SUPPORTED, UNSUPPORTED, UNKNOWN_SUPPORT
};

enum HURLDownloadState {
	/* File has not yet been processed. */
	DOWNLOAD_STATE_PENDING = 1,
	/* File is currently being processed. */
	DOWNLOAD_STATE_IN_PROGRESS = 2,
	/* File has been downloaded successfuly. */
	DOWNLOAD_STATE_COMPLETED = 4,
	/* File was processed and download failed. */
	DOWNLOAD_STATE_ERROR = 8
};

enum HURLDNSState {
	DNS_STATE_UNRESOLVED = 0, /* Name resolution has not been attempted yet. */
	DNS_STATE_RESOLVED, /* Name resolution was successful. */
	DNS_STATE_ERROR /* Name resolution failed. */
};


#define HURL_URL_PARSE_OK 0
#define HURL_URL_PARSE_ERROR 1

enum HURLConnectResult {
	CONNECTION_ERROR = 0, /* The connection attempt failed. */
	 CONNECTION_NEW = 1, /* A new connection was succcessfully established. */
	 CONNECTION_REUSED = 2 /* An existing connection is being reused. */
};

enum hurl_transfer_result {
	HURL_XFER_HOOK = -6, /* Transfer aborted due to hook return value. */
	HURL_XFER_REDIRECT_LOOP = -5, /* HTTP redirect limit reached. */
	HURL_XFER_PARSING = -4, /* HTTP header parsing error. */
	HURL_XFER_FAILED = -3, /* Transfer failed after connecting */
	HURL_XFER_CONNECT = -2, /* TCP/SSL connection could not be established. */
	HURL_XFER_DNS = -1, /* DNS resolution failed. */
	HURL_XFER_NONE = 0, /* No result yet. Target has not been processed. */
	HURL_XFER_OK = 1, /* Transfer successful. */
	HURL_XFER_REDIRECT = 2 /* Transfer contained HTTP redirect. */
};
typedef enum hurl_transfer_result HURLTransferResult;

/* Hierarchical structure of hurl:
 * HURLManager
 *  |-->HURLDomain
 *       |--> HURLServer
 *             |--> HURLPath
 */

/* Root structure of hurl. */
typedef struct hurl_manager {
	float http_version; /* HTTP version to send in requests. */
	enum HTTPFeatureSupport feature_tls; /* Allow TLS connections. */
	enum HTTPFeatureSupport feature_pipelining; /* Use pipelining if possible. */
	enum HTTPFeatureSupport feature_persistence; /* Use persistent connections if possible. */
	int follow_redirect; /* Follow HTTP redirects. */
	unsigned int max_domain_connections; /* Maximum number of connections to a domain. */
	unsigned int max_connections; /* Maximum number of connections regardless of domain. */
	unsigned int max_pipeline; /* Maximum number of pipelined requests on a connection. */
	unsigned int keep_alive; /* Keep alive value in seconds. */
	int connect_timeout; /* Connect timeout in milliseconds. */
	int send_timeout; /* Send timeout in milliseconds. */
	int recv_timeout; /* Receive timeout in milliseconds. */
	HURLDomain *domains; /* Pointers to domain structure. */
	unsigned int nrof_domains; /* Number of domains. */
	unsigned int connections; /* Number of open connections. */
	unsigned int max_retries; /* Maximum number of dowmload retries. */
	unsigned int max_redirects; /* Maximum number of HTTP redirects to follow. */

	/* HOOK POINTS */
	/* DNS OVERRIDE HOOK
	*  Event: Resolve domain name
	*  Parameters:	-- Domain that needs name resolution.
									-- Path that triggered the event.
	*/
	void (*hook_resolve)(HURLDomain *, HURLPath *); /* Override DNS resolution. */

	/* PRE-CONNECT HOOK
	*  Event: HURL is about to connect to a server
	*  Parameters:	-- Path being downloaded which triggered the event.
									-- Parameters of the connection that will be established.
	*/
	int (*hook_pre_connect)(HURLPath *, HURLConnection *); /* Hook before calling connect() */

	/* POST-CONNECT HOOK
	*  Event: HURL has attempted to connect to a server.
	*  Parameters:	-- Path being downloaded which triggered the event.
									-- Parameters of the connection.
									-- Result of connect attempt. TODO: Check enum
	*/
	void (*hook_post_connect)(HURLPath *, HURLConnection *, int); /* Hook after calling connect() */

	/* CONNECTION CLOSED HOOK
	*  Event: HURL has closed a connection to a server.
	*  Parameters:	-- Path being downloaded which triggered the event.
									-- Parameters of the connection which was closed.
	*/
	void (*hook_connection_close)(HURLPath *, HURLConnection *); /* Hook before calling close() */

	/* REQUEST PRE-TRANSMISSION HOOK
	*  Event: HURL is about to send an HTTP request.
	*  Parameters:	-- The path that will we requested.
									-- The connection the request will be sent on.
									-- Will the request be pipelined?
	*/
	int (*hook_send_request)(HURLPath *, HURLConnection *, int); /* Hook before a request is sent. */

	/* RECEIVE RESPONSE HOOK
	*  Event: HURL has received raw response data.
	*  Parameters:	-- The path which the data belongs to.
									-- The connection the data was received on.
									-- Pointer to first byte of ENTIRE response.
									-- Number of bytes received.
	*/
	void (*hook_recv)(HURLPath *, HURLConnection *, char *, size_t); /* Hook immediately after data has been received. */

	/* HEADER RECEIVED AND PARSED HOOK
	*  Event: HURL has received and parsed the entire HTTP header of a response.
	*  Parameters:	-- The path which the response header belongs to.
									-- HTTP response code.
									-- Pointer to first item in linked list of headers.
									-- Header size in bytes.
	*/
	void (*hook_header_received)(HURLPath *, int, HURLHeader *, size_t);

	/* RECEIVE DECODED RESPONSE BODY
	*  Event: HURL has received body data.
	*  Parameters:	-- The path which the data belongs to.
									-- Pointer to received data chunk (NOT beginning of response).
									-- Size of received data chunk.
	*/
	void (*hook_body_recv)(HURLPath *, char *, size_t); /* Event: Body data received */

	/* HEADER RECEIVED HOOK
	*  Event: HURL has received the entire HTTP response header.
	*  Parameters:	-- The path which the data belongs to.
									-- Pointer to the beginning of the HTTP response header.
									-- Size of response header.
	*/
	void (*hook_header_recv)(HURLPath *, char *, size_t);

	/* HTTP REDIRECT HOOK
	*  Event: 	HURL has received a response that contains an HTTP redirection (3xx response code).
	*  Parameters:	-- The path which received the redirection.
									-- The HTTP response code.
									-- Absolute redirection URL.
	*/
	int (*hook_redirect)(HURLPath *, int, char *);

	/* HTTP RESPONSE TEXT AND CODE HOOK
	*  Event: 	HURL has received and parsed the first line of a HTTP response.
	*  Parameters:	-- The path the response belongs to.
									-- The connection the response was received on.
									-- The HTTP response code, e.g. 404
									-- The HTTP response text, e.g. "Not found"
	*/
	void (*hook_response_code)(HURLPath *, HURLConnection *, int, char *); /* Hook after HTTP response code has been found. */

	/* TRANSFER COMPLETED HOOK
	*  Event: 	HURL has finnished downloading a path.
	*  Parameters:	-- The path that has been processed.
									-- The connection the transfer used.
									-- The result of the transfer.
									-- The decoded content length
									-- Header size + chunked encoding overhead.
	*/
	void (*hook_transfer_complete)(HURLPath *, HURLConnection *, HURLTransferResult, size_t, size_t);

	/* REQUEST POST-TRANSMISSION HOOK
	*  Event: 	HURL has sent an HTTP request.
	*  Parameters:	-- The path for which the request was sent.
									-- The connection the request was sent on.
	*/
	void (*hook_request_sent)(HURLPath *, HURLConnection *); /* Hook after HTTP request has been sent. */

	/* HTTP RETAGGING HOOK
	*  Event: 	HURL is following an HTTP redirection.
							This hook allows manipulation of tag elements.
	*  Parameters:	-- The path created due to HTTP redirection.
									-- The path that was redirected.
									-- The absolute redirection URL.
	*/
	void *(*retag)(HURLPath *, HURLPath *, char *);

	/* FREE TAG HOOK
	*  Event: 	HURL is cleaning up memory.
	*  Parameters:	-- Pointer to the tag that should be free()'d.
	*/
	void (*free_tag)(void *tag); /* Frees tag structure */

	unsigned int recv_buffer_len; /* Size of TCP receive buffer. */
	pthread_mutex_t lock; /* Mutex for connections variable. */
	pthread_cond_t condition; /* Condition for accessing connections variable. */
	HURLHeader *headers; /* Linked list of headers to include in HTTP requests. */
	struct timeval bgof_exec; /* When did the download process begin? */
	float exec_time; /* When did the download process begin? */
#ifndef HURL_NO_SSL
	char *ca_path; /* Path to CA store for OpenSSL. */
	char *ca_file; /* Path to CA file for OpenSSL. */
#endif
} HURLManager;

/* Structure used to create pipelining queue. */
typedef struct hurl_pipeline_queue {
	HURLPath *path; /* Download target */
	HURLPipelineQueue *previous, *next; /* Linked list pointers */
} HURLPipelineQueue;

/* Initializes HURL manager with default values. */
HURLManager *hurl_manager_init();

/* Add download target to queue using absolute URL. */
HURLPath *hurl_add_url(HURLManager *manager, int allow_duplicate, char *url, void *tag);

/* Download queued targets */
int hurl_exec(HURLManager *manager);

/* Get domain structure. If the domain does not exist it will be created. */
HURLDomain *hurl_get_domain(HURLManager *manager, char *domain);

/* Get server structure. If the server does not exist it will be created. */
HURLServer *hurl_get_server(HURLDomain *domain, unsigned short port, int tls);

/* Free memory used by HURL manager structure and ALL associated structures. */
void hurl_manager_free(HURLManager *manager);

/* Count number of paths with a certain download state hosted on a certain domain. */
int hurl_domain_nrof_paths(HURLDomain *domain, enum HURLDownloadState state);

/* Count total number of paths in the HURL queue with a certain download state. */
int hurl_nrof_paths(HURLManager *manager, enum HURLDownloadState state);

/* Allocate memory and copy string to it. */
char *hurl_allocstrcpy(char *str, size_t str_len, unsigned int alloc_padding);

/* Write debug line containing calling thread, function, and a message. */
void hurl_debug(const char *func, const char *msg, ...);

/* Print status of HURL execution. */
void hurl_print_status(HURLManager *manager, FILE *fp);

/* Converts struct timeval into milliseconds. */
#ifndef timeval_to_msec
#define timeval_to_msec(t) (float)((t)->tv_sec * 1000 + (float) (t)->tv_usec / 1e3)
#endif

#endif /* HURL_CORE_H_ */
