#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
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
#define HURL_TIMEOUT 5000 /* Default timeout in ms. */
#define HURL_CA_PATH "/etc/ssl/certs/"

typedef struct hurl_manager HURLManager;
typedef struct hurl_domain HURLDomain;
typedef struct hurl_server HURLServer;
typedef struct hurl_path HURLPath;
typedef struct hurl_connection HURLConnection;
typedef struct hurl_parsed_url HURLParsedURL;
typedef struct hurl_pipeline_queue HURLPipelineQueue;
typedef struct hurl_header HURLHeader;


enum HTTPFeatureSupport {
	SUPPORTED, UNSUPPORTED, UNKNOWN_SUPPORT
};

enum HURLConnectionState {
	CONNECTION_STATE_CLOSED = 0, CONNECTION_STATE_IN_PROGRESS = 1, CONNECTION_STATE_CONNECTED = 2, CONNECTION_STATE_ERROR = -1
};

enum HURLDownloadState {
	DOWNLOAD_STATE_PENDING = 1, DOWNLOAD_STATE_IN_PROGRESS = 2, DOWNLOAD_STATE_COMPLETED = 4, DOWNLOAD_STATE_ERROR = 8
};

enum HURLDNSState {
	DNS_STATE_UNRESOLVED = 0, DNS_STATE_RESOLVED, DNS_STATE_ERROR
};

enum HURLServerState {
	SERVER_STATE_OK = 0, SERVER_STATE_ERROR = -1, SERVER_STATE_SSL_ERROR = -2

};

enum HURLConnectResult {
	CONNECTION_ERROR = 0, CONNECTION_NEW = 1, CONNECTION_REUSED = 2
};


/* Hierarchical structure of hurl:
 * HURLManager
 *  |-->HURLDomain
 *       |--> HURLServer
 *             |--> HURLPath
 */

/* Structure representing a domain name. */
struct hurl_domain {
	HURLManager *manager; /* Reverse pointer to manager. */
	HURLDomain *previous, *next; /* Linked list pointers. */
	char *domain; /* Domain name of server. */
	struct sockaddr **addresses; /* IP addresses of domain name */
	unsigned int nrof_addresses; /* Number of IP addresses available. */
	unsigned int preferred_address; /* Index of preferred IP address. */
	enum HURLDNSState dns_state; /* Has the domain name been resolved? */
	HURLServer *servers; /* Linked list of servers. */
	unsigned short nrof_servers; /* Number of servers. */
	unsigned int max_connections;
	unsigned int nrof_connections; /* Number of connections. */
	unsigned int nrof_paths; /* Number of paths belonging to this domain. */
	pthread_mutex_t dns_lock; /* DNS resolution lock. */
	pthread_t thread;
	int thread_running; /* Is a thread running for this domain. */
	HURLPath *dns_trigger; /* The path that triggered DNS resolution. */
	struct timeval bgof_resolution; /* When did the resolution process begin? */
	float resolution_time; /* How long did the resolution process take? */
};

/* Structure representing a server. */
struct hurl_server {
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
};

/* Structure representing a path of a server. */
struct hurl_path {
	char *path; /* Path of file e.g. /index.html */
	HURLServer *server; /* Reverse pointer to domain structure. */
	enum HURLDownloadState state; /* Has the file been downloaded? */
	HURLPath *previous, *next; /* Linked list pointers. */
	unsigned int retries; /* Number of retries. */
	void *tag; /* Used to associate data with a path. */
	struct timeval request_sent; /* When was a GET request sent for this path. */
	struct timeval response_received; /* When was the response to the GET request received. */
};

/* Structure representing a TCP connection to a server. */
struct hurl_connection {
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
};

/* Structure representing a HTTP header. */
struct hurl_header {
	char *key, *value;
	HURLHeader *previous, *next;
};

/* Root structure of hurl. */
struct hurl_manager {
	float http_version;
	enum HTTPFeatureSupport feature_tls; /* Als download files using TLS. */
	enum HTTPFeatureSupport feature_pipelining; /* Use pipelining if possible. */
	enum HTTPFeatureSupport feature_persistence; /* Use pipelining if possible. */
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

	void (*hook_resolve)(HURLDomain *, HURLPath *); /* Override DNS resolution. */
	int (*hook_pre_connect)(HURLPath *, HURLConnection *); /* Hook before calling connect() */
	void (*hook_post_connect)(HURLPath *, HURLConnection *, int); /* Hook after calling connect() */
	void (*hook_connection_close)(HURLPath *, HURLConnection *); /* Hook before calling close() */
	int (*hook_send_request)(HURLPath *, HURLConnection *, int); /* Hook before a request is sent. */
	void (*hook_header_received)(HURLPath *, int, HURLHeader *, size_t);
	void (*hook_body_recv)(HURLPath *, char *, size_t);
	void (*hook_header_recv)(HURLPath *, char *, size_t); /* Hook after entire header has been received. */
	int (*hook_redirect)(HURLPath *, int, char *);
	void (*hook_response_code)(HURLPath *, HURLConnection *, int, char *); /* Hook after HTTP response code has been found. */
	void (*hook_transfer_complete)(HURLPath *, HURLConnection *, size_t, size_t); /* Hook at end of transfer when using pipelining */
	void (*hook_request_sent)(HURLPath *, HURLConnection *); /* Hook after HTTP request has been sent. */
	void *(*retag)(HURLPath *, char *); /* Create new tag for element in case of redirections. */
	void (*free_tag)(void *tag); /* Frees tag structure */
	unsigned int recv_buffer_len; /* Size of receive buffer. */
	pthread_mutex_t lock; /* Mutex for connections variable. */
	pthread_cond_t condition; /* Condition for connections variable. */
	HURLHeader *headers; /* Linked list of headers to include in HTTP requests. */
	struct timeval bgof_exec; /* When did the download process begin? */
	float exec_time; /* When did the download process begin? */
#ifndef HURL_NO_SSL
	char *ca_path; /* Path to CA store for OpenSSL. */
	char *ca_file; /* Path to CA file for OpenSSL. */
#endif
};

/* Structure representing a parsed URL. */
struct hurl_parsed_url {
	char *protocol; /* Protocol e.g. http, https */
	char *hostname; /* Host/domain name */
	unsigned short port; /* Server port. Default is port 80 for HTTP and 443 for HTTPS */
	char *path; /* Path e.g. /index.html */
};

/* Structure used to create pipelining queue. */
struct hurl_pipeline_queue {
	HURLPath *path;
	HURLPipelineQueue *previous, *next;
};
/* Initializes hurl with default values. */
HURLManager *hurl_manager_init();
HURLPath *hurl_add_url(HURLManager *manager, int allow_duplicate, char *url, void *tag);
int hurl_exec(HURLManager *manager);
int hurl_parse_url(char *url, HURLParsedURL **result);
void hurl_parsed_url_free(HURLParsedURL *url);
HURLDomain *hurl_get_domain(HURLManager *manager, char *domain);
HURLServer *hurl_get_server(HURLDomain *domain, unsigned short port, int tls);
int hurl_header_add(HURLHeader **headers, char *key, char *value);
char *hurl_header_get(HURLHeader *headers, char *key);
void hurl_headers_free(HURLHeader *headers);
int hurl_header_split_line(char *line, size_t line_len, char **key, char **value);
int hurl_header_exists(HURLHeader *headers, char *key);
void hurl_manager_free(HURLManager *manager);
void hurl_domain_free(HURLManager *manager, HURLDomain *domain);
void hurl_server_free(HURLManager *manager, HURLServer *server);
void hurl_path_free(HURLManager *manager, HURLPath *path);
void hurl_connection_free(HURLConnection *connection);
int hurl_domain_nrof_paths(HURLDomain *domain, enum HURLDownloadState state);
int hurl_nrof_paths(HURLManager *manager, enum HURLDownloadState state);
char *hurl_allocstrcpy(char *str, size_t str_len, unsigned int alloc_padding);
void hurl_debug(const char *func, const char *msg, ...);
void hurl_print_status(HURLManager *manager, FILE *fp);
void *hurl_domain_exec(void *domain_ptr);

/* Macro functions */
#ifndef timeval_to_msec
#define timeval_to_msec(t) (float)((t)->tv_sec * 1000 + (float) (t)->tv_usec / 1e3)
#endif

#endif /* HURL_CORE_H_ */
