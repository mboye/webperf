#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <openssl/ssl.h>

#ifndef INCLUDE_HURL__H_
#define INCLUDE_HURL__H_

/* Mac OS X - specific: MSG_NOSIGNAL not defined in OS X */
#if defined(__APPLE__) || defined(__MACH__)
# ifndef MSG_NOSIGNAL
#   define MSG_NOSIGNAL SO_NOSIGPIPE
# endif
#endif

#ifndef timeval_to_msec
#define timeval_to_msec(t) (double)((t)->tv_sec * 1e3 + (double) (t)->tv_usec / 1e3)
#endif

#define HURL_MAX_CONNECTIONS 16 /* Overall connection limit. */
#define HURL_MAX_DOMAIN_CONNECTIONS 6 /* Connection limit per domain name. */
#define HURL_MAX_PIPELINE_REQUESTS 3 /* Maximum number of consecutive HTTP requests to send. */
#define HURL_KEEP_ALIVE 60 /* 60 seconds */
#define HURL_MAX_RETRIES 0 /* Number of download retries. */
#define HURL_MAX_REDIRECTS 2 /* Number of HTTP redirects. */
#define HURL_TIMEOUT 5000 /* Default timeout in ms. */
#define HURL_CA_PATH "/etc/ssl/certs/"

#define HURL_URL_PARSE_OK 0
#define HURL_URL_PARSE_ERROR 1

/* typedefs */
typedef struct hurl_connection HURLConnection;
typedef struct hurl_path HURLPath;
typedef struct hurl_server HURLServer;
typedef struct hurl_domain HURLDomain;
typedef struct hurl_manager HURLManager;
typedef struct hurl_header HURLHeader;
typedef struct hurl_pipeline_queue HURLPipelineQueue;
typedef struct hurl_parsed_url HURLParsedURL;

/* enums */
enum hurl_url_parser_error_e
{
    HURL_URL_PARSER_ERROR_NONE,
    HURL_URL_PARSER_ERROR_MEMORY,
    HURL_URL_PARSER_ERROR_PROTOCOL_DELIM,
    HURL_URL_PARSER_ERROR_PROTOCOL,
    HURL_URL_PARSER_HOSTNAME,
    HURL_URL_PARSER_ERROR_PORT,
    HURL_URL_PARSER_HOSTNAME_LENGTH
};

enum hurl_http_feature_support
{
    SUPPORTED, UNSUPPORTED, UNKNOWN_SUPPORT
};

enum hurl_download_state
{
    /* File has not yet been processed. */
    DOWNLOAD_STATE_PENDING = 1,
    /* File is currently being processed. */
    DOWNLOAD_STATE_IN_PROGRESS = 2,
    /* File has been downloaded successfuly. */
    DOWNLOAD_STATE_COMPLETED = 4,
    /* File was processed and download failed. */
    DOWNLOAD_STATE_ERROR = 8
};

enum hurl_connect_result
{
    CONNECTION_ERROR = 0, /* The connection attempt failed. */
    CONNECTION_NEW = 1, /* A new connection was succcessfully established. */
    CONNECTION_REUSED = 2 /* An existing connection is being reused. */
};

enum hurl_transfer_result
{
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

enum hurl_connection_state
{
    CONNECTION_STATE_CLOSED = 0,
    CONNECTION_STATE_IN_PROGRESS = 1,
    CONNECTION_STATE_CONNECTED = 2,
    CONNECTION_STATE_ERROR = -1
};

enum hurl_dns_state
{
    DNS_STATE_UNRESOLVED = 0, /* Name resolution has not been attempted yet. */
    DNS_STATE_RESOLVED, /* Name resolution was successful. */
    DNS_STATE_ERROR /* Name resolution failed. */
};

enum hurl_server_state
{
    SERVER_STATE_OK = 0, /* The server is functional */
    SERVER_STATE_ERROR = -1, /* Something went wrong with the server. */
    SERVER_STATE_SSL_ERROR = -2 /* Failed to secure connection. */
};

enum hurl_hook_error_e
{
    HURL_HOOK_OK,
    HURL_HOOK_ERROR
};

/* typedefs for enums */
typedef enum hurl_url_parser_error_e hurl_url_parser_error_t;
typedef enum hurl_connection_state HURLConnectionState;
typedef enum hurl_dns_state HURLDNSState;
typedef enum hurl_connect_result HURLConnectResult;
typedef enum hurl_http_feature_support HTTPFeatureSupport;
typedef enum hurl_download_state HURLDownloadState;
typedef enum hurl_transfer_result HURLTransferResult;
typedef enum hurl_server_state HURLServerState;
typedef enum hurl_hook_error_e hurl_hook_error_t;

/* structs */
struct hurl_connection
{
    HURLServer *server; /* Reverse pointer to server. */
    int sock; /* Socket number of connection. */
    SSL *ssl_handle; /* SSL handle. */
    SSL_CTX *ssl_context; /* SSL context. */
    HURLConnectionState state; /* State of socket. */
    unsigned long data_tx, data_rx; /* TODO: Bytes sent and received. */
    unsigned int request_tx; /* TODO: Number of requests sent on connection. */
    HURLConnection *previous, *next; /* Linked list pointers. */
    pthread_t thread; /* Connection thread. */
    float connect_time, connect_time_ssl; /* Time to establish TCP+SSL connection and just SSL connection. */
    struct timeval begin_connect; /* Time when connect() was called. */
    int reused; /* Was the connection reused? */
};

struct hurl_path
{
    char *path; /* Path of file e.g. /index.html */
    HURLServer *server; /* Reverse pointer to domain structure. */
    HURLDownloadState state; /* Has the file been downloaded? */
    HURLPath *previous, *next; /* Linked list pointers. */
    unsigned int retries; /* Number of retries. */
    void *tag; /*  ointer used to associate user data with path (target). */
    struct timeval request_sent; /* When was a GET request sent for this path. */
    struct timeval response_received; /* When was the response to the GET request received. */
    unsigned int redirect_count; /* Number of redirects that have been followed. */
    HURLPath *redirector;
    HURLPath *redirectee;
};

struct hurl_server
{
    HURLDomain *domain; /* Reverse pointer to domain. */
    HURLServer *previous, *next; /* Linked list pointers. */
    unsigned short port; /* Server port number. */
    int tls; /* Connection should use TLS. */
    HURLPath *paths; /* Path of files on server. */
    unsigned int nrof_paths; /* Number of files to be downloaded from domain. */
    HURLConnection *connections; /* Connection structures. */
    unsigned int max_connections; /* Maximum number of connections to this server. */
    HURLServerState state; /* Server state. */
    unsigned int pipeline_errors; /* Number of times pipelined requests failed. */
    void *tag; /* Pointer used to associate user data with server. */
};

struct hurl_domain
{
    HURLManager *manager; /* Reverse pointer to manager. */
    HURLDomain *previous, *next; /* Linked list pointers. */
    char *domain; /* Domain name of server. */
    struct sockaddr **addresses; /* IP addresses of domain name */
    int nrof_addresses; /* Number of IP addresses available. */
    int preferred_address; /* Index of preferred IP address. */
    HURLDNSState dns_state; /* Has the domain name been resolved? */
    HURLServer *servers; /* Linked list of servers. */
    short nrof_servers; /* Number of servers. */
    int max_connections; /* Overall connection limit */
    int nrof_connections; /* Number of connections. */
    int nrof_paths; /* Number of paths belonging to this domain. */
    pthread_mutex_t dns_lock; /* DNS resolution lock. */
    pthread_t thread;
    int thread_running; /* Is a thread running for this domain. */
    HURLPath *dns_trigger; /* The path that triggered DNS resolution. */
    struct timeval bgof_resolution; /* When did the resolution process begin? */
    float resolution_time; /* How long did the resolution process take? */
    void *tag; /* Pointer used to associate user data with domain. */
};

struct hurl_manager
{
    float http_version; /* HTTP version to send in requests. */
    HTTPFeatureSupport feature_tls; /* Allow TLS connections. */
    HTTPFeatureSupport feature_pipelining; /* Use pipelining if possible. */
    HTTPFeatureSupport feature_persistence; /* Use persistent connections if possible. */
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
    unsigned int max_retries; /* Maximum number of download retries. */
    unsigned int max_redirects; /* Maximum number of HTTP redirects to follow. */

    /* HOOK POINTS */
    /* DNS OVERRIDE HOOK
     *  Event: Resolve domain name
     *  Parameters:    -- Domain that needs name resolution.
     -- Path that triggered the event.
     */
    void (*hook_resolve)(HURLDomain *,
                         HURLPath *); /* Override DNS resolution. */

    /* PRE-CONNECT HOOK
     *  Event: HURL is about to connect to a server
     *  Parameters:    -- Path being downloaded which triggered the event.
     -- Parameters of the connection that will be established.
     */
    hurl_hook_error_t (*hook_pre_connect)(HURLPath *,
                                          HURLConnection *); /* Hook before calling connect() */

    /* POST-CONNECT HOOK
     *  Event: HURL has attempted to connect to a server.
     *  Parameters:    -- Path being downloaded which triggered the event.
     -- Parameters of the connection.
     -- Result of connect attempt. TODO: Check enum
     */
    void (*hook_post_connect)(HURLPath *,
                              HURLConnection *,
                              int); /* Hook after calling connect() */

    /* CONNECTION CLOSED HOOK
     *  Event: HURL has closed a connection to a server.
     *  Parameters:    -- Path being downloaded which triggered the event.
     -- Parameters of the connection which was closed.
     */
    void (*hook_connection_close)(HURLPath *,
                                  HURLConnection *); /* Hook before calling close() */

    /* REQUEST PRE-TRANSMISSION HOOK
     *  Event: HURL is about to send an HTTP request.
     *  Parameters:    -- The path that will we requested.
     -- The connection the request will be sent on.
     -- Will the request be pipelined?
     */
    int (*hook_send_request)(HURLPath *,
                             HURLConnection *,
                             int); /* Hook before a request is sent. */

    /* RECEIVE RESPONSE HOOK
     *  Event: HURL has received raw response data.
     *  Parameters:    -- The path which the data belongs to.
     -- The connection the data was received on.
     -- Pointer to first byte of ENTIRE response.
     -- Number of bytes received.
     */
    void (*hook_recv)(HURLPath *,
                      HURLConnection *,
                      char *,
                      size_t); /* Hook immediately after data has been received. */

    /* HEADER RECEIVED AND PARSED HOOK
     *  Event: HURL has received and parsed the entire HTTP header of a response.
     *  Parameters:    -- The path which the response header belongs to.
     -- HTTP response code.
     -- Pointer to first item in linked list of headers.
     -- Header size in bytes.
     */
    void (*hook_header_received)(HURLPath *,
                                 int,
                                 HURLHeader *,
                                 size_t);

    /* RECEIVE DECODED RESPONSE BODY
     *  Event: HURL has received body data.
     *  Parameters:    -- The path which the data belongs to.
     -- Pointer to received data chunk (NOT beginning of response).
     -- Size of received data chunk.
     */
    void (*hook_body_recv)(HURLPath *,
                           char *,
                           size_t); /* Event: Body data received */

    /* HEADER RECEIVED HOOK
     *  Event: HURL has received the entire HTTP response header.
     *  Parameters:    -- The path which the data belongs to.
     -- Pointer to the beginning of the HTTP response header.
     -- Size of response header.
     */
    void (*hook_header_recv)(HURLPath *,
                             char *,
                             size_t);

    /* HTTP REDIRECT HOOK
     *  Event:     HURL has received a response that contains an HTTP redirection (3xx response code).
     *  Parameters:    -- The path which received the redirection.
     -- The HTTP response code.
     -- Absolute redirection URL.
     */
    int (*hook_redirect)(HURLPath *,
                         int,
                         char *);

    /* HTTP RESPONSE TEXT AND CODE HOOK
     *  Event:     HURL has received and parsed the first line of a HTTP response.
     *  Parameters:    -- The path the response belongs to.
     -- The connection the response was received on.
     -- The HTTP response code, e.g. 404
     -- The HTTP response text, e.g. "Not found"
     */
    void (*hook_response_code)(HURLPath *,
                               HURLConnection *,
                               int,
                               char *); /* Hook after HTTP response code has been found. */

    /* TRANSFER COMPLETED HOOK
     *  Event:     HURL has finnished downloading a path.
     *  Parameters:    -- The path that has been processed.
     -- The connection the transfer used.
     -- The result of the transfer.
     -- The decoded content length
     -- Header size + chunked encoding overhead.
     */
    void (*hook_transfer_complete)(HURLPath *,
                                   HURLConnection *,
                                   HURLTransferResult,
                                   size_t,
                                   size_t);

    /* REQUEST POST-TRANSMISSION HOOK
     *  Event:     HURL has sent an HTTP request.
     *  Parameters:    -- The path for which the request was sent.
     -- The connection the request was sent on.
     */
    void (*hook_request_sent)(HURLPath *,
                              HURLConnection *); /* Hook after HTTP request has been sent. */

    /* HTTP RETAGGING HOOK
     *  Event:     HURL is following an HTTP redirection.
     This hook allows manipulation of tag elements.
     *  Parameters:    -- The path created due to HTTP redirection.
     -- The path that was redirected.
     -- The absolute redirection URL.
     */
    void *(*retag)(HURLPath *,
                   char *);

    /* FREE TAG HOOK
     *  Event:     HURL is cleaning up memory.
     *  Parameters:    -- Pointer to the tag that should be free()'d.
     */
    void (*free_tag)(void *tag); /* Frees tag structure */

    unsigned int recv_buffer_len; /* Size of TCP receive buffer. */
    pthread_mutex_t lock; /* Mutex for connections variable. */
    pthread_cond_t condition; /* Condition for accessing connections variable. */
    HURLHeader *headers; /* Linked list of headers to include in HTTP requests. */
    struct timeval bgof_exec; /* When did the download process begin? */
    double exec_time; /* When did the download process begin? */
    char *ca_path; /* Path to CA store for OpenSSL. */
    char *ca_file; /* Path to CA file for OpenSSL. */
};

struct hurl_header
{
    char *key, *value; /* key-value pair */
    HURLHeader *previous, *next; /* Linked list pointers */
};

struct hurl_pipeline_queue
{
    HURLPath *path; /* Download target */
    HURLPipelineQueue *previous, *next; /* Linked list pointers */
};

struct hurl_parsed_url
{
    char *protocol; /* Protocol: http or https */
    char *hostname; /* Host/domain name */
    unsigned short port; /* Server port. Default is port 80 for HTTP and 443 for HTTPS */
    char *path; /* Path e.g. /index.html */
};

void hurl_connection_free(HURLConnection *connection);

void * hurl_connection_exec(void *connection_ptr);

int hurl_connect(HURLConnection *connection);

int hurl_connection_request(HURLConnection *connection,
                            HURLPath *path);

int hurl_connection_response(HURLConnection *connection,
                             HURLPath *path,
                             char **buffer,
                             size_t *buffer_len,
                             size_t *data_len,
                             HTTPFeatureSupport *feature_persistence);

void hurl_connection_close(HURLConnection *connection,
                           HURLConnectionState state);

void * hurl_domain_exec(void *domain_ptr);

void hurl_domain_free(HURLManager *manager,
                      HURLDomain *domain);

int hurl_header_add(HURLHeader **headers,
                    const char *key,
                    const char *value);

char * hurl_header_get(HURLHeader *headers,
                       const char *key);

void hurl_headers_free(HURLHeader *bgof_headers);

int hurl_header_split_line(const char *line,
                           size_t line_len,
                           char **key,
                           char **value);

int hurl_header_exists(HURLHeader *headers,
                       char *key);

HURLManager *hurl_manager_init();

/* Add download target to queue using absolute URL. */
HURLPath *hurl_add_url(HURLManager *manager,
                       int allow_duplicate,
                       char *url,
                       void *tag);

/* Download queued targets */
int hurl_exec(HURLManager *manager);

/* Get domain structure. If the domain does not exist it will be created. */
HURLDomain *hurl_get_domain(HURLManager *manager,
                            char *domain);

/* Get server structure. If the server does not exist it will be created. */
HURLServer *hurl_get_server(HURLDomain *domain,
                            unsigned short port,
                            int tls);
HURLPath *hurl_server_dequeue(HURLServer *server);

void hurl_resolve(HURLDomain *domain);

/* Free memory used by HURL manager structure and ALL associated structures. */
void hurl_manager_free(HURLManager *manager);

/* Count number of paths with a certain download state hosted on a certain domain. */
int hurl_domain_nrof_paths(HURLDomain *domain,
                           HURLDownloadState state);

/* Count total number of paths in the HURL queue with a certain download state. */
int hurl_nrof_paths(HURLManager *manager,
                    HURLDownloadState state);

hurl_url_parser_error_t hurl_parse_url(char *url,
                                       HURLParsedURL **result);

void hurl_parsed_url_free(HURLParsedURL *url);

void hurl_path_free(HURLManager *manager,
                    HURLPath *path);

void hurl_server_free(HURLManager *manager,
                      HURLServer *server);

int hurl_verify_ssl_scope(char *expected_domain,
                          char *actual_domain);

HURLHeader *hurl_headers_copy(HURLHeader *headers);

int hurl_header_str(HURLHeader *headers,
                    char *buffer,
                    size_t buffer_len);

ssize_t hurl_send(HURLConnection *connection,
                  char *buffer,
                  size_t buffer_len);

ssize_t hurl_recv(HURLConnection *connection,
                  char *buffer,
                  size_t buffer_len);

int hurl_parse_response_code(char *line,
                             char **code_text);

unsigned char split_domain_name(char *name,
                                char *labels[]);

double record_time_msec(struct timeval *begin);

#endif /* INCLUDE_HURL_H_ */
