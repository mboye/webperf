#include <stdlib.h>
#include "dns_core.h"
#include "hurl/hurl.h"
#include <openssl/md5.h>
#include <netinet/tcp.h>

#ifndef WEBPERF_H_
#define WEBPERF_H_

#define WEBPERF_TEST_VERSION 29
#define WEBPERF_TEST_NAME "webperf"

#define	HTTP_1_0  1.0
#define HTTP_1_1  1.1

#define WEBPERF_PRINT_URL_LENGTH 128
#define WEBPERF_MAX_CONNECTIONS 19
#define WEBPERF_MAX_DOMAIN_CONNECTIONS 6
#define WEBPERF_TIMEOUT 5000 /* 5 seconds */
#define WEBPERF_DNS_TIMEOUT 3000 /* 3 seconds */
#define WEBPERF_BUFFER_INCREMENT 4096
#define WEBPERF_MAX_ELEMENT_FILTERS 32
#define WEBPERF_DEFAULT_USER_AGENT "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.43 Safari/537.31"
#define WEBPERF_NO_CACHE_HEADER "Cache-Control: no-cache"
#define WEBPERF_HT_BINS 1
#define WEBPERF_DEFAULT_TIMEOUT 60*5 /* 5 minutes */

#define FORMAT_CSV 1
#define FORMAT_JSON 2

#define WEBPERF_MAX_DNS_ADDRESSES 16

#define OVECCOUNT 30
#define MAX_ELEMENTS 1000

enum test_result {
	WEBPERF_OK = 0,
	WEBPERF_ERROR = 1,
	WEBPERF_ARG_ERROR = 2,
	WEBPERF_PAGE_ERROR = 3,
	WEBPERF_ELEMENT_ERROR = 3,
	WEBPERF_MEM_ERROR = 4,
	WEBPERF_DNS_ERROR = 5,
	WEBPERF_NO_TARGETS = 6,
	WEBPERF_EXEC_TIMEOUT = 124
};
typedef enum test_result TestResult;
enum cdn_provider {
	CDN_NONE = 0, CDN_AKAMAI = 1, CDN_LEVEL3 = 2, CDN_LIMELIGHT = 3, CDN_TOTAL = 4, CDN_COUNT = 5
};
typedef enum cdn_provider CDNProvider;

typedef struct dns_stat DNSStat;
struct dns_stat {
	int return_code;
	float network_time;
	float exec_time;
	unsigned int data_tx, data_rx;
	unsigned int msg_tx, msg_rx;
	unsigned int queries;
	char *answer_a, *answer_aaaa;
	int answer_a_ttl, answer_aaaa_ttl;
	unsigned int nrof_answers_a, nrof_answers_aaaa;
	char *trace;
	struct timeval begin_resolve;
	char *qname, *qname_final;
};

typedef struct http_stat HTTPStat;
struct http_stat {
	float connect_time, connect_time_ssl;
	int connect_result;
	float download_time, ready_time;
	unsigned long download_size;
	unsigned long overhead;
	char *content_type;
	int return_code;
	int chunked_encoding;
	char *redirect_url;
	unsigned int date, expiry_date;
	unsigned int response_code;
	unsigned int header_size;
	int connection_reused;
	int pipelined;
	char *headers;
#ifdef __linux__
	struct tcp_info *tcp_stats;
#endif
	struct timeval begin_connect, request_sent;
	int tls;
	char *domain, *path;
	unsigned short port;
	float bgof_header, bgof_body;
	unsigned int header_len;
	HURLTransferResult result;
};

typedef struct element_stat ElementStat;
struct element_stat {
	/* New fields. */
	struct timeval begin_transfer, end_transfer;
	char *url;
	ElementStat *previous, *next; /* Linked list pointers. */
	int fp;
	char url_hash[41];
	int no_hostname;
	HURLPath *path;

	DNSStat *dns;
	HTTPStat *http;
	char *dns_trigger;
};

typedef struct webperf_test WebperfTest;
struct webperf_test {
	unsigned int nrof_elements;
	pthread_mutex_t lock;
	ElementStat *elements, *elements_tail;
	unsigned char nrof_root_servers;
	NetworkPreference nwp; /* Network preference; determines connect order or A/AAAA records. */
	DNSResolverState *dns_state_template;
	float http_version;
	char *user_agent;
	int no_cache;
	unsigned int timestamp; /* Timestamp of test run */
	int http_no_cache;
	HURLManager *manager;
	char *tag;
	DNSCache *cache;
	int print_url_length;
	DNSRecordType dns_query_type;
	char *body_path, *header_path;
	HURLHeader *stat_headers;
	int always_print_output;
	struct {
		struct {
			int connect_time, connect_time_ssl;
			int connect_result;
			int download_time, ready_time;
			int download_size;
			int overhead;
			int response_code;
			int cache_control;
			int chunked_encoding;
			int redirect_url;
			int date;
			int expiry_date;
			int header_size;
			int connection_reused;
			int pipelined;
			int all_headers;
			int tcp_stats;
			int begin_connect, request_sent;
			int save_body;
			int content_type;
			int tls;
			int domain, port, path;
			int redirector;
			int redirectee;
		} http;

		struct {
			int return_code;
			int network_time;
			int exec_time;
			int data_tx, data_rx;
			int msg_tx, msg_rx;
			int queries;
			int answer_a, answer_aaaa;
			int answer_a_ttl, answer_aaaa_ttl;
			int nrof_answers_a, nrof_answers_aaaa;
			int trace;
			int begin_resolve;
			int qname, qname_final;
		} dns;
		unsigned int output_format;
	} stats;

};

/* GLOBAL variable */
WebperfTest *test;

void str_trim(char *str);
#ifndef __cplusplus
int strncasecmp(const char *s1, const char *s2, size_t n);
char *strptime(const char *s, const char *format, struct tm *tm);
#endif

void print_stat(WebperfTest *test, ElementStat *stat);
void print_results(WebperfTest *test, int interrupted, char *filename);

void *duplicate_element_stat(HURLPath *new_path, HURLPath *redirector, char *destination_url);
void element_url_hash(ElementStat *element, HURLPath *path);
void stat_free(void *s);

/* JSON output functions */
char *dns_trace_json(DNSResolverState *state);
void dns_query_json(DNSQuery *query, Buffer *buf);
void dns_response_json(DNSMessage *response, Buffer *buf);
void dns_cache_json(DNSMessage *cache, Buffer *buf);

#endif /* WEBPERF_H_ */
