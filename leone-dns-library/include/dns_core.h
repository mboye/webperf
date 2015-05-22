#ifndef DNS_CORE_H_
#define DNS_CORE_H_
#include <netinet/in.h>
#include <limits.h>
#include "leone_tools.h"
#include <pthread.h>

#define DNS_MAX_RESPONSES 64
#define LEONE_DNS_MAX_RECORD_TRAIL 128
#define LEONE_DNS_MAX_DOMAIN_TRAIL 32
#define DNS_MAX_ROOT_SERVERS 32
#define DNS_TIMEOUT_DEFAULT 5000
#define DNS_RETRIES_DEFAULT 2
#define DNS_RESOLV_CONF "/etc/resolv.conf"
#define DNS_MAX_LABELS 127
#define DNS_MAX_DOMAIN_LENGTH 253

#define DNS_MAX_SECTION_RECORDS 32
#define DNS_CACHE_NODE_NROF_CHILDREN 16

#define DNS_FLAG_TYPE_BIT 15
#define DNS_FLAG_AUTHORITATIVE_ANS_BIT 10
#define DNS_FLAG_TRUNCATION_BIT 9
#define DNS_FLAG_RECURSION_DESIRED_BIT 8
#define DNS_FLAG_RECURSION_AVAIL_BIT 7
#define DNS_FLAG_RESP_CODE_BIT 0x000F
#define DNS_MAX_SEND_COUNT 32

#define DNS_FLAG_READ USHRT_MAX

#define DNS_MAX_DOMAINS sizeof(long)*8

#ifndef timeval_to_msec
#define timeval_to_msec(t) (t)->tv_sec * 1000 + (float) (t)->tv_usec / 1e3
#endif

/* Used for specifying which order A/AAAA records are used in when connecting. */
enum network_preference {
	IPv4 = 1, IPv6 = 2, IPv46 = 4, IPv64 = 8, DEFAULT = 0
};
typedef enum network_preference NetworkPreference;

enum dns_response_code {
	DNS_ERROR_OK = 0, DNS_ERROR_FORMAT = 1, DNS_ERROR_SERVER = 2, DNS_ERROR_NXDOMAIN = 3, DNS_ERROR_NOT_IMPL = 4, DNS_ERROR_REFUSED = 5
};
typedef enum dns_response_code DNSResponseCode;

/* Actual bits in DNS header. */
enum dns_flags {
	DNS_FLAG_TYPE, DNS_FLAG_AUTHORITATIVE_ANS, DNS_FLAG_TRUNCATION, DNS_FLAG_RECURSION_DESIRED, DNS_FLAG_RECURSION_AVAIL, DNS_FLAG_RESP_CODE
};

/* DNS message type. */
enum dns_message_type {
	QUERY = 0, RESPONSE = 1
};

/* Sections in DNS message. */
enum dns_section {
	QUESTIONS = 1, ANSWERS = 2, AUTHORITIES = 4, ADDITIONALS = 8, ALL = 15, NOT_QUESTIONS = ALL - QUESTIONS
};
typedef enum dns_section DNSSection;

/* DNS record classes. Only Internet is supported. */
enum dns_class {
	IN = 1
};
typedef enum dns_class DNSRecordClass;

/* DNS record types. */
enum dns_record_type {
	ANY = 0, A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, HINFO = 13, MINFO = 14, MX = 15, TXT = 16, AAAA = 28, OPT = 41,
	/* Made up numbers after this point. */
	A_AAAA = 128, A_AAAA_CNAME = 129, A_CNAME = 130, AAAA_CNAME = 131
};
typedef enum dns_record_type DNSRecordType;

/* DNS record data structure. Used to specify queries and contain responses. */
typedef struct dns_record DNSRecord;
struct dns_record {
	unsigned int record_id; /* Unique ID of record in DNS cache. */
	DNSSection section; /* Section of DNS message the record is stored in. */
	char *name;
	DNSRecordClass class; /* renamed as 'class' is a reserved keyword in cpp */
	DNSRecordType type;
	unsigned int ttl;
	char *data;
	unsigned short data_len;
	unsigned int offset; /* Offset of record with respect to beginning of DNS message. */
	DNSRecord *question; /* The question this record is an answer to. */
	DNSRecord *answer; /* The A/AAAA record belonging to this question/CNAME. */
};

/* Structure used for DNS queries. (Must be declared before DNSMessage */
typedef struct dns_query DNSQuery;

/* Structure used for DNS messages and nodes in DNS cache tree. */
typedef struct dns_message DNSMessage;
struct dns_message {
	/* Tree properties. */
	char *label;
	unsigned int domain_id; /* Unique ID of domain in DNS cache. */
	DNSMessage *parent;
	DNSMessage **children;
	unsigned short nrof_children, max_children;
	/* DNS header */
	unsigned short id;
	enum dns_message_type type;
	unsigned char authoritative, truncation, recursion_desired, recursion_avail, response_code;
	/* DNS records. */
	DNSRecord *questions[DNS_MAX_SECTION_RECORDS], *answers[DNS_MAX_SECTION_RECORDS], *authorities[DNS_MAX_SECTION_RECORDS],
			*additionals[DNS_MAX_SECTION_RECORDS];
	unsigned short nrof_questions, nrof_answers, nrof_authorities, nrof_additionals;
	/* DNS performance information. */
	float rtt;
	unsigned int pksize;
	DNSQuery *query;
};

/* Structure used for DNS queries. */
struct dns_query {
	DNSMessage *response;
	int response_code;
	char *qname;
	char *authority;
	char *destination;
	unsigned short pksize;
};

/* Structure used for SOA records. */
typedef struct {
	char *domain, *mailbox;
	unsigned int serial, refresh, retry, expire, minimum_ttl;
} DNSRecordSOA;

struct dns_cache {
	DNSMessage *root; /* Root node of cache. */
	unsigned int domain_counter; /* Number of distinct domain names in cache. */
	unsigned int record_counter; /* Number of DNS records in cache. */
	pthread_mutex_t lock; /* DNS cache lock. */
};
typedef struct dns_cache DNSCache;

/* Structure used to maintain the state of the resolver. */
struct dns_resolver_state {
	DNSMessage *responses[DNS_MAX_RESPONSES]; /* Received responses. */
	DNSQuery *queries[2 * DNS_MAX_RESPONSES]; /* Sent queries. */
	unsigned short nrof_responses; /* Number of received responses. */
	unsigned short nrof_queries; /* Number of sent queries. */
	NetworkPreference nwp; /* Network preference. */
	unsigned int timeout[DNS_MAX_SEND_COUNT]; /* Receive timeout. */
	unsigned short recurse; /* Send queries with "Recursion desired" set. */
	DNSMessage recursive_authority;
	struct {
		float network_time;
		char *firstAnswer;
		unsigned int data_tx, data_rx;
		unsigned int packet_tx, packet_rx;
	} stats;
};
typedef struct dns_resolver_state DNSResolverState;

enum dns_return_code {
	DNS_OK = 0,
	DNS_RECORD_NOT_FOUND = 1,
	DNS_PROTOCOL_ERROR = 2,
	DNS_NETWORK_ERROR = 3,
	DNS_MAX_RESPONSES_EXCEEDED = 4,
	DNS_TIMEOUT = 5,
	DNS_NO_AUTHORITIES = 6,
	DNS_ERROR = 7,
	DNS_MEMORY = 8,
	DNS_LOOP = 9,
	DNS_REFUSED = 10
};

/* Structure used to create query queue. */
typedef struct dns_query_queue DNSQueryQueue;
struct dns_query_queue {
	char *qname;
	unsigned int record_trail[LEONE_DNS_MAX_RECORD_TRAIL];
	unsigned int trail_offset;
	DNSQueryQueue *prev, *next;
};

/* Main resolver function */
int dns_resolve(DNSCache *cache, DNSResolverState *state, char *qname, DNSRecordType qtype, char **final_qname);

/* Functions for handling DNSRecords. */
void dns_record_free(DNSRecord *record);

int dns_domain_similarity(char *domain_a, char *domain_b);
int dns_domain_labels_count(char *domain);
unsigned int dns_domain_id(DNSCache *cache, char *domain);

DNSResolverState *dns_state_init();
void dns_state_free_responses(DNSResolverState *state);
void dns_state_reset(DNSResolverState *state);
void dns_cache_free(DNSCache *cache);
void dns_cache_node_free(DNSMessage *node);

void skip_line(char *buf, unsigned int buf_len, int *pos);
int dns_resolver_ready(DNSResolverState *state);

/* Functions for presenting DNS information. */
unsigned int dns_count_rr(enum dns_record_type type, DNSSection section, DNSMessage *msg);
char *dns_record_rdata_str(DNSRecord *record);
struct timeval dns_sum_rtt(DNSResolverState *state);

/* Functions for handling DNSMessages. */
void dns_message_section(DNSMessage *msg, DNSSection section, DNSRecord ***bgof_section, unsigned short *nrof_records);

int dns_queue_find(DNSQueryQueue *queue, char *qname);

#endif /* DNS_CORE_H_ */
