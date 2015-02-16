#include <hurl/server.h>
#include <hurl/manager.h>
#ifndef INCLUDE_HURL_DOMAIN_H_
#define INCLUDE_HURL_DOMAIN_H_

typedef enum hurl_dns_state {
	DNS_STATE_UNRESOLVED = 0, /* Name resolution has not been attempted yet. */
	DNS_STATE_RESOLVED, /* Name resolution was successful. */
	DNS_STATE_ERROR /* Name resolution failed. */
} HURLDNSState;


#define HURL_URL_PARSE_OK 0
#define HURL_URL_PARSE_ERROR 1


typedef struct hurl_domain {
	HURLManager *manager; /* Reverse pointer to manager. */
	HURLDomain *previous, *next; /* Linked list pointers. */
	char *domain; /* Domain name of server. */
	struct sockaddr **addresses; /* IP addresses of domain name */
	unsigned int nrof_addresses; /* Number of IP addresses available. */
	unsigned int preferred_address; /* Index of preferred IP address. */
	HURLDNSState dns_state; /* Has the domain name been resolved? */
	HURLServer *servers; /* Linked list of servers. */
	unsigned short nrof_servers; /* Number of servers. */
	unsigned int max_connections; /* Overall connection limit */
	unsigned int nrof_connections; /* Number of connections. */
	unsigned int nrof_paths; /* Number of paths belonging to this domain. */
	pthread_mutex_t dns_lock; /* DNS resolution lock. */
	pthread_t thread;
	int thread_running; /* Is a thread running for this domain. */
	HURLPath *dns_trigger; /* The path that triggered DNS resolution. */
	struct timeval bgof_resolution; /* When did the resolution process begin? */
	float resolution_time; /* How long did the resolution process take? */
	void *tag; /* Pointer used to associate user data with domain. */
} HURLDomain;

void *hurl_domain_exec(void *domain_ptr); 
void hurl_domain_free(HURLManager *manager, HURLDomain *domain);

#endif /* INCLUDE_HURL_DOMAIN_H_ */
