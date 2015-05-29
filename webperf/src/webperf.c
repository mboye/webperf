#include "hooks.h"
#include "webperf.h"
#include "arpa/inet.h"
#include "dns_core.h"
#include "dns_support.h"
#include "dns_cache.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include "leone_tools.h"
#include <errno.h>
#include <signal.h>
#include "hurl/hurl.h"
#include <string.h>

#ifdef AUTO_STACKTRACE
#include <execinfo.h>
#endif

#include <openssl/sha.h>

char *cmd = NULL;

void test_free();
int print_usage(int retval);
int parse_int(char *value_str, int *result, int min);
int parse_uint(char *value_str, unsigned int *result, unsigned int min);
int load_urls(char *file);
void *timeout_killer(void *arg);

void signal_handler(int signum, siginfo_t *info, void *context) {
#ifdef AUTO_STACKTRACE
#ifndef NDEBUG
	void *array[10];
	size_t size;
	log_debug(__func__, "BEGIN STACKTRACE", signum);
	size = backtrace(array, 16);
	backtrace_symbols_fd(array, size, STDERR_FILENO);
	log_debug(__func__, "END STACKTRACE", signum);
#endif
#endif
	log_debug(__func__, "Signal: %d. Aborting...", signum);
	char *fn;
	/* Print statistics for all elements. */
	if (test != NULL && test->always_print_output) {
		print_results(test, -signum, fn );
	}
#ifdef AUTO_STACKTRACE
	abort();
#else
	exit(signum);
#endif
}

int main(int argc, char *argv[]) {
	int i = 1;
	int fp_input;
	char *inputbuf;
	struct stat stat_input;
	int retval;
	struct sigaction sig_abort;
	char *key, *value;
	char *line, *str, *line_copy;
	int line_len;
	int line_count = 0;
	char *line_split_ptr;
	char *header_key, *header_value;
	int j;
	char *timeout_split_ptr;
	char *timeouts_line, *s;
	unsigned int exec_timeout = 120;
	pthread_t exec_timeout_thread;
	int override_recurse = 0;

	cmd = argv[0];

	if ((test = calloc(1, sizeof(WebperfTest))) == NULL) {
		log_debug(__func__, "Out of memory.");
		exit(1);
	}

	pthread_mutex_init(&test->lock, NULL);

	if ((test->manager = hurl_manager_init()) == NULL) {
		log_debug(__func__, "Failed to initialize hURL.");
		exit(1);
	}
	test->print_url_length = WEBPERF_PRINT_URL_LENGTH;
	test->manager->connect_timeout = WEBPERF_TIMEOUT;
	test->manager->send_timeout = WEBPERF_TIMEOUT;
	test->manager->recv_timeout = WEBPERF_TIMEOUT;
	test->manager->max_connections = WEBPERF_MAX_CONNECTIONS;
	test->manager->max_domain_connections = WEBPERF_MAX_DOMAIN_CONNECTIONS;

	/* Setup hooks */
	test->manager->hook_resolve = dns_resolve_wrapper;
	test->manager->hook_request_sent = stat_request_sent;
	test->manager->hook_transfer_complete = stat_transfer_complete;
	test->manager->hook_header_received = stat_header_received;
	test->manager->hook_send_request = stat_send_request;
	test->manager->hook_pre_connect = stat_pre_connect;
	test->manager->hook_post_connect = stat_post_connect;
	test->manager->hook_response_code = stat_response_code;
	test->manager->hook_body_recv = stat_body_recv; /* Used to count file size and save files */
	test->manager->hook_redirect = stat_redirect;
	test->manager->hook_recv = stat_response_latency;

	/* ElementStat duplicator function */
	test->manager->retag = duplicate_element_stat;
	test->manager->free_tag = stat_free;

	test->dns_query_type = A;

	/* Initialize DNS cache. */
	test->cache = dns_cache_init();

	/* Initialize DNS resolver state template. */
	test->dns_state_template = dns_state_init();

	/* Attach signal handler. */
	bzero(&sig_abort, sizeof(struct sigaction));
	sig_abort.sa_sigaction = &signal_handler;
	sigaction(SIGINT, &sig_abort, NULL);
	sigaction(SIGHUP, &sig_abort, NULL);
	sigaction(SIGTERM, &sig_abort, NULL);
	sigaction(SIGQUIT, &sig_abort, NULL);
	sigaction(SIGSEGV, &sig_abort, NULL); /* Also catch segmentation faults */

	/* Set test timestamp. */
	test->timestamp = time(NULL);

	if (argc != 3) { //make sure the usage command
		print_usage(1);
		exit(1);
	} else if (strcmp(argv[1], "--version") == 0) {
		printf("%s-v%d\n", WEBPERF_TEST_NAME, WEBPERF_TEST_VERSION);
		exit(0);
	}

	/* Get file size. */
	if (stat(argv[i], &stat_input) != 0) {
		log_debug(__func__, "Failed to load configuration file '%s'\n", argv[i]);
		exit(1);
	}

	/* Allocate buffer for file. */
	inputbuf = malloc(sizeof(char) * stat_input.st_size);

	/* Open file. */
	if ((fp_input = open(argv[1], O_RDONLY)) == -1) {
		printf("Failed to load configuration file '%s'\n", argv[i + 1]);
		exit(WEBPERF_ARG_ERROR);
	}
	/* Read file into buffer. */
	if (read(fp_input, inputbuf, stat_input.st_size) != stat_input.st_size) {
		printf("Failed to load configuration file '%s' - %s\n", argv[i + 1], strerror(errno));
		free(inputbuf);
		exit(1);
	}

	str = inputbuf;
	line_count = 0;
	/* Split buffer by line breaks. */
	while ((line = strtok_r(str, "\n", &line_split_ptr)) != NULL) {
		str = NULL;
		line_count++;
		/* log_debug(__func__, "Line %d: '%s'", line_count, line); */

		/* Skip comments. */
		if (line[0] == '#') {
			continue;
		}

		/* Split line */
		line_copy = allocstrcpy(line, strlen(line), 1);
		line_len = strlen(line_copy);
		j = 0;
		key = NULL;
		value = NULL;
		for (j = 0; j < line_len; j++) {
			/* Find end of key. */
			if (line_copy[j] == '=') {
				line_copy[j] = '\0';
				key = line_copy;
				value = &line_copy[j + 1];
				break;
			}
		}

		if (key != NULL) {
			log_debug(__func__, "%s => %s", key, value);
			/* Parse key and process value. */
			if (strcasecmp(key, "dns.resolvconf") == 0) {
				if (dns_load_resolv_conf(test->cache, value) != DNS_OK) {
					break;
				} else {
					/* Set dns.recurse = 1 after parsing configuration file. */
					override_recurse = 1;
				}
			} else if (strcasecmp(key, "dns.timeout") == 0) {
				timeouts_line = strdup(value);
				s = timeouts_line;
				j = 0;
				while ((str = strtok_r(s, " ", &timeout_split_ptr)) != NULL) {
					s = NULL;
					if (!parse_uint(str, &test->dns_state_template->timeout[j], 1)) {
						break;
					}
					log_debug(__func__, "Timeout #%d is %u ms", j, test->dns_state_template->timeout[j]);
					j++;
				}
			} else if (strcasecmp(key, "dns.loadCache") == 0) {
				/* Load DNS cache from file */
				if (dns_cache_load(&test->cache, value) != DNS_OK) {
					log_debug(__func__, "Failed to load DNS cache.");
					break;
				}
			} else if (strcasecmp(key, "dns.recurse") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->dns_state_template->recurse = 1;
					log_debug(__func__, "Recursive queries enabled.");
				} else if (strcasecmp(value, "no") == 0) {
					test->dns_state_template->recurse = 0;
					log_debug(__func__, "Recursive queries disabled.");
				} else {
					break;
				}
			} else if (strcasecmp(key, "dns.networkPreference") == 0) {
				if (strcasecmp(value, "v4") == 0) {
					test->dns_state_template->nwp = IPv4;
				} else if (strcasecmp(value, "v6") == 0) {
					test->dns_state_template->nwp = IPv6;
				} else if (strcasecmp(value, "v4v6") == 0) {
					test->dns_state_template->nwp = IPv46;
				} else if (strcasecmp(value, "v6v4") == 0) {
					test->dns_state_template->nwp = IPv64;
				} else if (strcasecmp(value, "default") == 0) {
					test->dns_state_template->nwp = DEFAULT;
				} else {
					break;
				}
			} else if (strcasecmp(key, "dns.queryType") == 0) {
				if (strcasecmp(value, "v4") == 0) {
					test->dns_query_type = A;
				} else if (strcasecmp(value, "v6") == 0) {
					test->dns_query_type = AAAA;
				} else {
					break;
				}
			} else if (strcasecmp(key, "http.persistentConnections") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->manager->feature_persistence = SUPPORTED;
				} else if (strcasecmp(value, "no") == 0) {
					test->manager->feature_persistence = UNSUPPORTED;
				} else {
					break;
				}
			} else if (strcasecmp(key, "http.pipelining") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->manager->feature_pipelining = SUPPORTED;
				} else if (strcasecmp(value, "no") == 0) {
					test->manager->feature_pipelining = UNSUPPORTED;
				} else {
					break;
				}
			} else if (strcasecmp(key, "http.maxPipelining") == 0) {
				if (!parse_uint(value, &test->manager->max_pipeline, 1)) {
					break;
				}
			} else if (strcasecmp(key, "http.maxConnections") == 0) {
				if (!parse_uint(value, &test->manager->max_connections, 1)) {
					break;
				}
			} else if (strcasecmp(key, "http.maxDomainConnections") == 0) {
				if (!parse_uint(value, &test->manager->max_domain_connections, 1)) {
					break;
				}
			} else if (strcasecmp(key, "http.connectTimeout") == 0) {
				if (!parse_int(value, &test->manager->connect_timeout, 1)) {
					break;
				}
			} else if (strcasecmp(key, "http.sendTimeout") == 0) {
				if (!parse_int(value, &test->manager->send_timeout, 1)) {
					break;
				}
			} else if (strcasecmp(key, "http.recvTimeout") == 0) {
				if (!parse_int(value, &test->manager->recv_timeout, 1)) {
					break;
				}
			} else if (strcasecmp(key, "http.maxRetries") == 0) {
				if (!parse_uint(value, &test->manager->max_retries, 0)) {
					break;
				}
			} else if (strcasecmp(key, "http.header") == 0) {
				if (hurl_header_split_line(value, strlen(value), &header_key, &header_value)) {
					hurl_header_add(&test->manager->headers, header_key, header_value);
					free(header_key);
					free(header_value);
				} else {
					log_debug(__func__, "Failed to parse header '%s'", line_copy);
				}

			} else if (strcasecmp(key, "http.maxRedirects") == 0) {
				if (!parse_uint(value, &test->manager->max_redirects, 0)) {
					break;
				}
			} else if (strcasecmp(key, "test.loadURLs") == 0) {
				if (!load_urls(value)) {
					break;
				}

			} else if (strcasecmp(key, "stats.dns.queryName") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.qname = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.qname = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.finalQueryName") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.qname_final = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.qname_final = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.returnCode") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.return_code = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.return_code = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.networkTime") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.network_time = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.network_time = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.executionTime") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.exec_time = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.exec_time = 0;
				} else {
					break;
				}

			} else if (strcasecmp(key, "stats.dns.dataSent") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.data_tx = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.data_tx = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.dataReceived") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.data_rx = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.data_rx = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.messagesSent") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.msg_tx = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.msg_tx = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.messagesReceived") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.msg_rx = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.msg_rx = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.queries") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.queries = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.queries = 0;
				} else {
					break;
				}

			} else if (strcasecmp(key, "stats.dns.answerA") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.answer_a = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.answer_a = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.answerAAAA") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.answer_aaaa = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.answer_aaaa = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.answerATTL") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.answer_a_ttl = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.answer_a_ttl = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.answerAAAATTL") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.answer_aaaa_ttl = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.answer_aaaa_ttl = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.nrofAnswersA") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.nrof_answers_a = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.nrof_answers_a = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.nrofAnswersAAAA") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.nrof_answers_aaaa = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.nrof_answers_aaaa = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.trace") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.trace = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.trace = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.URLLength") == 0) {
				if (!parse_int(value, &test->print_url_length, -1)) {
					break;
				}
			} else if (strcasecmp(key, "stats.http.TLS") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.tls = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.tls = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.port") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.port = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.port = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.domain") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.domain = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.domain = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.path") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.path = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.path = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.responseCode") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.response_code = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.response_code = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.connectTime") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.connect_time = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.connect_time = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.connectTimeSSL") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.connect_time_ssl = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.connect_time_ssl = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.connectionReused") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.connection_reused = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.connection_reused = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.downloadTime") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.download_time = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.download_time = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.readyTime") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.ready_time = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.ready_time = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.header") == 0) {
				if (hurl_header_add(&test->stat_headers, value, "")) {
					log_debug(__func__, "Will record header '%s'", value);
				} else {
					log_debug(__func__, "Failed add header key to list: '%s'", line_copy);
					break;
				}
			} else if (strcasecmp(key, "stats.http.allHeaders") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.all_headers = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.all_headers = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.headerSize") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.header_size = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.header_size = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.downloadSize") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.download_size = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.download_size = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.overhead") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.overhead = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.overhead = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.contentType") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.content_type = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.content_type = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.chunkedEncoding") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.chunked_encoding = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.chunked_encoding = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.date") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.date = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.date = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.expiryDate") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.expiry_date = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.expiry_date = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.pipelined") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.pipelined = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.pipelined = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.TCPStats") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.tcp_stats = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.tcp_stats = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.beginConnect") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.begin_connect = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.begin_connect = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.redirectURL") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.redirect_url = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.redirect_url = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.redirector") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.redirector = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.redirector = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.redirectee") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.redirectee = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.redirectee = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.http.requestSent") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.http.request_sent = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.http.request_sent = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "stats.dns.beginResolve") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->stats.dns.begin_resolve = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->stats.dns.begin_resolve = 0;
				} else {
					break;
				}
			} else if (strcasecmp(key, "http.saveBody") == 0) {
				if (strlen(value) > 0) {
					if (test->body_path != NULL) {
						free(test->body_path);
					}
					test->body_path = allocstrcpy(value, strlen(value), 1);
					test->stats.http.save_body = 1;
					log_debug(__func__, "Will save downloaded files to '%s'", test->body_path);
				} else {
					break;
				}
			} else if (strcasecmp(key, "http.CAFile") == 0) {
				if (strlen(value) > 0) {
					if (test->manager->ca_file != NULL) {
						free(test->body_path);
					}
					test->manager->ca_file = allocstrcpy(value, strlen(value), 1);
					log_debug(__func__, "OpenSSL will load CAs from '%s'", test->manager->ca_file);
				} else {
					break;
				}
			} else if (strcasecmp(key, "test.tag") == 0) {
				if (strlen(value) > 0) {
					if (test->tag != NULL) {
						free(test->tag);
					}
					test->tag = allocstrcpy(value, strlen(value), 1);
					log_debug(__func__, "Test tag set: '%s'", test->tag);
				} else {
					break;
				}
			} else if (strcasecmp(key, "test.timestamp") == 0) {
				if (strcasecmp(value, "now") == 0) {
					test->timestamp = time(NULL);
				} else {
					test->timestamp = atof(value);
					if (test->timestamp <= 0) {
						break;
					}
				}
			} else if (strcasecmp(key, "test.timeout") == 0) {
				if (!parse_uint(value, &exec_timeout, 1)) {
					break;
				} else {
					log_debug(__func__, "Execution timeout set: %u seconds", exec_timeout);
				}
			} else if (strcasecmp(key, "test.outputFormat") == 0) {
				if (!parse_uint(value, &test->stats.output_format, 0)) {
					break;
				} else {
					if (test->stats.output_format & FORMAT_CSV) {
						log_debug(__func__, "CSV output format enabled.");
					}
					if (test->stats.output_format & FORMAT_JSON) {
						log_debug(__func__, "JSON output format enabled.");
					}
				}
			} else if (strcasecmp(key, "test.alwaysPrintOutput") == 0) {
				if (strcasecmp(value, "yes") == 0) {
					test->always_print_output = 1;
				} else if (strcasecmp(value, "no") == 0) {
					test->always_print_output = 0;
				} else {
					break;
				}
			} else {
				log_debug(__func__, "Unknown parameter '%s'", key);
				exit(1);
			}

		}
		free(line_copy);

	}
	free(inputbuf);
	i++;

	if (line != NULL) {
		/* An error occurred. */
		log_debug(__func__, "Parser error: '%s'", line);
		exit(1);
	}

	/* Fix tag */
	if (test->tag == NULL) {
		test->tag = calloc(1, sizeof(char));
	}

	/* Override DNS recurse setting if necessary. */
	if (override_recurse) {
		log_debug(__func__, "Overriding dns.recurse because dns.resolvconf parameter was specified.");
		test->dns_state_template->recurse = 1;
		log_debug(__func__, "Recursive queries enabled.");
	}

	/* Override output format if no format was specified. */
	if (test->stats.output_format == 0 || test->stats.output_format > FORMAT_CSV + FORMAT_JSON) {
		log_debug(__func__, "Overriding output format.");
		test->stats.output_format = FORMAT_JSON;
	}

	if (test->nrof_elements > 0) {
		/* Start execution timeout timer */
		bzero(&exec_timeout_thread, sizeof(pthread_t));
		pthread_create(&exec_timeout_thread, NULL, timeout_killer, &exec_timeout);

		/* Start download. */
		if ((retval = hurl_exec(test->manager)) == 1) {

			/* Print statistics for all elements. */
			print_results(test, 0, argv[2]);
			/* hurl_print_status(test->manager, stderr); */
			/* Free memory */
			dns_cache_free(test->cache);
			hurl_manager_free(test->manager);
			test_free();
			exit(0);
		} else {
			exit(retval);
		}
	} else {
		exit(print_usage(WEBPERF_NO_TARGETS));
	}
}

int print_usage(int retval) {
	printf("Usage:\t%s <test.conf> <output.json>\n", cmd);
	return retval;
}

int parse_int(char *value_str, int *result, int min) {
	long value = strtol(value_str, NULL, 10);
	if (value == LONG_MIN || value == LONG_MAX || value < min) {
		/* Value is out of range. */
		return 0;
	} else {
		*result = value;
		return 1;
	}
}
int parse_uint(char *value_str, unsigned int *result, unsigned int min) {
	unsigned long value = strtoul(value_str, NULL, 10);
	if (value == ULONG_MAX || value < min) {
		/* Value is out of range. */
		return 0;
	} else {
		*result = value;
		return 1;
	}
}

void str_trim(char *str) {
	unsigned int str_len;
	int i;
	str_len = strlen(str);
	/* Trim end of string. */
	for (i = str_len - 1; i >= 0; i--) {
		if ((*(str + i)) == '\n' || (*(str + i)) == ' ' || (*(str + i)) == '\n' || (*(str + i)) == '\r') {
			(*(str + i)) = '\0';
		} else {
			/* First non-spacing char detected. */
			break;
		}
	}

}

int load_urls(char *file) {
	char *inputbuf, *urlbuf;
	struct stat stat_input;
	int fp_input;
	int j;
	ElementStat *element, *prev_element = NULL;
	HURLPath *path_created;
	unsigned int bgof_line, eof_line, line_len;


	/* Get file size. */
	if (stat(file, &stat_input) != 0) {
		log_debug(__func__, "Failed to load URLs from '%s'", file);
		return 0;
	}

	/* Allocate buffer for file. */
	inputbuf = malloc(sizeof(char) * stat_input.st_size);

	/* Open file. */
	if ((fp_input = open(file, O_RDONLY)) == -1) {
		printf("Failed to load URLs from '%s'\n", file);
		return 0;
	}
	/* Read file into buffer. */
	if (read(fp_input, inputbuf, stat_input.st_size) != stat_input.st_size) {
		printf("Failed to load URLs from '%s' - %s\n", file, strerror(errno));
		return 0;
	}

	j = 0;
	while (j < stat_input.st_size) {
		bgof_line = j;
		/* Skip URLs that start with # or data: */
		if ((inputbuf + bgof_line)[0] == '#' || strncasecmp("data:", inputbuf + bgof_line, strlen("data:")) == 0) {
			/* Data URL detected. Skip this element. */
			while (inputbuf[j] != '\n' && j < stat_input.st_size) {
				j++;
			}
			j++;
			continue;
		}
		while (inputbuf[j] != '\n' && j < stat_input.st_size) {
			j++;
		}
		eof_line = j;
		line_len = eof_line - bgof_line + 1;
		/* Skip empty lines. */
		if (line_len > 1) {
			urlbuf = malloc(sizeof(char) * line_len);
			memcpy(urlbuf, inputbuf + bgof_line, line_len - 1);
			urlbuf[line_len - 1] = '\0';
			log_debug(__func__, "Loaded URL '%.32s' from file.", urlbuf);

			/* Initialize linked list */
			if (test->elements == NULL) {
				element = calloc(1, sizeof(ElementStat));
				test->elements = element;
				prev_element = element;
			} else {
				element = calloc(1, sizeof(ElementStat));
				element->previous = prev_element;
				prev_element->next = element;

			}

			/* Add URL to list of elements. */
			element->url = urlbuf;

			/* Add URL to hURL and attach ElementStat structure to it. */
			if (!(path_created = hurl_add_url(test->manager, 0, urlbuf, NULL))) {
				log_debug(__func__, "WARNING: Failed to add elements to download queue.");
				/* Remove element from linked list and free it */
				element->previous->next = NULL;
				stat_free(element);
			} else {
				/* Calculate SHA1 hash of URL */
				test->nrof_elements++;
				element_url_hash(element, path_created);

				/* Set tag */
				path_created->tag = element;
				element->path = path_created; /* Reverse pointer */
				element->http = calloc(1, sizeof(HTTPStat));
				element->http->tls = path_created->server->tls;
				element->http->domain = strdup(path_created->server->domain->domain);
				element->http->port = path_created->server->port;
				element->http->path = strdup(path_created->path);

				/* Update previous element pointer. */
				prev_element = element;
			}

		} else {
			log_debug(__func__, "WARNING: Skipping empty line.");
		}
		j++;
	}
	test->elements_tail = prev_element;
	return 1;
}

void test_free() {
	hurl_headers_free(test->stat_headers);
	/* TODO: Implement this */
}

void *timeout_killer(void *arg) {
	//how to pass argument for
	unsigned int sleep_time = *((unsigned int *) arg);
	char *fn = arg;
	log_debug(__func__, "Killer thread started. Waiting %u seconds before calling exit()", sleep_time);
	sleep(sleep_time);
	log_debug(__func__, "Execution timeout. Calling exit()");

	/* Print statistics for all elements. */
	if (test != NULL && test->always_print_output) {
		print_results(test, WEBPERF_EXEC_TIMEOUT, fn);
	}

	exit(WEBPERF_EXEC_TIMEOUT);
	return NULL;
}
