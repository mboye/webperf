#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <assert.h>
#include <alloca.h>
#include <math.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include "dns_core.h"
#include "leone_tools.h"
#include "webperf.h"
#include "dns_cache.h"
#include "dns_core.h"
#include <openssl/sha.h>
#include <float.h>
#include "hurl/hurl.h"
#include "sk_metrics.h"

char *json_escape(char *str);
char *cutoff(char *str, int maxlen);

/* This is main function for printing measurement results. */
void print_results(WebperfTest *test, int interrupted, char *filename) {
	ElementStat *stat;
	int is_first = 1;
	char hostname[512], timeout[1024];
	Buffer *dns_conf;
	char *user_agent, *tmp_ptr, *rdata, tmp[1024];
	int i, n;
	DNSMessage *msg;
	const char *nwp_str;
	char *jsonfn, *csvfn;

	/* Is JSON output format enabled? */
	if (test->stats.output_format & FORMAT_JSON) {
		switch (test->dns_state_template->nwp) {
		case IPv4:
			nwp_str = "v4";
			break;
		case IPv6:
			nwp_str = "v6";
			break;
		case IPv46:
			nwp_str = "v4v6";
			break;

		case IPv64:
			nwp_str = "v6v4";
			break;
		default:
		case DEFAULT:
			nwp_str = "default";
		}

		/* Get user-agent header. */
		tmp_ptr = hurl_header_get(test->manager->headers, "user-agent");
		user_agent = json_escape(tmp_ptr);

		/* Create DNS configuration string. */
		buffer_init(&dns_conf, 1024, 128);
		n = 0;
		for (i = 0;
				test->dns_state_template->timeout[i] > 0
						&& i < DNS_MAX_SEND_COUNT; i++) {
			n += snprintf(&timeout[n], sizeof(timeout) - n, "%u ",
					test->dns_state_template->timeout[i]);
		}
		timeout[n - 1] = '\0';
		snprintf(tmp, sizeof(tmp),
				"{\"timeout\":\"%s\",\"recurse\":%u,\"networkPreference\":\"%s\"",
				timeout, test->dns_state_template->recurse, nwp_str);
		buffer_insert_strlen(dns_conf, tmp);

		/* Add list of recursive servers */
		log_debug(__func__, "Adding list of recursive DNS servers.");
		if (test->dns_state_template->recurse
				&& dns_cache_find_rr(test->cache, "recursive-dns-server",
						A_AAAA, ANSWERS, &msg) != NULL) {
			buffer_insert_strlen(dns_conf, ",\"servers\":[");
			for (i = 0; i < msg->nrof_answers; i++) {
				rdata = dns_record_rdata_str(msg->answers[i]);
				if (is_first) {
					snprintf(tmp, sizeof(tmp), "\"%s\"", rdata);
					is_first = 0;
				} else {
					snprintf(tmp, sizeof(tmp), ",\"%s\"", rdata);
				}
				buffer_insert_strlen(dns_conf, tmp);
			}
			buffer_insert_strlen(dns_conf, "]");
		}
		/* TODO: Add list of root servers if in iterative mode. */
		buffer_insert_strlen(dns_conf, "}");

		is_first = 1;

		/* Get system hostname */
		bzero(hostname, sizeof(hostname));
		gethostname(hostname, sizeof(hostname));

		/* Begin results JSON  --- write to JSON file*/
		jsonfn = malloc(strlen(filename) + strlen(".json"));
		sprintf(jsonfn, "%s.json", filename);
		freopen(jsonfn, "w", stdout);

		printf(
				"{\"testName\":\"%s\",\"testVersion\":%d,\"timestamp\":%u,\"hostname\":\"%s\","
						"\"connectTimeout\":%d,\"sendTimeout\":%d,\"receiveTimeout\":%d,\"http_version\":%1.1f,"
						"\"maxConnections\":%d,\"maxDomainConnections\":%d,\"noCache\":%d,\"nwp\":%d,\"userAgent\":\"%s\","
						"\"startTime\":%f,\"execTime\":%f,\"interrupt\":%d,"
						"\"tag\":\"%s\",\"dns\":%s,\"elements\":[",
				WEBPERF_TEST_NAME, WEBPERF_TEST_VERSION, test->timestamp,
				hostname, test->manager->connect_timeout,
				test->manager->send_timeout, test->manager->recv_timeout,
				test->http_version, test->manager->max_connections,
				test->manager->max_domain_connections, test->no_cache,
				test->nwp, user_agent,
				timeval_to_msec(&test->manager->bgof_exec),
				test->manager->exec_time, interrupted, test->tag,
				dns_conf->head);
		buffer_free(dns_conf);
		free(user_agent);

		/* Print statistics for all elements. */
		stat = test->elements;
		while (stat != NULL) {
			if (!is_first) {
				printf(",");
			} else {
				is_first = 0;
			}
			print_stat(test, stat);
			stat = stat->next;
		}
		printf("]}\n"); /*End elements, end container */
		//fflush(stdout);
		fclose(stdout);
	}

	/* Check if output should use CSV format */
	if (test->stats.output_format & FORMAT_CSV) {
		/* */
		csvfn = malloc(strlen(filename) + strlen(".csv"));
		sprintf(csvfn, "%s.csv", filename);
		freopen(csvfn, "w", stdout);
		print_sk_metrics_csv(test, interrupted, STDOUT_FILENO);
		//fflush(stdout);
		fclose(stdout);
	}
}

void write_out(char *filename, const char *mode, FILE *fp) {
	freopen(filename, mode, fp);
	fclose(fp);

}

char *cutoff(char *str, int maxlen) {
	unsigned int len = strlen(str);
	if (maxlen > 0) {
		if (len > maxlen) {
			/* String is too long so cut it. */
			return allocstrcpy(str, maxlen, 1);
		} else {
			return allocstrcpy(str, len, 1);
		}
	} else {
		return calloc(1, sizeof(char));
	}

}

void print_stat(WebperfTest *test, ElementStat *stat) {
	Buffer *json;
	char tmp[4096], *tmp_ptr;
	unsigned int tmp_len;
	unsigned int begin_size;
	char *str = NULL;
	char *escaped;
	struct timeval diff;

	buffer_init(&json, 4096, 4096);
	buffer_insert_strlen(json, "{");

	/* URL of element. */
	if (test->print_url_length >= 0) {
		str = cutoff(stat->url, test->print_url_length);
		escaped = json_escape(str);
	} else {
		/* Do not shorten URL */
		escaped = json_escape(stat->url);
	}

	tmp_len = strlen(escaped) + strlen("\"url\":\"\",") + 1;
	if ((tmp_ptr = calloc(tmp_len, sizeof(char))) == NULL) {
		log_debug(__func__, "Out of memory.");
		return;
	}
	snprintf(tmp_ptr, tmp_len, "\"url\":\"%s\",", escaped);
	free(escaped);
	free(str);

	buffer_insert_strlen(json, tmp_ptr);
	free(tmp_ptr);

	/* Add MD5 hash of URL */
	snprintf(tmp, sizeof(tmp), "\"hash\":\"%s\"", stat->url_hash);
	buffer_insert_strlen(json, tmp);

	/* The DNS stats point may be NULL if URL contained an IP address, e.g. http://8.8.8.8/index.html */
	if (stat->dns_trigger != NULL || stat->dns != NULL) {
		/* DNS statistics */
		buffer_insert_strlen(json, ",\"dns\":{");
		begin_size = json->data_len;

		if (stat->dns != NULL) {
			/* This element did the actual DNS measurement. */
			if (test->stats.dns.qname) {
				snprintf(tmp, sizeof(tmp), "\"queryName\":\"%s\",",
						stat->dns->qname);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.qname_final) {
				snprintf(tmp, sizeof(tmp), "\"finalQueryName\":\"%s\",",
						stat->dns->qname_final);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.begin_resolve) {
				timersub(&stat->dns->begin_resolve, &test->manager->bgof_exec,
						&diff);
				snprintf(tmp, sizeof(tmp), "\"beginResolve\":%f,",
						timeval_to_msec(&diff));
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.return_code) {
				snprintf(tmp, sizeof(tmp), "\"returnCode\":%d,",
						stat->dns->return_code);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.network_time) {
				snprintf(tmp, sizeof(tmp), "\"networkTime\":%f,",
						stat->dns->network_time);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.exec_time) {
				snprintf(tmp, sizeof(tmp), "\"executionTime\":%f,",
						stat->dns->exec_time);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.queries) {
				snprintf(tmp, sizeof(tmp), "\"queries\":%u,",
						stat->dns->queries);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.msg_tx) {
				snprintf(tmp, sizeof(tmp), "\"messagesSent\":%u,",
						stat->dns->msg_tx);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.msg_rx) {
				snprintf(tmp, sizeof(tmp), "\"messagesReceived\":%u,",
						stat->dns->msg_rx);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.data_tx) {
				snprintf(tmp, sizeof(tmp), "\"dataSent\":%u,",
						stat->dns->data_tx);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.data_rx) {
				snprintf(tmp, sizeof(tmp), "\"dataReceived\":%u,",
						stat->dns->data_rx);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.answer_a) {
				snprintf(tmp, sizeof(tmp), "\"answerA\":\"%s\",",
						stat->dns->answer_a);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.answer_a_ttl) {
				snprintf(tmp, sizeof(tmp), "\"answerATTL\":%d,",
						stat->dns->answer_a_ttl);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.answer_aaaa) {
				snprintf(tmp, sizeof(tmp), "\"answerAAAA\":\"%s\",",
						stat->dns->answer_aaaa);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.answer_aaaa_ttl) {
				snprintf(tmp, sizeof(tmp), "\"answerAAAATTL\":%d,",
						stat->dns->answer_aaaa_ttl);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.nrof_answers_a) {
				snprintf(tmp, sizeof(tmp), "\"answersA\":%d,",
						stat->dns->nrof_answers_a);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.nrof_answers_aaaa) {
				snprintf(tmp, sizeof(tmp), "\"answersAAAA\":%d,",
						stat->dns->nrof_answers_aaaa);
				buffer_insert_strlen(json, tmp);
			}
			if (test->stats.dns.trace) {
				buffer_insert_strlen(json, "\"trace\":");
				if (stat->dns->trace != NULL) {
					buffer_insert_strlen(json, stat->dns->trace);
					buffer_insert_strlen(json, ",");
				} else {
					buffer_insert_strlen(json, "[],");
				}
			}
		} else {
			/* This elements used a DNS lookup result obtained by another element */
			snprintf(tmp, sizeof(tmp), "\"trigger\":\"%s\",",
					stat->dns_trigger);
			buffer_insert_strlen(json, tmp);
		}
		if (json->data_len - begin_size > 0) {
			buffer_rewind(json, 1);
		}
		buffer_insert_strlen(json, "}");
	} else {
		/* log_debug(__func__, "ERROR: No DNS element for %s (%s)", stat->url_hash, stat->url);*/
	}

	/* HTTP statistics */
	if (stat->http != NULL) {
		if (json->head[json->data_len] != ',') {
			buffer_insert_strlen(json, ",\"http\":{");
		} else {
			buffer_insert_strlen(json, "\"http\":{");
		}

		begin_size = json->data_len;
		/* Redirected URL of element. */
		if (test->stats.http.redirect_url != 0
				&& stat->http->redirect_url != NULL) {
			if (test->print_url_length >= 0) {
				str = cutoff(stat->http->redirect_url, test->print_url_length);
				escaped = json_escape(str);
			} else {
				/* Do not shorten URL */
				escaped = json_escape(stat->http->redirect_url);
			}

			tmp_len = strlen(escaped) + strlen("\"redirectURL\":\"\",") + 1;
			if ((tmp_ptr = calloc(tmp_len, sizeof(char))) == NULL) {
				log_debug(__func__, "Out of memory.");
				return;
			}
			snprintf(tmp_ptr, tmp_len, "\"redirectURL\":\"%s\",", escaped);
			free(escaped);
			free(str);

			buffer_insert_strlen(json, tmp_ptr);
			free(tmp_ptr);
		}

		if(test->stats.http.redirector && stat->path->redirector != NULL) {
			ElementStat *redirector_stat = (ElementStat *) stat->path->redirector->tag;
			snprintf(tmp, sizeof(tmp), "\"redirector\":\"%s\",", redirector_stat->url_hash);
			buffer_insert_strlen(json, tmp);
		}

		if(test->stats.http.redirectee && stat->path->redirectee != NULL) {
			ElementStat *redirectee_stat = (ElementStat *) stat->path->redirectee->tag;
			snprintf(tmp, sizeof(tmp), "\"redirectee\":\"%s\",", redirectee_stat->url_hash);
			buffer_insert_strlen(json, tmp);
		}

		/* TODO: Add field that tells whether the transfer actually succeeded.
		 * 		 Use the value specified in the TRANSFER COMPLETED HOOK
		 * 		 This modification is needed to identify transfers that returned "200 OK" but then failed during transfer.
		 */

		if (test->stats.http.response_code) {
			snprintf(tmp, sizeof(tmp), "\"responseCode\":%u,",
					stat->http->response_code);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.tls) {
			snprintf(tmp, sizeof(tmp), "\"TLS\":%u,", stat->http->tls);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.domain) {
			snprintf(tmp, sizeof(tmp), "\"domain\":\"%s\",",
					stat->http->domain);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.port) {
			snprintf(tmp, sizeof(tmp), "\"port\":%u,", stat->http->port);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.path) {
			str = cutoff(stat->http->path, test->print_url_length);
			escaped = json_escape(str);
			snprintf(tmp, sizeof(tmp), "\"path\":\"%s\",", escaped);
			buffer_insert_strlen(json, tmp);
			free(escaped);
			free(str);
		}
		if (test->stats.http.download_time) {
			snprintf(tmp, sizeof(tmp), "\"downloadTime\":%f,",
					stat->http->download_time);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.ready_time) {
			snprintf(tmp, sizeof(tmp), "\"readyTime\":%f,",
					stat->http->ready_time);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.begin_connect) {
			timersub(&stat->http->begin_connect, &test->manager->bgof_exec,
					&diff);
			if (timeval_to_msec(&diff) > 0) {
				snprintf(tmp, sizeof(tmp), "\"beginConnect\":%f,",
						timeval_to_msec(&diff));
			} else {
				snprintf(tmp, sizeof(tmp), "\"beginConnect\":-1,");
			}
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.request_sent) {
			if (stat->http->connect_result != 0) {
				timersub(&stat->http->request_sent, &test->manager->bgof_exec,
						&diff);
				log_debug(__func__, "URL %s", stat->url);
				assert(timeval_to_msec(&diff) > 0);
				snprintf(tmp, sizeof(tmp), "\"requestSent\":%f,",
						timeval_to_msec(&diff));
			} else {
				/* Set request sent time as -1 if connect failed. */
				snprintf(tmp, sizeof(tmp), "\"requestSent\":-1,");
			}
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.download_size) {
			snprintf(tmp, sizeof(tmp), "\"downloadSize\":%ld,",
					stat->http->download_size);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.chunked_encoding) {
			snprintf(tmp, sizeof(tmp), "\"chunkedEncoding\":%d,",
					stat->http->chunked_encoding);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.connect_time) {
			snprintf(tmp, sizeof(tmp), "\"connectTime\":%f,",
					stat->http->connect_time);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.connect_time_ssl) {
			snprintf(tmp, sizeof(tmp), "\"connectTimeSSL\":%f,",
					stat->http->connect_time_ssl);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.connection_reused) {
			snprintf(tmp, sizeof(tmp), "\"connectionReused\":%d,",
					stat->http->connection_reused);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.pipelined) {
			snprintf(tmp, sizeof(tmp), "\"pipelined\":%d,",
					stat->http->pipelined);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.content_type) {
			if (stat->http->content_type != NULL) {
				escaped = json_escape(stat->http->content_type);
				snprintf(tmp, sizeof(tmp), "\"contentType\":\"%s\",", escaped);
				free(escaped);
				buffer_insert_strlen(json, tmp);
			} else {
				buffer_insert_strlen(json, "\"contentType\": null,");
			}
		}
		if (test->stats.http.date) {
			snprintf(tmp, sizeof(tmp), "\"date\":%d,", stat->http->date);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.expiry_date) {
			snprintf(tmp, sizeof(tmp), "\"date\":%d,", stat->http->expiry_date);
			buffer_insert_strlen(json, tmp);
		}

		if (test->stats.http.overhead) {
			snprintf(tmp, sizeof(tmp), "\"overhead\":%lu,",
					stat->http->overhead);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.header_size) {
			snprintf(tmp, sizeof(tmp), "\"headerSize\":%d,",
					stat->http->header_size);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.header_size) {
			snprintf(tmp, sizeof(tmp), "\"responseCode\":%d,",
					stat->http->response_code);
			buffer_insert_strlen(json, tmp);
		}
		if (test->stats.http.all_headers || test->stat_headers != NULL) {
			if (stat->http->headers != NULL) {
				tmp_len = strlen("\"headers\":,") + strlen(stat->http->headers)
						+ 1;
				if ((tmp_ptr = malloc(sizeof(char) * tmp_len)) == NULL) {
					/* Out of memory */
					return;
				}
				snprintf(tmp_ptr, tmp_len, "\"headers\":%s,",
						stat->http->headers);
				buffer_insert_strlen(json, tmp_ptr);
				free(tmp_ptr);
			} else {
				buffer_insert_strlen(json, "\"headers\":{},");
			}
		}
#ifdef __linux__
		if (test->stats.http.tcp_stats) {
			if (stat->http->tcp_stats != NULL) {
				snprintf(tmp, sizeof(tmp),
						"\"tcp\":{\"totalRTX\":%d,\"reordering\":%d,\"lost\":%d,\"RTT\":%d,\"RTTVar\":%d,\"pathMTU\":%d},",
						stat->http->tcp_stats->tcpi_total_retrans,
						stat->http->tcp_stats->tcpi_reordering,
						stat->http->tcp_stats->tcpi_lost,
						stat->http->tcp_stats->tcpi_rtt,
						stat->http->tcp_stats->tcpi_rttvar,
						stat->http->tcp_stats->tcpi_pmtu);
				buffer_insert_strlen(json, tmp);
			} else {
				buffer_insert_strlen(json, "\"tcp\":{},");
			}
		}
#endif

		if (json->data_len - begin_size > 0) {
			buffer_rewind(json, 1);
		}

		/* End HTTP statistics */
		buffer_insert_strlen(json, "}");
	}

	/* End of web metric. */
	buffer_insert_strlen(json, "}");

	printf("%s", json->head);
	buffer_free(json);
}

char *json_escape(char *str) {
	Buffer *buf;
	char *result;
	int i;

	if (str == NULL) {
		/* Return empty string */
		return calloc(1, sizeof(char));
	}

	buffer_init(&buf, strlen(str), 64);
	for (i = 0; i < strlen(str); i++) {
		switch (str[i]) {
		case '"':
			buffer_insert_strlen(buf, "\\\"");
			break;
		default:
			buffer_insert(buf, str + i, 1);
		}
	}

	buffer_trim(buf);
	result = buf->head;
	free(buf);
	return result;
}

void *duplicate_element_stat(HURLPath *new_path, HURLPath *redirector,
		char *destination_url) {
	hurl_url_parser_error_t parser_rc;
	HURLParsedURL *parsed_url;
	ElementStat *stat = calloc(1, sizeof(ElementStat));
	stat->url = strdup(destination_url);
	element_url_hash(stat, new_path);

	if ((parser_rc = hurl_parse_url(destination_url, &parsed_url)) == HURL_URL_PARSER_ERROR_NONE) {
		if (test->stats.http.tls || test->stats.http.domain || test->stats.http.port || test->stats.http.path) {
			stat->http = calloc(1, sizeof(HTTPStat));
			stat->http->tls =
					strcasecmp(parsed_url->protocol, "https") == 0 ? 1 : 0;
			stat->http->domain = strdup(parsed_url->hostname);
			stat->http->port = parsed_url->port;
			stat->http->path = strdup(parsed_url->path);
		}
		hurl_parsed_url_free(parsed_url);
	} else {
		log_debug(__func__, "URL parser returned: %d", parser_rc);
		log_debug(__func__, "Failed to parse redirect URL.");
	}

	/* Link with path */
	stat->path = new_path;

	log_debug(__func__, "Retagging '%s'", destination_url);

	/* Add to linked list. */
	pthread_mutex_lock(&test->lock);
	stat->previous = test->elements_tail;
	test->elements_tail->next = stat;
	test->elements_tail = stat;
	pthread_mutex_unlock(&test->lock);
	return stat;
}

/* Calculate MD5 hash of URL of element */
void element_url_hash(ElementStat *element, HURLPath *path) {
	int h;
	SHA_CTX sha_context;
	HURLPath *redirector;
	ElementStat *redirector_stat;
	unsigned char hash[SHA_DIGEST_LENGTH];
	pthread_mutex_lock(&test->lock);
	test->nrof_elements++;
	pthread_mutex_unlock(&test->lock);
	SHA1_Init(&sha_context);

	redirector = path->redirector;
	while (redirector != NULL) {
		redirector_stat = (ElementStat *)redirector->tag;
		SHA1_Update(&sha_context, redirector_stat->url_hash, sizeof(redirector_stat->url_hash));
		redirector = redirector->redirector;
	}

	SHA1_Update(&sha_context, element->url, strlen(element->url));

	if(path->redirector == NULL) {
		SHA1_Update(&sha_context, &test->nrof_elements, sizeof(unsigned int));
	}

	if (SHA1_Final(hash, &sha_context)) {
		/* Convert to hexadecimal */
		for (h = 0; h < SHA_DIGEST_LENGTH; h++) {
			snprintf(&element->url_hash[h * 2], 3, "%02x", hash[h]);
		}
		log_debug(__func__, "URL hash is '%s'", element->url_hash);
	}
}

void stat_free(void *s) {
	ElementStat *stat = (ElementStat *) s;
	free(stat->dns_trigger);
	free(stat->url);
	/* Free DNS statistics */
	if (stat->dns) {
		free(stat->dns->answer_a);
		free(stat->dns->answer_aaaa);
		free(stat->dns->trace);
		free(stat->dns);
	}
	/* Free HTTP statistics */
	if (stat->http) {
		free(stat->http->content_type);
		free(stat->http->headers);
		free(stat->http->redirect_url);
#ifdef __linux__
		free(stat->http->tcp_stats);
#endif
		free(stat->http);
	}
}
