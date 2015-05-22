#include <float.h>
#include <limits.h>
#include <assert.h>
#include <stdio.h>
#include <dns_core.h>
#include <dns_cache.h>
#include "webperf.h"
#include "sk_metrics.h"

/* char *strcasestr(const char *haystack, const char *needle); */

float median_float(float *values, unsigned int n) {
	int i, j;
	float *sorted = malloc(sizeof(float) * n);
	float tmp;

	if (n == 0) {
		return -1;
	}
	memcpy(sorted, values, sizeof(float) * n);
	for (i = 0; i < n; i++) {
		for (j = 0; j < n - 1; j++) {
			if (sorted[j] > sorted[j + 1]) {
				/* Swap values */
				tmp = sorted[j];
				sorted[j] = sorted[j + 1];
				sorted[j + 1] = tmp;
			}
		}
	}

	if (n % 2 == 0) {
		return (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0f;
	} else {
		return sorted[n / 2];
	}
}

float median_int(int *values, unsigned int n) {
	int i, j;
	int *sorted = malloc(sizeof(int) * n);
	int tmp;

	if (n == 0) {
		return -1;
	}
	memcpy(sorted, values, sizeof(int) * n);
	for (i = 0; i < n; i++) {
		for (j = 0; j < n - 1; j++) {
			if (sorted[j] > sorted[j + 1]) {
				/* Swap values */
				tmp = sorted[j];
				sorted[j] = sorted[j + 1];
				sorted[j + 1] = tmp;
			}
		}
	}

	if (n % 2 == 0) {
		return (float) (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0f;
	} else {
		return (float) sorted[n / 2];
	}
}

void print_sk_metrics_csv(WebperfTest *test, int interrupted, int fd_out) {
	Buffer *csvbuf, *csvheader;
	ElementStat *e;
	char **dns_ok_hashes = calloc(test->nrof_elements, sizeof(char *));
	int i = 0;
	int test_status = 0;
	char *first_server = "";
	DNSRecord *dns_server = NULL;
	CDNProvider cdn;
	int dns_ok_hashes_n = 0;

	buffer_init(&csvbuf, 1024, 128);
	buffer_init(&csvheader, 1024, 128);

	/* Find DNS server address. */
	assert(test->dns_state_template != NULL);
	if (test->dns_state_template->recurse) {
		if ((dns_server = dns_cache_find_rr(test->cache, "recursive-dns-server", test->dns_query_type, ANSWERS, NULL)) != NULL) {
			first_server = dns_record_rdata_str(dns_server);
		}
	} else if (test->cache != NULL) {
		DNSMessage *root = test->cache->root;
		if (root != NULL) {
			for (i = 0; i < root->nrof_authorities; i++) {
				dns_server = dns_cache_find_rr(test->cache, root->authorities[i]->data, test->dns_query_type, ANSWERS, NULL);
				if (dns_server != NULL) {
					/* Format IP address */
					first_server = dns_record_rdata_str(dns_server);
					break;
				}
			}
		}
	}

	/* Create list of elements where DNS resolution was sucessful. */
	for (e = test->elements; e != NULL; e = e->next) {
		if (e->dns != NULL && e->dns->return_code == DNS_OK) {
			/* Add elements hash to list of success DNS lookups */
			dns_ok_hashes[dns_ok_hashes_n++] = e->url_hash;
		}
	}

	/* <TEST STATUS> */
	/* Check if the first element was downloaded. */
	if (test->elements->dns != NULL) {
		if (test->elements->dns->return_code == 0) {
			test_status++;
		}
	} else if (test->elements->dns_trigger != NULL) {
		for (i = 0; i < dns_ok_hashes_n && dns_ok_hashes[i] != NULL; i++) {
			if (strcmp(dns_ok_hashes[i], e->dns_trigger) == 0) {
				test_status++;
				break;
			}
		}
	}
	if (test_status) {
		/* DNS OK */
		if (test->elements->http != NULL && test->elements->http->download_time == 0) {
			/* DNS OK but HTTP failed. */
			test_status = 0;
		}
	}

	for (cdn = CDN_NONE; cdn < CDN_COUNT; cdn++) {
		unsigned int http_n = 0, https_n = 0;
		unsigned int dns_ok_n = 0, dns_error_n = 0;
		float avg_dns_ok_time = -1, avg_dns_error_time = -1;
		float *lst_dns_ok_time = calloc(test->nrof_elements, sizeof(float));
		float *lst_dns_error_time = calloc(test->nrof_elements, sizeof(float));
		float avg_dns_ok_iterations = -1, avg_dns_error_iterations = -1;
		int *lst_dns_ok_iterations = calloc(test->nrof_elements, sizeof(float));
		int *lst_dns_error_iterations = calloc(test->nrof_elements, sizeof(float));
		unsigned int http_no_ip_n = 0;
		int http_ok_n = 0, http_error_n = 0, http_ok_ssl_n = 0, http_ok_connect_n = 0, http_ok_connect_ssl_n = 0;
		float avg_http_ok_connect_time = -1, avg_http_ok_ssl_connect_time = -1;
		float *lst_http_ok_connect_time = calloc(test->nrof_elements, sizeof(float));
		float *lst_http_ok_ssl_connect_time = calloc(test->nrof_elements, sizeof(float));
		float avg_http_ok_download_time = -1;
		float *lst_http_ok_download_time = calloc(test->nrof_elements, sizeof(float));
		float avg_http_ok_download_size = -1;
		float *lst_http_ok_download_size = calloc(test->nrof_elements, sizeof(float));
		float avg_https_ok_download_time = -1;
		float *lst_https_ok_download_time = calloc(test->nrof_elements, sizeof(float));
		float avg_https_ok_download_size = -1;
		float *lst_https_ok_download_size = calloc(test->nrof_elements, sizeof(float));
		float avg_ttfb_header = -1;
		float *lst_ttfb_header = calloc(test->nrof_elements, sizeof(float));
		float avg_ttfb_body = -1;
		float *lst_ttfb_body = calloc(test->nrof_elements, sizeof(float));
		unsigned int http_redirects = 0;
		int dns_success = 0;
		CDNProvider element_cdn;
		if(cdn == CDN_TOTAL) {
			log_debug(__func__, "Ignoring CDN class (TOTAL)");
		}
		for (e = test->elements; e != NULL; e = e->next) {
			/* If the test was aborted ignore unprocessed downloads. */
			if (interrupted && e->http != NULL && e->http->result == HURL_XFER_NONE) {
				continue;
			}

			/* Filter by CDN */
			if(e->path->server->domain->tag != NULL) {
				log_debug(__func__, "CDN is NOT NULL");
			}
			element_cdn = e->path->server->domain->tag != NULL ? *((CDNProvider *)e->path->server->domain->tag) : CDN_NONE;
			assert(element_cdn != CDN_TOTAL);
			assert(element_cdn != CDN_COUNT);
			if (cdn != CDN_TOTAL && element_cdn != cdn) {
				/* Element was not classified as the current CDN */
				continue;
			}

			/* If this element triggered DNS resolution. */
			if (e->dns != NULL) {
				assert(e->dns_trigger == NULL);
				if (e->dns->return_code == DNS_OK) {
					log_debug(__func__, "This element triggered DNS resolution and it went OKAY.");
					/* <AVG LOOKUP TIME FOR SUCCESSFUL LOOKUPS> */
					avg_dns_ok_time = (avg_dns_ok_time * dns_ok_n + e->dns->exec_time) / (dns_ok_n + 1);
					lst_dns_ok_time[dns_ok_n] = e->dns->exec_time;

					/* <AVG ITERATIONS FOR SUCCESSFUL LOOKUPS> */
					avg_dns_ok_iterations = (avg_dns_ok_iterations * dns_ok_n + e->dns->msg_tx) / (dns_ok_n + 1);
					lst_dns_ok_iterations[dns_ok_n] = e->dns->msg_tx;

					/* TODO: <AVG CNAME FOLLOWED FOR SUCCESSFUL LOOKUPS> */

					/* <DNS LOOKUPS OK> */
					dns_ok_n++;
					dns_success = 1;

				} else {
					log_debug(__func__, "This element triggered DNS resolution and it did NOT go okay.");

					/* <AVG LOOKUP TIME FOR FAILED LOOKUPS> */
					avg_dns_error_time = (avg_dns_error_time * dns_error_n + e->dns->network_time) / (dns_error_n + 1);
					lst_dns_error_time[dns_error_n] = e->dns->network_time;

					/* <AVG ITERATIONS FOR FAILED LOOKUPS> */
					avg_dns_error_iterations = (avg_dns_error_iterations * dns_error_n + e->dns->msg_tx) / (dns_error_n + 1);
					lst_dns_error_iterations[dns_error_n] = e->dns->msg_tx;

					/* TODO: <AVG CNAME FOLLOWED FOR FAILED LOOKUPS> */

					/* <DNS LOOKUPS ERROR> */
					dns_error_n++;
				}
			} else if (e->dns_trigger != NULL) {
				/* Check list of hashes of elements where DNS lookup was successful. */
				log_debug(__func__, "This elements did not trigger DNS resolution, so let's find the element that did.");
				for (i = 0; i < dns_ok_n && dns_ok_hashes[i] != NULL; i++) {
					if (strcmp(dns_ok_hashes[i], e->dns_trigger) == 0) {
						dns_success = 1;
						break;
					}
				}
				log_debug(__func__, "Found it? %s", dns_success ? "yes" : "no");
			}

			if (!dns_success) {
				/* Don't calculate HTTP metrics if DNS resolution failed. */
				log_debug(__func__, "DNS resolution failed for this element, so HTTP download was never attempted.");
				/* HTTP_NO_IP */
				http_no_ip_n++;
				continue;
			}

			if (e->http != NULL) {
				/* <NUMBER OF HTTPS ELEMENTS> */
				/* <NUMBER OF HTTP ELEMENTS> */
				e->http->tls ? https_n++ : http_n++;

				if (e->http->download_time > 0) {
					/* <NUMBER OF HTTP REDIRECTS> */
					if (e->http->redirect_url != NULL) {
						http_redirects++;
					}

					/* <AVG CONNECT TIME OF COMPLETED DOWNLOADS> */
					if(e->http->connect_time  > 0) {
					avg_http_ok_connect_time = (avg_http_ok_connect_time * http_ok_connect_n + e->http->connect_time) / (http_ok_connect_n + 1);
					lst_http_ok_connect_time[http_ok_connect_n] = e->http->connect_time;
					}

					/* <AVG SSL CONNECT TIME, DL TIME, DL SIZE OF COMPLETED DOWNLOADS> */
					if (e->http->tls) {
						/* Connect time */
						if(e->http->connect_time > 0) {
							avg_http_ok_ssl_connect_time = (avg_http_ok_ssl_connect_time * http_ok_connect_ssl_n + e->http->connect_time_ssl) / (http_ok_connect_ssl_n + 1);
							lst_http_ok_ssl_connect_time[http_ok_connect_ssl_n] = e->http->connect_time_ssl;
						}

						/* Download time */
						avg_https_ok_download_time = (avg_https_ok_download_time * http_ok_ssl_n + e->http->download_time) / (http_ok_ssl_n + 1);
						lst_http_ok_download_time[http_ok_ssl_n] = e->http->download_time;

						/* Download size */
						avg_https_ok_download_size = (avg_https_ok_download_size * http_ok_ssl_n + e->http->download_size) / (http_ok_ssl_n + 1);
						lst_http_ok_download_size[http_ok_ssl_n] = e->http->download_size;

						http_ok_ssl_n++;
					} else {
						/* <AVG TRANSFER TIME OF COMPLETED DOWNLOADS>  */
						avg_http_ok_download_time = (avg_http_ok_download_time * http_ok_n + e->http->download_time) / (http_ok_n + 1);
						lst_http_ok_download_time[http_ok_n] = e->http->download_time;

						/* <AVG FILE SIZE OF COMPLETED DOWNLOADS>  */
						avg_http_ok_download_size = (avg_http_ok_download_size * http_ok_n + e->http->download_size) / (http_ok_n + 1);
						lst_http_ok_download_size[http_ok_n] = e->http->download_size;
					}

					/* AVG TIME TO FIRST HEADER BYTE */
					avg_ttfb_header = (avg_ttfb_header * http_ok_n + e->http->bgof_header) / (http_ok_n + 1);
					lst_ttfb_header[http_ok_n] = e->http->bgof_header;

					/* AVG TIME TO FIRST BODY BYTE */
					avg_ttfb_body = (avg_ttfb_body * http_ok_n + e->http->bgof_body) / (http_ok_n + 1);
					lst_ttfb_body[http_ok_n] = e->http->bgof_body;

					http_ok_n++;
				} else {
					/* TODO: calculate statistics for failed downloads. */
					http_error_n++;
				}
			} else {
				http_error_n++;
			}
		}

		/* <METRICNAME> */
		buffer_insert_strlen(csvheader, "metric_name;");
		buffer_snprintf(csvbuf, 32, "WEBPERF;");

		/* <UNIX_TIMESTAMP> */
		buffer_insert_strlen(csvheader, "timestamp;");
		buffer_snprintf(csvbuf, 32, "%u;", test->timestamp);

		/* <TEST TAG> */
		buffer_insert_strlen(csvheader, "test_tag;");
		buffer_snprintf(csvbuf, 64, "%s;", test->tag);

		buffer_insert_strlen(csvheader, "test_status;");
		if (interrupted) {
			/* The test always fails if it was interrupted by a signal. */
			test_status = 0;
		}
		if (test_status) {
			buffer_snprintf(csvbuf, 64, "OK;");
		} else {
			buffer_snprintf(csvbuf, 64, "FAIL;");
		}

		/* CDN PROVIDER */
		buffer_insert_strlen(csvheader, "cdn;");
		switch (cdn) {
		case CDN_NONE:
			buffer_snprintf(csvbuf, 64, "NONE;");
			break;
		case CDN_AKAMAI:
			buffer_snprintf(csvbuf, 64, "AKAMAI;");
			break;
		case CDN_LEVEL3:
			buffer_snprintf(csvbuf, 64, "LEVEL3;");
			break;
		case CDN_LIMELIGHT:
			buffer_snprintf(csvbuf, 64, "LIMELIGHT;");
			break;
		case CDN_TOTAL:
			buffer_snprintf(csvbuf, 64, "TOTAL;");
			break;
		case CDN_COUNT:
			/* No operation */
			break;
		}

		/* <NUMBER OF HTTP ELEMENTS> */
		buffer_insert_strlen(csvheader, "http_elements;");
		buffer_snprintf(csvbuf, 64, "%u;", http_n);

		/* <NUMBER OF HTTPS ELEMENTS> */
		buffer_insert_strlen(csvheader, "https_elements;");
		buffer_snprintf(csvbuf, 64, "%u;", https_n);

		/* <NUMBER OF HTTP REDIRECTS> */
		buffer_insert_strlen(csvheader, "http_redirects;");
		buffer_snprintf(csvbuf, 64, "%u;", http_redirects);

		/* <DNS LOOKUPS OK> */
		buffer_insert_strlen(csvheader, "dns_ok_n;");
		buffer_snprintf(csvbuf, 64, "%u;", dns_ok_n);

		/* <DNS LOOKUPS ERROR> */
		buffer_insert_strlen(csvheader, "dns_error_n;");
		buffer_snprintf(csvbuf, 64, "%u;", dns_error_n);

		/* <AVG LOOKUP TIME FOR SUCCESSFUL LOOKUPS> */
		buffer_insert_strlen(csvheader, "avg_dns_ok_time;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_dns_ok_time);

		/* <MED LOOKUP TIME FOR SUCCESSFUL LOOKUPS> */
		buffer_insert_strlen(csvheader, "med_dns_ok_time;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_dns_ok_time, dns_ok_n));

		/* <AVG ITERATIONS FOR SUCCESSFUL LOOKUPS> */
		buffer_insert_strlen(csvheader, "avg_dns_ok_iterations;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_dns_ok_iterations);

		/* <MEDIAN ITERATIONS FOR SUCCESSFUL LOOKUPS> */
		buffer_insert_strlen(csvheader, "med_dns_ok_iterations;");
		buffer_snprintf(csvbuf, 64, "%f;", median_int(lst_dns_ok_iterations, dns_ok_n));

		/* <AVG LOOKUP TIME FOR FAILED LOOKUPS> */
		buffer_insert_strlen(csvheader, "avg_dns_error_time;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_dns_error_time);

		/* <MED LOOKUP TIME FOR FAILED LOOKUPS> */
		buffer_insert_strlen(csvheader, "med_dns_error_time;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_dns_error_time, dns_error_n));

		/* <AVG ITERATIONS FOR FAILED LOOKUPS> */
		buffer_insert_strlen(csvheader, "avg_dns_error_iterations;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_dns_error_iterations);

		/* <MEDIAN ITERATIONS FOR FAILED LOOKUPS> */
		buffer_insert_strlen(csvheader, "med_dns_error_iterations;");
		buffer_snprintf(csvbuf, 64, "%f;", median_int(lst_dns_error_iterations, dns_error_n));

		/* <NUMBER OF COMPLETED HTTP DOWNLOADS>  */
		buffer_insert_strlen(csvheader, "http_ok_n;");
		buffer_snprintf(csvbuf, 64, "%u;", http_ok_n);

		/* <NUMBER OF COMPLETED HTTPS DOWNLOADS>  */
		buffer_insert_strlen(csvheader, "https_ok_n;");
		buffer_snprintf(csvbuf, 64, "%u;", http_ok_ssl_n);

		/* HTTP_NO_IP */
		buffer_insert_strlen(csvheader, "http_no_ip_n;");
		buffer_snprintf(csvbuf, 64, "%u;", http_no_ip_n);

		/* <AVG CONNECT TIME OF COMPLETED DOWNLOADS> */
		buffer_insert_strlen(csvheader, "avg_http_ok_connect_time;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_http_ok_connect_time);

		/* <MED CONNECT TIME>  */
		buffer_insert_strlen(csvheader, "med_http_ok_connect_time;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_http_ok_connect_time, http_ok_connect_n));

		/* <AVG SSL CONNECT TIME OF COMPLETED DOWNLOADS> */
		buffer_insert_strlen(csvheader, "avg_http_ok_ssl_connect_time;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_http_ok_ssl_connect_time);

		/* <MED SSL CONNECT TIME>  */
		buffer_insert_strlen(csvheader, "med_http_ok_ssl_connect_time;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_http_ok_ssl_connect_time, http_ok_connect_ssl_n));

		/* <AVG DOWNLOAD TIME OF COMPLETED DOWNLOADS>  */
		buffer_insert_strlen(csvheader, "avg_http_ok_download_time;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_http_ok_download_time);

		/* <MED DOWNLOAD TIME OF COMPLETED DOWNLOADS>  */
		buffer_insert_strlen(csvheader, "med_http_ok_download_time;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_http_ok_download_time, http_ok_n));

		/* <AVG FILE SIZE OF COMPLETED DOWNLOADS>  */
		buffer_insert_strlen(csvheader, "avg_http_ok_download_size;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_http_ok_download_size);

		/* <MED FILE SIZE>  */
		buffer_insert_strlen(csvheader, "med_http_ok_download_size;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_http_ok_download_size, http_ok_n));

		/* <HTTPS AVG DOWNLOAD TIME OF COMPLETED DOWNLOADS>  */
		buffer_insert_strlen(csvheader, "avg_https_ok_download_time;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_https_ok_download_time);

		/* <httpsS MED DOWNLOAD TIME OF COMPLETED DOWNLOADS>  */
		buffer_insert_strlen(csvheader, "med_https_ok_download_time;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_https_ok_download_time, http_ok_ssl_n));

		/* <httpsS AVG FILE SIZE OF COMPLETED DOWNLOADS>  */
		buffer_insert_strlen(csvheader, "avg_https_ok_download_size;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_https_ok_download_size);

		/* <httpsS MED FILE SIZE>  */
		buffer_insert_strlen(csvheader, "med_https_ok_download_size;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_https_ok_download_size, http_ok_ssl_n));

		/* <FIRST SERVER> */
		buffer_insert_strlen(csvheader, "dns_server;");
		buffer_snprintf(csvbuf, 64, "%s;", first_server);

		/* 50% PAGE LOAD TIME */
		buffer_insert_strlen(csvheader, "page_load_time_50;");
		buffer_snprintf(csvbuf, 64, "%f;", page_load_time(test, 50));

		/* 80% PAGE LOAD TIME */
		buffer_insert_strlen(csvheader, "page_load_time_80;");
		buffer_snprintf(csvbuf, 64, "%f;", page_load_time(test, 80));

		/* 95% PAGE LOAD TIME */
		buffer_insert_strlen(csvheader, "page_load_time_95;");
		buffer_snprintf(csvbuf, 64, "%f;", page_load_time(test, 95));

		/* 100% PAGE LOAD TIME */
		buffer_insert_strlen(csvheader, "page_load_time_100;");
		buffer_snprintf(csvbuf, 64, "%f;", page_load_time(test, 100));

		/* AVG TIME TO FIRST HEADER BYTE */
		buffer_insert_strlen(csvheader, "avg_header_latency;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_ttfb_header);

		/* MED TIME TO FIRST HEADER BYTE */
		buffer_insert_strlen(csvheader, "med_header_latency;");
		buffer_snprintf(csvbuf, 64, "%f;", median_float(lst_ttfb_header, http_ok_n));

		/* AVG TIME TO BODY HEADER BYTE */
		buffer_insert_strlen(csvheader, "avg_body_latency;");
		buffer_snprintf(csvbuf, 64, "%f;", avg_ttfb_body);

		/* MED TIME TO BODY HEADER BYTE */
		buffer_insert_strlen(csvheader, "med_body_latency");
		buffer_snprintf(csvbuf, 64, "%f", median_float(lst_ttfb_body, http_ok_n));

#ifndef NDEBUG
		if (cdn == CDN_NONE) {
			dprintf(fd_out, "%s\n", csvheader->head);
		}
#endif
		dprintf(fd_out, "%s\n", csvbuf->head);
		fflush(stdout);
		buffer_reset(csvheader);
		buffer_reset(csvbuf);

		free(lst_dns_error_iterations);
		free(lst_dns_error_time);
		free(lst_dns_ok_iterations);
		free(lst_dns_ok_time);
		free(lst_http_ok_connect_time);
		free(lst_http_ok_download_size);
		free(lst_http_ok_download_time);
		free(lst_http_ok_ssl_connect_time);
		free(lst_ttfb_header);
		free(lst_ttfb_body);

	}
	buffer_free(csvheader);
	buffer_free(csvbuf);
}

float page_load_time(WebperfTest *test, int completeness) {
	ElementStat *e;
	float tmp;
	int n = test->nrof_elements;
	float *sorted = calloc(n, sizeof(float));
	int i = 0, j;
	float result;
	struct timeval diff;

	assert(test->manager->bgof_exec.tv_sec != 0 && test->manager->bgof_exec.tv_usec != 0);
	for (e = test->elements; e != NULL; e = e->next) {
		if (e->http == NULL || (e->http != NULL && e->http->result == HURL_XFER_NONE)) {
			/* If interrupted: Ignore elements where the HTTP download was never attempted. */
			continue;
		}
		assert(e->end_transfer.tv_sec != 0 && e->end_transfer.tv_usec != 0);
		timersub(&e->end_transfer, &test->manager->bgof_exec, &diff);
		sorted[i] = timeval_to_msec(&diff);
		/* log_debug(__func__, "Element was loaded after %f ms", sorted[i]); */
		assert(sorted[i] > 0);
		i++;
	}

	for (i = 0; i < n; i++) {
		for (j = 0; j < n - 1; j++) {
			if (sorted[j] > sorted[j + 1]) {
				/* Swap values */
				tmp = sorted[j];
				sorted[j] = sorted[j + 1];
				sorted[j + 1] = tmp;
			}
		}
	}

	i = (float) completeness * (float) (n - 1) / 100.0f;
	result = sorted[i];
	log_debug(__func__, "%d %% of the elements were downloaded in %f ms.", completeness, result);
	free(sorted);
	return result;
}
