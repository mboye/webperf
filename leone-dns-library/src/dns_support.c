#include <arpa/inet.h>
#include "dns_core.h"
#include "dns_support.h"
#include "leone_tools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include "dns_cache.h"

int dns_load_resolv_conf(DNSCache *cache, char *conf) {
	struct stat resolv_st;
	char *resolvbuf;
	int resolv_fd;
	struct buffer *buf;
	int i;
	int pton, af;
	char *record_name, record_addr[16];
	DNSRecord *record;
	unsigned int bgof_line, eof_line, line_len;
	int nrof_records = 0;
	DNSRecordType record_type = ANY;

	/* Get size of /etc/resolv.conf */
	if (stat(conf, &resolv_st) == -1) {
		log_debug(__func__, "Failed to open '%s': %s", conf, strerror(errno));
		return DNS_ERROR;
	}
	/* Allocate memory. */
	if ((resolvbuf = calloc(1, (size_t)resolv_st.st_size)) == NULL) {
		log_debug(__func__, "Out of memory.");
		return DNS_MEMORY;
	}
	/* Read name servers from /etc/resolv.conf */
	if ((resolv_fd = open(conf, O_RDONLY)) == -1) {
		log_debug(__func__, "Failed to open '%s': %s", conf, strerror(errno));
		return DNS_ERROR;
	}
	/* Read name servers. */
	if (read(resolv_fd, resolvbuf, resolv_st.st_size) != resolv_st.st_size) {
		log_debug(__func__, "Failed to read list of name servers.");
		return DNS_ERROR;
	}
	buffer_init(&buf, 1024, 128);
	for (i = 0; i < resolv_st.st_size; i++) {
		if (resolvbuf[i] == '#') {
			/* Skip comment lines */
			skip_line(resolvbuf, resolv_st.st_size, &i);
			i--;
			continue;
		}
		if (strncasecmp(resolvbuf + i, "nameserver ", strlen("nameserver ")) == 0) {
			i += strlen("nameserver "); /* Move cursor past "nameserver " */
			/* Read until end of line. */
			bgof_line = i;
			for (eof_line = bgof_line; eof_line < resolv_st.st_size && resolvbuf[eof_line] != '\n'; eof_line++) {
				/* Do nothing. */
			}
			line_len = eof_line - bgof_line;
			i += line_len;
			buffer_insert(buf, resolvbuf + bgof_line, line_len);
			log_debug(__func__, "Name server: %s", buf->head);

			/* Parse IP address. */
			for (af = AF_INET; af <= AF_INET6; af += AF_INET6 - AF_INET) {
				if ((pton = inet_pton(af, buf->head, record_addr)) == 0) {
					/* Wrong address family. */
					continue;
				} else if (pton == 1) {
					/* Parse OK. */
					record_type = (af == AF_INET ? A : AAAA);
					record_name = buf->head;
					break;
				} else {
					/* Parser failed. */
					log_debug(__func__, "Failed to parse name server '%s'", buf->head);
					break;
				}
			}

			/* Reset buffer. */
			buffer_reset(buf);

			/* Check if parser failed. */
			if (record_type == 0) {
				log_debug(__func__, "Failed to parse name server '%s'", buf->head);
			} else {
				nrof_records++;
				/* Set record name. */
				record_name = allocstrcpy(DNS_FAKE_ROOT_SERVER_NAME, strlen(DNS_FAKE_ROOT_SERVER_NAME), 1);
				/* Insert record into cache. */
				record = dns_record_create(record_type, record_name, record_addr, record_type == A ? 4 : 16, DNS_DEFAULT_TTL, ANSWERS);
				/* Insert record into DNS cache. */
				dns_cache_add_rr(cache, record);
				dns_record_free(record);
			}

		}
	}

	free(resolvbuf);
	free(buf);
	log_debug(__func__, "Loaded %d name servers from '%s'", nrof_records, conf);
	return DNS_OK;
}

unsigned short chars_to_short(char *bgof_value) {
	unsigned char x = *bgof_value, y = *(bgof_value + 1);
#if __BYTE_ORDER == LITTLE_ENDIAN
	/* Smallest value at the lowest index. */
	return (unsigned short) (x + (y << 8));
#else
	/* Largest value at the lowest index. */
	return (unsigned short) (y + (x << 8));
#endif
}

unsigned int chars_to_int(char *bgof_value) {
	unsigned int result = 0;
#if __BYTE_ORDER == LITTLE_ENDIAN
	/* Smallest value at the lowest index. */
	result = bgof_value[3] << 24;
	result += bgof_value[2] << 16;
	result += bgof_value[1] << 8;
	result += bgof_value[0];
#else
	/* Largest value at the lowest index. */
	result = bgof_value[0] << 24;
	result += bgof_value[1] << 16;
	result += bgof_value[2] << 8;
	result += bgof_value[3];
#endif
	return result;
}

/* Order records in ANSWER and ADDITIONAL by network preference. */
unsigned short dns_message_nwp(DNSMessage *msg, NetworkPreference nwp, DNSRecord ***nwp_records) {
	char done = 0;
	int i;
	unsigned short nrof_records;
	enum network_preference state;
	DNSRecord *record = NULL;
	DNSRecord **result, **tmp = NULL; /* Contains pointers to A/AAAA records based on network preference. */
	int nrof_nwp_records = 0;
	nrof_records = msg->nrof_answers + msg->nrof_additionals;
	if ((result = calloc(nrof_records, sizeof(DNSRecord *))) == NULL) {
		log_debug(__func__, "Out of memory.");
		exit(EXIT_FAILURE);
	}

	state = nwp;
	while (!done) {
		switch (state) {
		case DEFAULT:
			for (i = 0; i < msg->nrof_answers; i++) {
				record = msg->answers[i];
				if (record->type == A || record->type == AAAA) {
					result[nrof_nwp_records] = record;
					nrof_nwp_records++;
				}
			}
			for (i = 0; i < msg->nrof_additionals; i++) {
				record = msg->additionals[i];
				if (record->type == A || record->type == AAAA) {
					result[nrof_nwp_records] = record;
					nrof_nwp_records++;
				}
			}
			done = 1;
			break;
		case IPv46:
			/* no break */
		case IPv4:
			for (i = 0; i < msg->nrof_answers; i++) {
				record = msg->answers[i];
				if (record->type == A) {
					result[nrof_nwp_records] = record;
					nrof_nwp_records++;
				}
			}
			for (i = 0; i < msg->nrof_additionals; i++) {
				record = msg->additionals[i];
				if (record->type == A) {
					result[nrof_nwp_records] = record;
					nrof_nwp_records++;
				}
			}
			if (nwp == IPv46) {
				state = IPv6;
			} else {
				done = 1;
			}
			break;
		case IPv64:
			/* no break */
		case IPv6:
			for (i = 0; i < msg->nrof_answers; i++) {
				record = msg->answers[i];
				if (record->type == AAAA) {
					result[nrof_nwp_records] = record;
					nrof_nwp_records++;
				}
			}
			for (i = 0; i < msg->nrof_additionals; i++) {
				record = msg->additionals[i];
				if (record->type == AAAA) {
					result[nrof_nwp_records] = record;
					nrof_nwp_records++;
				}
			}
			if (nwp == IPv64) {
				state = IPv4;
			} else {
				done = 1;
			}
			break;
		}
	}
	if (nrof_nwp_records > 0) {
		/* Optimize memory allocation. */
		if ((tmp = realloc(result, sizeof(DNSRecord *) * nrof_nwp_records)) != NULL) {
			result = tmp;
#ifndef NDEBUG
			/*
			 log_debug(__func__, "Ordered list of A/AAAA records:");
			 for (i = 0; i < nrof_nwp_records; i++) {
			 record_debug(__func__, result[i]);
			 }
			 */
#endif
			*nwp_records = result;
			return nrof_nwp_records;
		} else {
			log_debug(__func__, "realloc() failed.");
			exit(EXIT_FAILURE);
		}
	} else {
		/* log_debug(__func__, "The DNS message contained no ANSWERs or ADDITIONALs."); */
		free(result);
		return 0;
	}
}

char *repeat_char(char c, int times) {
	char *string = malloc(sizeof(char) * (times + 1));
	int i;
	for (i = 0; i < times; i++) {
		string[i] = c;
	}
	return string;
}

void dns_cache_print(DNSMessage *root, char *parent) {
	DNSMessage *node;
	char p[512];
	char *name;
	int i, af;
	char debug_addr[INET6_ADDRSTRLEN];
	int nrof_records = root->nrof_answers + root->nrof_authorities + root->nrof_additionals + root->nrof_children;
	if (parent != NULL) {
		if (!nrof_records)
			printf("%s--- [%s]\n", parent, root->label);
		snprintf(p, sizeof(p), "%s--- [%s] ", parent, root->label);
	} else {
		if (!nrof_records)
			printf("--- [%s]\n", root->label);
		snprintf(p, sizeof(p), "<root> ");
	}
	/* Print ANSWERS */
	for (i = 0; i < root->nrof_answers; i++) {
		bzero(debug_addr, sizeof(debug_addr));
		af = root->answers[i]->data_len == 4 ? AF_INET : AF_INET6;
		inet_ntop(af, root->answers[i]->data, debug_addr, INET6_ADDRSTRLEN);
		name = root->answers[i]->name;
		if (strlen(name) == 0)
			name = ".";
		if (af == AF_INET) {
			printf("%s--- A: %s\n", p, debug_addr);
		} else {
			printf("%s--- AAAA: %s\n", p, debug_addr);
		}
	}
	/* Print AUTHORITIES records. */
	for (i = 0; i < root->nrof_authorities; i++) {
		name = root->authorities[i]->name;
		if (strlen(name) == 0)
			name = ".";
		printf("%s--- NS: %s\n", p, root->authorities[i]->data);
	}
	/* Print ADDITIONALS records. */
	for (i = 0; i < root->nrof_additionals; i++) {
		bzero(debug_addr, sizeof(debug_addr));
		af = root->additionals[i]->data_len == 4 ? AF_INET : AF_INET6;
		inet_ntop(af, root->additionals[i]->data, debug_addr, INET6_ADDRSTRLEN);
		name = root->additionals[i]->name;
		if (strlen(name) == 0)
			name = ".";
		if (af == AF_INET) {
			printf("%s--- A: %s\n", p, debug_addr);
		} else {
			printf("%s--- AAAA: %s\n", p, debug_addr);
		}
	}

	for (i = 0; i < root->nrof_children; i++) {
		node = root->children[i];
		dns_cache_print(node, p);
	}
}

