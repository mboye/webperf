#include <arpa/inet.h>
#include <assert.h>
#include "leone_tools.h"
#include "dns_core.h"
#include "dns_support.h"
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "dns_cache.h"

unsigned int debug_counter = 0;

char dns_message_parse(DNSResolverState *state, DNSCache *cache, char *respbuf, unsigned int respbuf_len, char *qname) {
	char *cursor = respbuf, *cursor_max;
	unsigned short r, nrof_records;
	struct buffer *namebuf;
	int label_len;
	unsigned short flags;
	unsigned short *cursor_short;
	DNSMessage *response;
	DNSRecord *record, **record_ptr = NULL;
	DNSSection section = 0;
	char soa_exit = 0;
	char cacheable = 1;

	cursor_short = (unsigned short *) respbuf;
	response = state->responses[state->nrof_responses];
	response->type = RESPONSE;

	/* Get transaction ID. */
	response->id = ntohs(chars_to_short(cursor));
	cursor += 2;

	cursor_short = (unsigned short *) cursor;
	flags = ntohs(*cursor_short);
	/* Parse flags. */
	response->type = dns_message_flag(&flags, DNS_FLAG_TYPE, DNS_FLAG_READ);
	response->authoritative = dns_message_flag(&flags, DNS_FLAG_AUTHORITATIVE_ANS, DNS_FLAG_READ);
	response->truncation = dns_message_flag(&flags, DNS_FLAG_TRUNCATION, DNS_FLAG_READ);
	response->recursion_desired = dns_message_flag(&flags, DNS_FLAG_RECURSION_DESIRED, DNS_FLAG_READ);
	response->recursion_avail = dns_message_flag(&flags, DNS_FLAG_RECURSION_AVAIL, DNS_FLAG_READ);
	response->response_code = dns_message_flag(&flags, DNS_FLAG_RESP_CODE, DNS_FLAG_READ);

	log_debug(__func__, "Response code is: %u", response->response_code);
	log_debug(__func__, "Flags: 0x%04x", flags);

	/* Check response code. */
	if (response->response_code != 0) {
		/* Request failed. */
		switch (response->response_code) {
		case 1:
			log_debug(__func__, "Response code: Format error.");
			break;
		case 2:
			log_debug(__func__, "Response code: Server failure.");
			break;
		case 3:
			log_debug(__func__, "Response code: Non-existant domain.");
			break;
		case 4:
			log_debug(__func__, "Response code: Not implemented.");
			break;
		case 5:
			log_debug(__func__, "Response code: Query refused.");
			break;
		default:
			log_debug(__func__, "ERROR: Response code %u", response->response_code);
			break;
		}
		if (response->response_code != 3) {
			return response->response_code;
		}
	}

	/* Update cursors. */
	cursor += 2;
	cursor_short++;

	/* Read number of questions, answers, name servers, and additional records. */
	response->nrof_questions = ntohs(*cursor_short++);
	response->nrof_answers = ntohs(*cursor_short++);
	response->nrof_authorities = ntohs(*cursor_short++);
	response->nrof_additionals = ntohs(*cursor_short++);

	/* Allocate memory for record pointers. */
	nrof_records = response->nrof_questions + response->nrof_answers + response->nrof_authorities + response->nrof_additionals;

	/* Update char cursor. */
	cursor = (char *) cursor_short;
	cursor_max = cursor + respbuf_len;

	/* Read records. */
	for (r = 0; r < nrof_records; r++) {
		cacheable = 1;
		/* Determine current section of response. */
		if (r < response->nrof_questions) {
			section = QUESTIONS;
			record_ptr = &response->questions[r];
		} else if (r < response->nrof_questions + response->nrof_answers) {
			section = ANSWERS;
			record_ptr = &response->answers[r - response->nrof_questions];
		} else if (r < response->nrof_questions + response->nrof_answers + response->nrof_authorities) {
			section = AUTHORITIES;
			record_ptr = &response->authorities[r - response->nrof_questions - response->nrof_answers];
		} else if (r < response->nrof_questions + response->nrof_answers + response->nrof_authorities + response->nrof_additionals) {
			section = ADDITIONALS;
			record_ptr = &response->additionals[r - response->nrof_questions - response->nrof_answers - response->nrof_authorities];
		}
		*record_ptr = calloc(1, sizeof(DNSRecord));
		record = *record_ptr;

		/* Read name. */
		buffer_init(&namebuf, 1024, 1024);
		while ((label_len = dns_parse_rr_label(respbuf, &cursor, cursor_max, namebuf)) > 0) {
			/* Do nothing. */
		}

		/* Check return value of label reader. */
		if (label_len == 0) {
			/* Labels read successfully. */
			/* Remove trailing dot. */
			if (namebuf->data_len > 0) { /* Handle records for root servers. */
				buffer_rewind(namebuf, 1);
				buffer_trim(namebuf);
			}
			record->section = section;
			record->name = namebuf->head;
			free(namebuf);
		} else {
			/* Failed to read labels. */
			buffer_free(namebuf);
			return DNS_ERROR_FORMAT;
		}

		/* Read type and class. */
		record->type = ntohs(chars_to_short(cursor));
		cursor += 2;
		record->class = ntohs(chars_to_short(cursor));
		cursor += 2;
		if (section != QUESTIONS) {
			log_debug(__func__, "Section: %d", section);

			/* Read TTL of record. */
			record->ttl = ntohl(chars_to_int(cursor));
			cursor += 4;
			/* Read length of RDATA. */
			record->data_len = ntohs(chars_to_short(cursor));
			cursor += 2;

			/* Check that RDATA is within buffer. */
			if (cursor + record->data_len > cursor_max) {
				log_debug(__func__, "RDATA outside of buffer.");
				return DNS_ERROR_FORMAT;
			}

			/* Perform processing depending on record type. */
			switch (record->type) {
			case A:
			case AAAA:
				/* This assertion is not always true for poorly configured DNS servers and it doesnt really harm to accept A/AAAA records in the authorities section. */
				 /* assert(section == ANSWERS || section == ADDITIONALS); */

				if (dns_parse_rr_a(&cursor, cursor_max, response, record) != DNS_OK) {
					return DNS_ERROR_FORMAT;
				}
				break;
			case CNAME:
				if (dns_parse_rr_cname(respbuf, &cursor, cursor_max, response, record) != DNS_OK) {
					return DNS_ERROR_FORMAT;
				}
				break;
			case NS:
				assert(section == AUTHORITIES);
				if (dns_parse_rr_ns(respbuf, &cursor, cursor_max, response, record) != DNS_OK) {
					return DNS_ERROR_FORMAT;
				}
				break;
			case SOA:
				/* If a SOA record is received, this is interpreted as game over for the query. */
				if (dns_parse_rr_soa(respbuf, &cursor, cursor_max, response, record) != DNS_OK) {
					return DNS_ERROR_FORMAT;
				} else {
					/* If a response contains NO answers but a SOA record, the queried record does NOT exist. */
					if (response->nrof_answers == 0) {
						log_debug(__func__, "SOA + 0 answers => Record does not exist.");
						log_debug(__func__, "SOA RECORD: %s", dns_record_rdata_str(record));
						log_debug(__func__, "Expected QNAME: '%s' -- Actual QNAME: '%s'", qname, response->questions[0]->name);
						soa_exit = 1; /* Indicate that resolution process should end. */
					}
				}
				cacheable = 0;
				break;
			default:
				cursor += record->data_len;
				log_debug(__func__, "Ignoring unsupported record type: %d", record->type);
				cacheable = 0; /* Prevent caching. */
				break;
			}
			/* Print record. */
			record_debug(__func__, record);
			/* Add record to cache. */
			if (cacheable) {
				/* TODO: Check if record comes from a credible source. */
				dns_cache_add_rr(cache, record);
			}
			debug_counter++;
		}
		/* Verify that the response matches QNAME. */
		/*
		 else {

		 if (strcasecmp(record->name, qname) != 0) {
		 log_debug(__func__, "Received response that did not match QNAME of query: '%s' != '%s'", qname, record->name);
		 return DNS_PROTOCOL_ERROR;
		 }
		 }
		 */
	}
#ifndef NDEBUG
	/* Check if end of response has been reached. */

	if (cursor != respbuf + respbuf_len) {
		log_debug(__func__, "WARNING: Parsing ended before end of DNS response (possibly padded).");
	}
#endif

	dns_fix_pointers(response, state->nwp);
	if (soa_exit || response->response_code == 3) {
		return DNS_ERROR_NXDOMAIN;
	} else {
		return DNS_ERROR_OK;
	}
}

char dns_parse_rr_cname(char *respbuf, char **cursor, char *cursor_max, DNSMessage *response, DNSRecord *record) {
	struct buffer *rdatabuf;
	int label_len;
	/* Read name of server responsible for the domain. */
	buffer_init(&rdatabuf, record->data_len, 1024);
	while ((label_len = dns_parse_rr_label(respbuf, cursor, cursor_max, rdatabuf)) > 0) {
		/* Do nothing. */
	}

	/* Check return value of label reader. */
	if (label_len == 0) {
		/* Labels read successfully. */
		/* Remove trailing dot. */
		buffer_rewind(rdatabuf, 1);
		buffer_trim(rdatabuf);
		record->data = rdatabuf->head;
		free(rdatabuf);
	} else {
		/* Failed to read labels. */
		buffer_free(rdatabuf);
		return DNS_PROTOCOL_ERROR;
	}
	/* Override data_len */
	record->data_len = strlen(record->data);
	return DNS_OK;
}

char dns_parse_rr_soa(char *bgof_msg, char **cursor, char *cursor_max, DNSMessage *response, DNSRecord *record) {
	struct buffer *databuf;
	DNSRecordSOA *soa;
	int label_len;
	if ((soa = calloc(1, sizeof(DNSRecordSOA))) == NULL) {
		/* Out of memory. */
		exit(EXIT_FAILURE);
	}
	/* Read name of server responsible for the domain. */
	buffer_init(&databuf, record->data_len, 1024);
	while ((label_len = dns_parse_rr_label(bgof_msg, cursor, cursor_max, databuf)) > 0) {
		/* Do nothing. */
	}
	/* Check return value of label reader. */
	if (label_len == 0) {
		/* Labels read successfully. */
		/* Remove trailing dot. */
		buffer_rewind(databuf, 1);
		buffer_trim(databuf);
		soa->domain = databuf->head;
		free(databuf);
	} else {
		/* Failed to read labels. */
		buffer_free(databuf);
		free(soa);
		return DNS_PROTOCOL_ERROR;
	}

	/* Read e-mail address of domain. */
	buffer_init(&databuf, record->data_len, 1024);
	while ((label_len = dns_parse_rr_label(bgof_msg, cursor, cursor_max, databuf)) > 0) {
		/* Do nothing. */
	}
	/* Check return value of label reader. */
	if (label_len == 0) {
		/* Labels read successfully. */
		/* Remove trailing dot. */
		buffer_rewind(databuf, 1);
		buffer_trim(databuf);
		soa->mailbox = databuf->head;
		free(databuf);
	} else {
		/* Failed to read labels. */
		buffer_free(databuf);
		free(soa->domain);
		free(soa);
		return DNS_PROTOCOL_ERROR;
	}

	/* Read serial. */
	soa->serial = ntohl(chars_to_int(*cursor));
	(*cursor) += 4;
	/* Read refresh time. */
	soa->refresh = ntohl(chars_to_int(*cursor));
	(*cursor) += 4;
	/* Read retry time. */
	soa->retry = ntohl(chars_to_int(*cursor));
	(*cursor) += 4;
	/* Read expiry time. */
	soa->expire = ntohl(chars_to_int(*cursor));
	(*cursor) += 4;
	soa->minimum_ttl = ntohl(chars_to_int(*cursor));
	(*cursor) += 4;

	/* Point data pointer to SOA record structure. */
	record->data = (char *) soa;
	return DNS_OK;
}

char dns_parse_rr_a(char **cursor, char *cursor_max, DNSMessage *response, DNSRecord *record) {
	/* Check that end of RDATA is within message boundaries. */
	if ((*cursor) + record->data_len > cursor_max) {
		log_debug(__func__, "RDATA exceeds message boundary.");
		return DNS_PROTOCOL_ERROR;
	}
	/* Copy IPv4 or IPv6 address. */
	if ((record->data = malloc(sizeof(char) * record->data_len)) == NULL) {
		/* Memory error. */
		log_debug(__func__, "Out of memory.");
		exit(EXIT_FAILURE);
	}
	/* Copy IP address. */
	memcpy(record->data, *cursor, record->data_len);
	/* Update cursor. */
	(*cursor) += record->data_len;
	return DNS_OK;
}

char dns_parse_rr_ns(char *bgof_msg, char **cursor, char *cursor_max, DNSMessage *response, DNSRecord *record) {
	struct buffer *rdatabuf;
	int label_len;
	/* Read name of server responsible for the domain. */
	buffer_init(&rdatabuf, record->data_len, 1024);
	while ((label_len = dns_parse_rr_label(bgof_msg, cursor, cursor_max, rdatabuf)) > 0) {
		/* Do nothing. */
	}

	/* Check return value of label reader. */
	if (label_len == 0) {
		/* Labels read successfully. */
		/* Remove trailing dot. */
		if (rdatabuf->data_len > 0)
			buffer_rewind(rdatabuf, 1);
		buffer_trim(rdatabuf);
		record->data = rdatabuf->head;
		free(rdatabuf);
	} else {
		/* Failed to read labels. */
		buffer_free(rdatabuf);
		return DNS_PROTOCOL_ERROR;
	}
	/* Override data_len */
	record->data_len = strlen(record->data);
	return DNS_OK;

}

/* Read label and return size of it.
 * Calling function should free() output buffer on failure. */
char dns_parse_rr_label(char *bgof_msg, char **cursor, char *cursor_max, struct buffer *output) {
	char *label_ptr;
	unsigned short label_offset;
	unsigned char chunk_len;
	int label_len;
	/* Read label length. */
	chunk_len = (unsigned char) **cursor;
	/* Check if chunk size indicated end of series of labels. */
	if (chunk_len != 0) {
		/* Check if length is actually a label pointer. */
		if (((chunk_len >> 6) & 0x03) == 3) {
			/* Read label offset. */
			label_offset = ntohs(chars_to_short(*cursor));
			label_offset &= 0x3fff;
			label_ptr = bgof_msg + label_offset;
			/*log_debug(__func__, "Label pointer detected with offset %u",
			 label_offset);*/
			(*cursor) += 2;
			/* Read size of label at label pointer. */
			chunk_len = *label_ptr;
			/*log_debug(__func__, "Label size at label pointer: %u", chunk_len);*/
			/* Read label at pointer. */
			while ((label_len = dns_parse_rr_label(bgof_msg, &label_ptr, cursor_max, output)) > 0) {
				/* Read until \0 is seen. */
			}

			if (label_len == 0) {
				/* The label pointer was processed successfully. */
				return 0;
			} else {
				log_debug(__func__, "Failed to read label pointer.");
				return -1;
			}
		} else {
			/* No label pointer. Read label at cursor. */
			(*cursor)++;
			/* Check that end of label is inside buffer. */
			if (*cursor + chunk_len <= cursor_max) {
				buffer_insert(output, *cursor, chunk_len);
				buffer_insert(output, ".", 1);
				(*cursor) += chunk_len;
				return chunk_len;
			} else {
				log_debug(__func__, "End of label outside of buffer!");
				return -1; /* ERROR */
			}
		}
	} else {
		/* log_debug(__func__, "End of label series reached."); */
		(*cursor)++;
		return 0; /* End of series of labels reached. */
	}
}
void record_debug(const char *func, DNSRecord *record) {
#ifndef NDEBUG
	char ipaddr[INET6_ADDRSTRLEN];
	int af;
	char *section;

	/* Determine section. */
	switch (record->section) {
	case QUESTIONS:
		section = "QUESTIONS";
		break;
	case ANSWERS:
		section = "ANSWERS";
		break;
	case AUTHORITIES:
		section = "NAMESERVERS";
		break;
	case ADDITIONALS:
		section = "ADDITIONALS";
		break;
	default:
		section = "OTHER?!";
		break;
	}

	if (record->type == NS) {
		if (strlen(record->name) > 0) {
			log_debug(__func__, "[%s] NS(%s) = %s", section, record->name, record->data);
		} else {
			log_debug(__func__, "[%s] NS(.) = %s", section, record->data);
		}
	} else if (record->type == CNAME) {
		log_debug(__func__, "[%s] CNAME(%s) => %s", section, record->name, record->data);
	} else {
		if (record->type == A) {
			af = AF_INET;
		} else {
			af = AF_INET6;
		}

		if (af == AF_INET) {
			if (inet_ntop(AF_INET, record->data, ipaddr, INET6_ADDRSTRLEN) != NULL) {
				log_debug(func, "[%s] A(%s) = %s", section, record->name, ipaddr);
			}
		} else if (record->type == AAAA) {
			if (inet_ntop(AF_INET6, record->data, ipaddr, INET6_ADDRSTRLEN) != NULL) {
				log_debug(func, "[%s] AAAA(%s) = %s", section, record->name, ipaddr);
			}
		}
	}
#endif
}
