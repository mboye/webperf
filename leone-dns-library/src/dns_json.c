#include "leone_tools.h"
#include "dns_core.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "dns_json.h"

void dns_conf_json(DNSResolverState *state, Buffer *buf) {
	char tmp[1024];
	char timeout[1024];
	int i, n = 0;
	for (i = 0; state->timeout[i] > 0 && i < DNS_MAX_SEND_COUNT; i++) {
		n += snprintf(timeout, (size_t) (1024 - n), "%u ", state->timeout[i]);
	}
	timeout[n] = '\0';
	snprintf(tmp, sizeof(tmp), "{\"timeout\":\"%s\",\"recurse\":%u,\"networkPreference\":%d}", timeout, state->recurse, state->nwp);
	buffer_insert_strlen(buf, tmp);
}

void dns_cache_json(DNSMessage *root, Buffer *buf) {
	int is_root = (root->parent == NULL);
	DNSRecord *record;
	char tmp[1024], *rdata;
	int i;

	/* Beginning of root */
	if (is_root) {
		buffer_insert_strlen(buf, "{\".\":{");
	} else {
		snprintf(tmp, sizeof(tmp), "\"%s\":{", root->label);
		buffer_insert_strlen(buf, tmp);
	}

	/* Print records for current node. */
	buffer_insert_strlen(buf, "\"$records\":[");
	for (i = 0; i < root->nrof_answers; i++) {
		record = root->answers[i];
		rdata = dns_record_rdata_str(record);
		snprintf(tmp, sizeof(tmp), "{\"type\":%d,\"section\":%d,\"TTL\":%u,\"data\":\"%s\"},", record->type, record->section, record->ttl, rdata);
		buffer_insert_strlen(buf, tmp);
	}
	for (i = 0; i < root->nrof_authorities; i++) {
		record = root->authorities[i];
		rdata = dns_record_rdata_str(record);
		snprintf(tmp, sizeof(tmp), "{\"type\":%d,\"section\":%d,\"TTL\":%u,\"data\":\"%s\"},", record->type, record->section, record->ttl, rdata);
		buffer_insert_strlen(buf, tmp);
	}
	for (i = 0; i < root->nrof_additionals; i++) {
		record = root->additionals[i];
		rdata = dns_record_rdata_str(record);
		snprintf(tmp, sizeof(tmp), "{\"type\":%d,\"section\":%d,\"TTL\":%u,\"data\":\"%s\"},", record->type, record->section, record->ttl, rdata);
		buffer_insert_strlen(buf, tmp);
	}
	if (root->nrof_answers || root->nrof_authorities || root->nrof_additionals) {
		buffer_rewind(buf, 1);
	}
	buffer_insert_strlen(buf, "]");
	/* Print records for child nodes. */
	for (i = 0; i < root->nrof_children; i++) {
		buffer_insert_strlen(buf, ",");
		dns_cache_json(root->children[i], buf);
	}
	/* End child. */
	buffer_insert_strlen(buf, "}");
	/* Endroot. */
	if (is_root)
		buffer_insert_strlen(buf, "}");
}

char *dns_trace_json(DNSResolverState *state) {
	Buffer *buf;
	char *json;
	int i;
	if (!buffer_init(&buf, 4096, 1024)) {
		return NULL;
	}

	buffer_insert_strlen(buf, "[");
	for (i = 0; i < state->nrof_queries; i++) {
		if (i > 0) {
			buffer_insert_strlen(buf, ",");
		}
		dns_query_json(state->queries[i], buf);
	}
	buffer_insert_strlen(buf, "]");
	buffer_trim(buf);
	json = buf->head;
	free(buf);
	return json;

}

void dns_query_json(DNSQuery *query, Buffer *buf) {
	char tmp[32];
	/* Print JSON for query. */
	buffer_insert_strlen(buf, "{ \"server\":\"");
	buffer_insert_strlen(buf, query->authority);
	buffer_insert_strlen(buf, "\",\"serverAddress\":\"");
	buffer_insert_strlen(buf, query->destination);
	buffer_insert_strlen(buf, "\",\"queryName\":\"");
	buffer_insert_strlen(buf, query->qname);
	buffer_insert_strlen(buf, "\",\"responseCode\":");
	snprintf(tmp, sizeof(tmp), "%d,", query->response_code);
	buffer_insert_strlen(buf, tmp);
	buffer_insert_strlen(buf, "\"size\":");
	snprintf(tmp, sizeof(tmp), "%u", query->pksize);
	buffer_insert_strlen(buf, tmp);
	if (query->response != NULL) {
		buffer_insert_strlen(buf, ",\"response\":");
		/* Print response JSON. */
		dns_response_json(query->response, buf);
	}
	/* End query JSON. */
	buffer_insert_strlen(buf, "}");

}
void dns_response_json(DNSMessage *response, Buffer *buf) {
	char tmp[1024];
	char *rdata;
	int i;
	int nrof_records = 0;
	DNSRecord *record;
	buffer_insert_strlen(buf, "{ \"networkTime\":");
	snprintf(tmp, sizeof(tmp), "%f,", response->rtt);
	buffer_insert_strlen(buf, tmp);
	buffer_insert_strlen(buf, "\"size\":");
	snprintf(tmp, sizeof(tmp), "%u,", response->pksize);
	buffer_insert_strlen(buf, tmp);
	buffer_insert_strlen(buf, "\"authoritative\":");
	snprintf(tmp, sizeof(tmp), "%u,", response->authoritative);
	buffer_insert_strlen(buf, tmp);
	buffer_insert_strlen(buf, "\"recursionAvailable\":");
	snprintf(tmp, sizeof(tmp), "%u,", response->recursion_avail);
	buffer_insert_strlen(buf, tmp);
	buffer_insert_strlen(buf, "\"recursionDesired\":");
	snprintf(tmp, sizeof(tmp), "%u,", response->recursion_desired);
	buffer_insert_strlen(buf, tmp);
	buffer_insert_strlen(buf, "\"sectionSizes\":");
	snprintf(tmp, sizeof(tmp), "[%d,%d,%d,%d],", response->nrof_questions, response->nrof_answers, response->nrof_authorities, response->nrof_additionals);
	buffer_insert_strlen(buf, tmp);

	/* Print answers. */
	buffer_insert_strlen(buf, "\"answers\": [");
	for (i = 0; i < response->nrof_answers; i++) {
		record = response->answers[i];
		if (i > 0) {
			buffer_insert_strlen(buf, ",");
		}
		rdata = dns_record_rdata_str(record);
		snprintf(tmp, sizeof(tmp), "{\"name\":\"%s\",\"type\":%d,\"TTL\":%d,\"data\":\"%s\"}", record->name, record->type, record->ttl, rdata);
		buffer_insert_strlen(buf, tmp);
		nrof_records++;
	}
	buffer_insert_strlen(buf, "],");

	/* Print authorities. */
	buffer_insert_strlen(buf, "\"authorities\": [");
	for (i = 0; i < response->nrof_authorities; i++) {
		record = response->authorities[i];
		if (i > 0) {
			buffer_insert_strlen(buf, ",");
		}
		rdata = dns_record_rdata_str(record);
		if (record->type != SOA) {
			snprintf(tmp, sizeof(tmp), "{\"name\":\"%s\",\"type\":%d,\"TTL\":%d,\"data\":\"%s\"}", record->name, record->type, record->ttl, rdata);
		} else {
			/* data is set to SOA object. */
			snprintf(tmp, sizeof(tmp), "{\"name\":\"%s\",\"type\":%d,\"TTL\":%d,\"data\":%s}", record->name, record->type, record->ttl, rdata);
		}
		buffer_insert_strlen(buf, tmp);
		nrof_records++;
	}
	buffer_insert_strlen(buf, "],");

	/* Print additionals. */
	buffer_insert_strlen(buf, "\"additionals\": [");
	for (i = 0; i < response->nrof_additionals; i++) {
		record = response->additionals[i];
		if (i > 0) {
			buffer_insert_strlen(buf, ",");
		}
		rdata = dns_record_rdata_str(record);
		snprintf(tmp, sizeof(tmp), "{\"name\":\"%s\",\"type\":%d,\"TTL\":%d,\"data\":\"%s\"}", record->name, record->type, record->ttl, rdata);
		buffer_insert_strlen(buf, tmp);
		nrof_records++;
	}
	buffer_insert_strlen(buf, "]");

	/* End of JSON */
	buffer_insert_strlen(buf, "}");

}
