#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include "leone_tools.h"
#include "dns_core.h"
#include "dns_support.h"

void dns_record_free(DNSRecord *record) {
	free(record->data);
	free(record->name);
	free(record);
}

DNSRecord *dns_record_create(DNSRecordType type, char *name, char *rdata, unsigned short rdata_len, unsigned int ttl, DNSSection section) {
	DNSRecord *record;
	record = calloc(1, sizeof(DNSRecord));
	record->type = type;
	record->class = IN;
	if (strcmp(name, ".") != 0) {
		record->name = malloc(sizeof(char) * (strlen(name) + 1));
		strncpy(record->name, name, strlen(name) + 1);
	} else {
		record->name = calloc(1, 1);
	}
	record->data = malloc((size_t)(rdata_len + 1));
	memcpy(record->data, rdata, rdata_len); /* Copy RDATA */
	record->data[rdata_len] = '\0';
	record->data_len = rdata_len;
	record->ttl = ttl;
	record->section = section;
	return record;
}

void dns_fix_pointers(DNSMessage *response, enum network_preference nwp) {
	DNSRecord *question;
	int i;

	/* Pair questions with answers. */
	for (i = 0; i < response->nrof_questions; i++) {
		question = response->questions[i];
		if (question->type == A || question->type == AAAA) {
			/* Create link question to answer. */
			question->answer = dns_message_find_answer(response, question->name, nwp);

			/* Some sort of answer was found! */
			if (question->answer != NULL) {
				/* Check if answer is CNAME. */
				if (question->answer->type == CNAME && question->answer->answer != NULL) {
					/* Create link to CNAME's answer. */
					question->answer = question->answer->answer;
				}
				/* Create reverse link: answer to CNAME */
				question->answer->question = question;
			}
		}
	}
}

DNSMessage *dns_message_copy(DNSMessage *msg, enum network_preference nwp) {
	DNSMessage *copy;
	int i;
	assert(msg!=NULL);

	/* Allocate memory for message copy. */
	if ((copy = calloc(1, sizeof(DNSMessage))) == NULL) {
		log_debug(__func__, "Out of memory.");
		exit(EXIT_FAILURE);
	}
	/* Copy message fields. */
	memcpy(copy, msg, sizeof(DNSMessage));

	/* Copy label */
	copy->label = allocstrcpy(msg->label, strlen(msg->label), 1);

	/* Copy QUESTIONS. */
	for (i = 0; i < msg->nrof_questions; i++) {
		copy->questions[i] = dns_record_copy(msg->questions[i]);
	}
	/* Copy ANSWERS. */
	for (i = 0; i < msg->nrof_answers; i++) {
		copy->answers[i] = dns_record_copy(msg->answers[i]);
	}
	/* Copy AUTHORITIES. */
	for (i = 0; i < msg->nrof_authorities; i++) {
		copy->authorities[i] = dns_record_copy(msg->authorities[i]);
	}
	/* Copy ADDITIONALS. */
	for (i = 0; i < msg->nrof_additionals; i++) {
		copy->additionals[i] = dns_record_copy(msg->additionals[i]);
	}

	/* Link question to answers and vice versa. */
	dns_fix_pointers(copy, nwp);
	return copy;
}

DNSRecord *dns_record_copy(DNSRecord *record) {
	DNSRecord *copy;

	/* Allocate memory for record copy. */
	if ((copy = calloc(1, sizeof(DNSRecord))) == NULL) {
		log_debug(__func__, "Out of memory.");
		exit(EXIT_FAILURE);
	}
	/* Copy message fields. */
	memcpy(copy, record, sizeof(DNSRecord));

	/* Copy name. */
	copy->name = allocstrcpy(record->name, strlen(record->name), 1);

	/* Copy RDATA */
	copy->data = allocstrcpy(record->data, record->data_len, 1);

	return copy;
}

/* Frees DNS messages in msgs, but not msgs itself. */
void dns_message_free(DNSMessage *msg) {
	int i;
	/* Free questions. */
	for (i = 0; i < msg->nrof_questions; i++) {
		dns_record_free(msg->questions[i]);
	}
	/* Free answers. */
	for (i = 0; i < msg->nrof_answers; i++) {
		dns_record_free(msg->answers[i]);
	}
	/* Free authorities. */
	for (i = 0; i < msg->nrof_authorities; i++) {
		dns_record_free(msg->authorities[i]);
	}
	/* Free addtionals. */
	for (i = 0; i < msg->nrof_additionals; i++) {
		dns_record_free(msg->additionals[i]);
	}
	free(msg->label);
	free(msg);
}

/* Sets flag bits and response code.
 * flags is a bitset, flag is the bit that should be set/read,
 * and value is the value to set the flag to. */
unsigned short dns_message_flag(unsigned short *flags, enum dns_flags flag, unsigned short value) {
	unsigned short flag_value = 0;
	int shift = 0;
	/* Determine flag bit. */
	switch (flag) {
	case DNS_FLAG_TYPE:
		shift = DNS_FLAG_TYPE_BIT;
		break;
	case DNS_FLAG_AUTHORITATIVE_ANS:
		shift = DNS_FLAG_AUTHORITATIVE_ANS_BIT;
		break;
	case DNS_FLAG_TRUNCATION:
		shift = DNS_FLAG_TRUNCATION_BIT;
		break;
	case DNS_FLAG_RECURSION_DESIRED:
		shift = DNS_FLAG_RECURSION_DESIRED_BIT;
		break;
	case DNS_FLAG_RECURSION_AVAIL:
		shift = DNS_FLAG_RECURSION_AVAIL_BIT;
		break;
	case DNS_FLAG_RESP_CODE:
		break;
	default:
		log_debug(__func__, "Unkown flag.");
		exit(EXIT_FAILURE);
	}

	if (value != DNS_FLAG_READ) {
		flag_value = 1 << shift;
		/* Set flag mode. */
		if (flag != DNS_FLAG_RESP_CODE) {
			if (value) {
				(*flags) |= flag_value;
			} else {
				if ((*flags) & flag_value) {
					/* Flag is set, so zero it. */
					(*flags) -= flag_value;
				}
			}
		} else {
			/* Set response code to zero. */
			(*flags) &= ~DNS_FLAG_RESP_CODE_BIT;
			(*flags) |= (DNS_FLAG_RESP_CODE_BIT & value);
		}
		return 1;
	} else {
		/* Read flag mode. */
		if (flag != DNS_FLAG_RESP_CODE) {
			return ((*flags) >> shift) & 0x0001;
		} else {
			return (*flags) & 0x000f;
		}
	}
}

/* Create DNS query packet. Returns message ID. */
void dns_create_packet(char *qname, DNSRecordType qtype, unsigned short flags, char **packet, unsigned short *packet_len, unsigned short *id) {
	unsigned int seed;
	struct timeval tm_seed;
	char *token;
	char *domain, *domain_tmp, *domain_split_ptr = NULL;
	unsigned char token_len;
	struct buffer *msgbuf;
	assert(qname != NULL);

	/* Initialize message buffer. */
	buffer_init(&msgbuf, 1024, 1024);

	/* Set transaction ID. */
	gettimeofday(&tm_seed, NULL);
	seed = strlen(qname) + tm_seed.tv_usec + (int) qtype;
	srand(seed);
	*id = (unsigned short) rand();

	/* Modify flags. ONLY create query messages. */
	dns_message_flag(&flags, DNS_FLAG_TYPE, QUERY);

	/* Insert header values into message buffer. */
	buffer_insert_short(msgbuf, htons(*id));
	buffer_insert_short(msgbuf, htons(flags));
	buffer_insert_short(msgbuf, htons(1)); /* Nrof questions. DNS servers only support one query per message. */
	buffer_insert_short(msgbuf, htons(0)); /* Nrof answers. */
	buffer_insert_short(msgbuf, htons(0));/* Nrof authorities. */
	buffer_insert_short(msgbuf, htons(0)); /* Nrof addtionals. */

	log_debug(__func__, "QNAME is '%s'", qname);

	domain = allocstrcpy(qname, strlen(qname), 1); /* Copy qname before calling strtok(). */
	domain_tmp = domain;
	/* Full label detected. */
	while ((token = strtok_r(domain_tmp, ".", &domain_split_ptr)) != NULL) {
		domain_tmp = NULL;
		token_len = (unsigned char) strlen(token);
		/* Insert token length. */
		buffer_insert(msgbuf, (char *) &token_len, 1);
		/* Insert token */
		buffer_insert(msgbuf, token, token_len);
	}
	/* Terminate question with \0. */
	buffer_insert(msgbuf, "\0", 1);

	/* Free domain buffer. */
	free(domain);

	/* Insert class and type. */
	buffer_insert_short(msgbuf, htons(qtype));
	buffer_insert_short(msgbuf, htons(IN));

	*packet = msgbuf->head;
	*packet_len = msgbuf->data_len;
	free(msgbuf);
}

/*
 DNSRecord *dns_message_find_question(DNSMessage *msg, char *name) {
 DNSRecord *record;
 int q;
 assert(msg != NULL);
 record = msg->questions;
 for (q = 0; q < msg->nrof_questions; q++) {
 record = msg->questions + q;
 if (strcmp(record->name, name) == 0) {
 return record;
 }
 }
 return NULL ;
 }
 */
DNSRecord *dns_message_find_answer(DNSMessage *msg, char *qname, NetworkPreference nwp) {
	DNSRecord *answer = NULL;
	assert(msg != NULL);
	assert(qname != NULL);

	/* Create link question to answer. */
	if (nwp == DEFAULT) {
		/* Find A/AAAA record outside of QUESTIONS section. */
		answer = dns_message_find_rr(msg, NOT_QUESTIONS, qname, A_AAAA_CNAME);
	}
	if ((nwp == IPv4 || nwp == IPv46) && answer == NULL) {
		/* Find A record outside of QUESTIONS section. */
		answer = dns_message_find_rr(msg, NOT_QUESTIONS, qname, A_CNAME);

	}
	if ((nwp == IPv6 || nwp == IPv46 || nwp == IPv64) && answer == NULL) {
		/* Find AAAA record outside of QUESTIONS section.
		 * OR find AAAA record after checking for A record. */
		answer = dns_message_find_rr(msg, NOT_QUESTIONS, qname, AAAA_CNAME);
	}
	if (nwp == IPv64 && answer == NULL) {
		/* Find A record outside of QUESTIONS section, AFTER checking for AAAAA record. */
		answer = dns_message_find_rr(msg, NOT_QUESTIONS, qname, A);
	}
	return answer;
}

DNSRecord *dns_message_find_rr(DNSMessage *msg, DNSSection section, char *name, enum dns_record_type type) {
	DNSRecord *record = NULL;
	int r, i;
	unsigned short nrof_records;
	DNSRecord **search_section;
	DNSSection s;
	assert(msg != NULL);
	assert(name != NULL);

	/* For each section. */
	for (i = 0; i < 4; i++) {
		s = 1 << i;
		/* Check if section should be searched. */
		if (section & s) {
			dns_message_section(msg, s, &search_section, &nrof_records);
			for (r = 0; r < nrof_records; r++) {
				record = search_section[r];
				if (type == A_AAAA_CNAME) {
					if ((record->type == A || record->type == AAAA || record->type == CNAME) && (strcmp(record->name, name) == 0)) {
						/* Record found. */
						return record;
					}
				} else if (type == A_CNAME) {
					if ((record->type == A || record->type == CNAME) && (strcmp(record->name, name) == 0)) {
						/* Record found. */
						return record;
					}
				} else if (type == AAAA_CNAME) {
					if ((record->type == AAAA || record->type == CNAME) && (strcmp(record->name, name) == 0)) {
						/* Record found. */
						return record;
					}
				} else {
					if (record->type == type && (strcmp(record->name, name) == 0)) {
						/* Record found. */
						return record;
					}
				}
			}
		}
	}
	return NULL;
}

DNSRecord *dns_message_find_duplicate(DNSMessage *msg, DNSRecord *record) {
	DNSRecord *existing_record = NULL;
	int r, j;
	unsigned short nrof_records;
	DNSRecord **search_section;
	char rdata_matches;
	assert(msg != NULL);

	dns_message_section(msg, record->section, &search_section, &nrof_records);
	for (r = 0; r < nrof_records; r++) {
		existing_record = search_section[r];
		/* Check record type and name */
		if (existing_record->type == record->type && (strcasecmp(existing_record->name, record->name) == 0)) {
			/* Check length of RDATA. */
			if (existing_record->data_len == record->data_len) {
				/* Check RDATA. */
				rdata_matches = 1;
				for (j = 0; j < existing_record->data_len; j++) {
					if (existing_record->data[j] != record->data[j]) {
						rdata_matches = 0;
						break;
					}
				}
				if (rdata_matches)
					return existing_record; /* Identical record found. */
			}
		}
	}
	return NULL;
}

void dns_message_section(DNSMessage *msg, DNSSection section, DNSRecord ***bgof_section, unsigned short *nrof_records) {
	switch (section) {
	case QUESTIONS:
		*bgof_section = msg->questions;
		*nrof_records = msg->nrof_questions;
		break;
	case ANSWERS:
		*bgof_section = msg->answers;
		*nrof_records = msg->nrof_answers;
		break;
	case AUTHORITIES:
		*bgof_section = msg->authorities;
		*nrof_records = msg->nrof_authorities;
		break;
	case ADDITIONALS:
		*bgof_section = msg->additionals;
		*nrof_records = msg->nrof_additionals;
		break;
	default:
		log_debug(__func__, "WARNING: Unsupported section."); /* This should never happen. */
		*bgof_section = msg->answers;
		*nrof_records = msg->nrof_answers;
		break;
	}
}

unsigned int dns_count_rr(DNSRecordType type, DNSSection section, DNSMessage *msg) {
	DNSRecord **records;
	unsigned short nrof_records = 0;
	int s, j;
	DNSSection sec;
	unsigned int count = 0;
	for (s = 0; s < 4; s++) {
		/* Check if section should be counted. */
		sec = (1 << s);
		if (sec & section) {
			switch (sec) {
			case QUESTIONS:
				records = msg->questions;
				nrof_records = msg->nrof_questions;
				break;
			case ANSWERS:
				records = msg->answers;
				nrof_records = msg->nrof_answers;
				break;
			case AUTHORITIES:
				records = msg->authorities;
				nrof_records = msg->nrof_authorities;
				break;
			case ADDITIONALS:
				records = msg->additionals;
				nrof_records = msg->nrof_additionals;
				break;
			default:
				/* This should never happen. */
				log_debug(__func__, "WARNING: Default case entered.");
				exit(1);
				break;
			}
			/* Count records based on their type. */
			for (j = 0; j < nrof_records; j++) {
				if (records[j]->type == type) {
					count++;
				}
			}
		}
	}
	return count;
}
