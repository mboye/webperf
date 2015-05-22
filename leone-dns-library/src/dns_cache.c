#include <stdlib.h>
#include "dns_core.h"
#include "dns_cache.h"
#include "dns_support.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>

/* Private functions */
void dns_cache_node_add_record(DNSCache *cache, DNSMessage *node, DNSRecord *record);
DNSMessage *dns_cache_node_add_child(DNSCache *cache, DNSMessage *parent, char *label);

void dns_cache_add_rr(DNSCache *cache, DNSRecord *record) {
	char *name, *name_tmp, *label;
	DNSMessage *root, *leaf, *parent_node;
	int i, j, k;
	char *labels[DNS_MAX_LABELS];
	unsigned char nrof_labels, parent_level = 0, record_level, level_prev = 0;
	char *name_split_ptr;

	/* Get cache lock. */
	pthread_mutex_lock(&cache->lock);

	root = cache->root;
	record_level = dns_count_labels(record->name);
	/* log_debug(__func__, "Adding '%s' (%d labels) to cache.", record->name, record_level);*/

	/* Verify record integrity. */
	assert(record->name != NULL);
	assert(record->data != NULL);

	if (strlen(record->data) == 0) {
		log_debug(__func__, "WARNING: Cannot add record with empty RDATA to cache.");
		/* Release cache lock. */
		pthread_mutex_unlock(&cache->lock);
		return;
	}

	/* Check for root records. */
	if (record_level == 0) {
		dns_cache_node_add_record(cache, cache->root, record);
		/* Release cache lock. */
		pthread_mutex_unlock(&cache->lock);
		return;
	}

	name = allocstrcpy(record->name, strlen(record->name), 1);
	name_tmp = name;

	/* Split domain name into labels. */
	i = 0;

	while ((labels[i] = strtok_r(name_tmp, ".", &name_split_ptr)) != NULL) {
		if (name_tmp != NULL)
			name_tmp = NULL;
		i++;
	}
	nrof_labels = record_level;
	leaf = root;
	/* Traverse tree. */
	for (i = nrof_labels - 1; i >= 0; i--) {
		label = labels[i];
		for (j = 0; j < leaf->nrof_children; j++) {
			if (strcasecmp(leaf->children[j]->label, label) == 0) {
				/* Label matches. Select new leaf node. */
				leaf = leaf->children[j];
				parent_level++;
				break;
			}
		}

		/* Check if best leaf node has been found. */
		if (parent_level == level_prev || i == 0) {
			/* Record being added must be a subdomain of current leaf. */
			parent_node = leaf;
			/*parent_domain = dns_cat_labels(labels, 0, parent_level);
			 free(parent_domain); */
			assert(parent_level <= record_level);
			if (parent_level == record_level) {
				/* Parent is the direct parent of the record. */
				/* log_debug(__func__, "Adding record to %s", parent_node->label);*/
				dns_cache_node_add_record(cache, parent_node, record);
				free(name);

				/* Release cache lock. */
				pthread_mutex_unlock(&cache->lock);

				return;
			} else {
				/* Create missing nodes. */
				for (k = 0; k < (record_level - parent_level); k++) {
					label = labels[i - k];
					/* log_debug(__func__, "Creating node '%s'=>'%s'", parent_node->label, label); */
					parent_node = dns_cache_node_add_child(cache, parent_node, label);
					assert(parent_node->label != NULL);
					assert(strlen(parent_node->label) != 0);
				}
				/* Add record to parent. */
				/* log_debug(__func__, "Adding record to %s", parent_node->label); */
				dns_cache_node_add_record(cache, parent_node, record);
				free(name);

				/* Release cache lock. */
				pthread_mutex_unlock(&cache->lock);
				return;
			}
		}
		level_prev = parent_level;
	}
	free(name);

	/* Release cache lock. */
	pthread_mutex_unlock(&cache->lock);
}

int dns_cache_load(DNSCache **cache, char *conf) {
	struct stat conf_st;
	char *buf;
	int fd, i, j, nrof_nodes = 0;
	DNSRecord *record;
	char af;
	int pton_retval;
	DNSRecordType record_type = 0;
	DNSSection record_section = QUESTIONS;
	char type[8], name[256], rdata[256];
	char ip_address[16];
	int line_count = 1;
	if (conf != NULL) {
		/* Initialize cache if necessary. */
		if (*cache == NULL)
			*cache = dns_cache_init();

		/* Get size configuration file. */
		if (stat(conf, &conf_st) == -1) {
			log_debug(__func__, "Failed to open '%s': %s", conf, strerror(errno));
			return DNS_ERROR;
		}
		/* Allocate memory. */
		if ((buf = calloc(1, conf_st.st_size)) == NULL) {
			log_debug(__func__, "Out of memory.");
			return DNS_MEMORY;
		}
		/* Read name servers from /etc/resolv.conf */
		if ((fd = open(conf, O_RDONLY)) == -1) {
			log_debug(__func__, "Failed to open '%s': %s", conf, strerror(errno));
			return DNS_ERROR;
		}
		/* Read name servers. */
		if (read(fd, buf, conf_st.st_size) != conf_st.st_size) {
			log_debug(__func__, "Failed to read cache configuration file.");
			return DNS_ERROR;
		}
		nrof_nodes = 0;
		i = 0;
		while (i < conf_st.st_size && nrof_nodes < DNS_MAX_ROOT_SERVERS) {
			/* Configuration format: "NS google-public-dns-a.google.com
			 * 						  A google-public-dns-a.google.com 8.8.8.8" */
			if (buf[i] == '#') {
				/* Skip comment lines */
				skip_line(buf, conf_st.st_size, &i);
				continue;
			}

			bzero(type, sizeof(type));
			bzero(name, sizeof(name));
			bzero(rdata, sizeof(rdata));
			j = 0;
			/* Read record type. */
			while (j < sizeof(type) && i < conf_st.st_size) {
				if (buf[i] == ' ') {
					type[j] = '\0';
					if (strlen(type) == 0) {
						log_debug(__func__, "ERROR: TYPE cannot be empty.");
						i++;
						skip_line(buf, conf_st.st_size, &i);
						line_count++;
						continue;
					}
					log_debug(__func__, "Type: %s", type);
					i++;
					break;
				} else if (buf[i] == '\n') {
					log_debug(__func__, "Bad configuration syntax on line %d", line_count);
					i++;
					line_count++;
					continue;

				} else {
					type[j] = buf[i];
				}
				i++;
				j++;
			}
			/* Read domain name. */
			j = 0;
			while (j < sizeof(name) && i < conf_st.st_size) {
				if (buf[i] == ' ') {
					name[j] = '\0';
					if (strlen(name) == 0) {
						log_debug(__func__, "ERROR: NAME cannot be empty.");
						i++;
						skip_line(buf, conf_st.st_size, &i);
						line_count++;
						continue;
					}
					log_debug(__func__, "Domain: %s", name);
					i++;
					break;
				} else if (buf[i] == '\n') {
					log_debug(__func__, "Bad configuration syntax on line %d", line_count);
					i++;
					line_count++;
					continue;
				} else {
					name[j] = buf[i];
				}
				i++;
				j++;
			}
			/* Read RDATA address. */
			j = 0;
			while (j < sizeof(rdata) && i < conf_st.st_size) {
				if (buf[i] == '\n') {
					rdata[j] = '\0';
					if (strlen(rdata) == 0) {
						log_debug(__func__, "ERROR: RDATA cannot be empty.");
						i++;
						line_count++;
						continue;
					}
					log_debug(__func__, "RDATA: %s", rdata);
					i++;
					break;
				} else {
					rdata[j] = buf[i];
				}
				i++;
				j++;
			}

			/* Determine record type. */
			if (strcasecmp("A", type) == 0 || strcasecmp("AAAA", type) == 0) {
				/* Parser IP address. */
				for (af = AF_INET; af <= AF_INET6; af += AF_INET6 - AF_INET
				) {
					if ((pton_retval = inet_pton(af, rdata, &ip_address)) == 0) {
						/* Wrong address family. */
						continue;
					} else if (pton_retval == 1) {
						/* Parse OK. */
						record_type = (af == AF_INET ? A : AAAA);
						record_section = ANSWERS;
						break;
					} else {
						/* Parser failed. */
						log_debug(__func__, "Failed to parse IP address '%s'", rdata);
						break;
					}
				}

				/* Check if parser failed. */
				if (record_type == 0) {
					log_debug(__func__, "Failed to parse IP address '%s'", rdata);
				}
			} else if (strcasecmp("NS", type) == 0) {
				record_type = NS;
				record_section = AUTHORITIES;
			} else {
				log_debug(__func__, "Unexpected record type.");
				continue;
			}
			/* Create record. */
			if (record_type == A || record_type == AAAA) {
				/* RDATA was IP address. */
				record = dns_record_create(record_type, name, ip_address, (record_type == A ? 4 : 16), DNS_DEFAULT_TTL, record_section);
			} else {
				/* RDATA was NS record. */
				record = dns_record_create(record_type, name, rdata, strlen(rdata), DNS_DEFAULT_TTL, record_section);
			}
			/* Insert record into DNS cache. */
			dns_cache_add_rr(*cache, record);
			dns_record_free(record);
		}
		/* Free buffer. */
		free(buf);
		return DNS_OK;
	} else {
		return DNS_ERROR;
	}
}

int dns_cache_ready(DNSCache *cache) {
	DNSRecord *ns;
	int i;
	if (cache != NULL && cache->root->nrof_authorities > 0) {
		for (i = 0; i < cache->root->nrof_authorities; i++) {
			ns = cache->root->authorities[i];
			if (dns_cache_find_rr(cache, ns->data, A_AAAA, ANSWERS | ADDITIONALS, NULL) != NULL) {
				return 1; /* Resolver has root NS record with A/AAAA record. */
			}
		}
	}
	return 0; /* No root NS record with A/AAAA record found. */
}

void dns_cache_reset() {
	log_debug(__func__, "NOT IMPLEMENTED.");
}

void dns_cache_verify(DNSMessage *root, DNSMessage *node) {
#ifndef NDEBUG
	DNSMessage *child;
	int i;
	child = root;
	/* Verify root. */

	/*log_debug(__func__, "Label: %s", root->label);*/
	fflush(stdout);
	assert(node->label != NULL);
	if (root != node)
		assert(strlen(node->label) > 0);

	/* Verify questions. */
	for (i = 0; i < node->nrof_questions; i++) {
		assert(node->questions[i] != NULL);
		assert(node->questions[i]->name != NULL);
		assert(node->questions[i]->data != NULL);
	}
	/* Verify answers. */
	for (i = 0; i < node->nrof_answers; i++) {
		assert(node->answers[i] != NULL);
		assert(node->answers[i]->name != NULL);
		assert(node->answers[i]->data != NULL);
	}
	/* Verify authorities. */
	for (i = 0; i < node->nrof_authorities; i++) {
		assert(node->authorities[i] != NULL);
		assert(node->authorities[i]->name != NULL);
		assert(node->authorities[i]->data != NULL);
	}
	/* Verify additionals. */
	for (i = 0; i < node->nrof_additionals; i++) {
		assert(node->additionals[i] != NULL);
		assert(node->additionals[i]->name != NULL);
		assert(node->additionals[i]->data != NULL);
	}

	for (i = 0; i < node->nrof_children; i++) {
		child = node->children[i];
		assert(child != NULL);
		dns_cache_verify(root, child);
	}
#endif
}

void dns_cache_print_csv(DNSMessage *root) {
	DNSMessage *node;
	char *name;
	int i, af;
	char debug_addr[INET6_ADDRSTRLEN];
	/* Print ANSWERS */
	for (i = 0; i < root->nrof_answers; i++) {
		bzero(debug_addr, sizeof(debug_addr));
		af = root->answers[i]->data_len == 4 ? AF_INET : AF_INET6;
		inet_ntop(af, root->answers[i]->data, debug_addr, INET6_ADDRSTRLEN);
		name = root->answers[i]->name;
		if (af == AF_INET) {
			printf("A %s. %s\n", name, debug_addr);
		} else {
			printf("AAAA %s. %s\n", name, debug_addr);
		}

	}
	/* Print AUTHORITIES records. */
	for (i = 0; i < root->nrof_authorities; i++) {
		name = root->authorities[i]->name;
		printf("NS %s. %s\n", name, root->authorities[i]->data);
	}
	/* Print ADDITIONALS records. */
	for (i = 0; i < root->nrof_additionals; i++) {
		bzero(debug_addr, sizeof(debug_addr));
		af = root->additionals[i]->data_len == 4 ? AF_INET : AF_INET6;
		inet_ntop(af, root->additionals[i]->data, debug_addr,
		INET6_ADDRSTRLEN);
		name = root->additionals[i]->name;
		if (af == AF_INET) {
			printf("A %s. %s\n", name, debug_addr);
		} else {
			printf("AAAA %s. %s\n", name, debug_addr);
		}
	}

	for (i = 0; i < root->nrof_children; i++) {
		node = root->children[i];
		dns_cache_print_csv(node);
	}
}

DNSCache *dns_cache_init() {
	DNSCache *cache;
	if ((cache = calloc(1, sizeof(DNSCache))) == NULL) {
		return NULL;
	}
	if ((cache->root = calloc(1, sizeof(DNSMessage))) == NULL) {
		free(cache);
		return NULL;
	}
	cache->root->domain_id = 1; /* The first domain IDs are reserved for internal purposes. */

	if ((cache->root->children = calloc(DNS_CACHE_NODE_NROF_CHILDREN, sizeof(DNSMessage *))) == NULL) {
		free(cache);
		free(cache->root);
		return NULL;
	}
	/* Initialize label to "" */
	if ((cache->root->label = calloc(1, sizeof(char))) == NULL) {
		free(cache);
		free(cache->root->children);
		free(cache->root);
		return NULL;
	}

	cache->root->nrof_children = 0;
	cache->root->max_children = DNS_CACHE_NODE_NROF_CHILDREN;

	return cache;
}

DNSRecord *dns_cache_find_rr(DNSCache *cache, char *qname, DNSRecordType qtype, DNSSection section, DNSMessage **msg) {
	DNSMessage *leaf, *root;
	int i, j, k, x;
	char *qname_tmp, *label, *copy;
	char *labels[DNS_MAX_LABELS];
	int nrof_labels;
	unsigned char level = 0, level_prev = 0;
	DNSSection s;
	DNSRecord **search_section, *record;
	unsigned short nrof_records;
	char *name_split_ptr = NULL;

	/* Get cache lock. */
	pthread_mutex_lock(&cache->lock);

	/* log_debug(__func__, "Search for '%s' in cache.", qname); */

	/* Split domain name into labels. */
	i = 0;
	copy = allocstrcpy(qname, strlen(qname), 1);
	qname_tmp = copy;
	while ((labels[i] = strtok_r(qname_tmp, ".", &name_split_ptr)) != NULL) {
		if (qname_tmp != NULL)
			qname_tmp = NULL;
		i++;
	}
	nrof_labels = i;
	root = cache->root;

	leaf = root;
	/* Traverse tree. */
	for (i = nrof_labels - 1; i >= 0; i--) {
		label = labels[i];
		for (j = 0; j < leaf->nrof_children; j++) {
			if (strcasecmp(leaf->children[j]->label, label) == 0) {
				/* Label matches. Select new leaf node. */
				leaf = leaf->children[j];
				level++;
				break;
			}
		}

		/* Check if node matching FULL qname has been found. */
		if (i == 0 && level == nrof_labels) {
			if (i == 0) {
				/* This is the node we were looking for.
				 * Search for record in node... */
				for (k = 1; k < 4; k++) {
					s = 1 << k;
					if (section & s) {
						/* Create pointer to search section. */
						dns_message_section(leaf, s, &search_section, &nrof_records);
						for (x = 0; x < nrof_records; x++) {
							record = search_section[x];
							/* TODO: We should probably return a copy of the record. */
							if (record->type == CNAME) {
								/* Always give CNAMEs priority. */
								if (msg != NULL)
									*msg = leaf;
								free(copy);
								/* Release cache lock. */
								pthread_mutex_unlock(&cache->lock);
								return record;
							} else if (qtype == A_AAAA && (record->type == A || record->type == AAAA)) {
								if (msg != NULL)
									*msg = leaf;
								free(copy);
								/* Release cache lock. */
								pthread_mutex_unlock(&cache->lock);
								return record;
							} else if (record->type == qtype) {
								if (msg != NULL)
									*msg = leaf;
								free(copy);
								/* Release cache lock. */
								pthread_mutex_unlock(&cache->lock);
								return record;
							}
						}
					}
				}
				/* None of the sections contains the node we were looking for. */
				free(copy);
				/* Release cache lock. */
				pthread_mutex_unlock(&cache->lock);
				return NULL;
			} else {
				/* The cache only contains information about parent domain. */
				free(copy);
				/* Release cache lock. */
				pthread_mutex_unlock(&cache->lock);
				return NULL;
			}
		} else if (level_prev == level) {
			/* The full QNAME was not found in cache. */
			break;
		}
		level_prev = level;
	}
	free(copy);
	/* Release cache lock. */
	pthread_mutex_unlock(&cache->lock);
	return NULL;
}

void dns_cache_node_add_record(DNSCache *cache, DNSMessage *node, DNSRecord *record) {
	DNSRecord *copy;
	if (dns_message_find_duplicate(node, record) != NULL) {
		/* log_debug(__func__, "WARNING: Duplicate record already in cache."); */
		return;
	}
	/* Check that record actually belongs to this node. */
	assert(strncasecmp(node->label, record->name, strlen(node->label)) == 0);

	switch (record->section) {
	case ANSWERS:
		if (node->nrof_answers < DNS_MAX_SECTION_RECORDS) {
			copy = dns_record_copy(record);
			copy->record_id = ++(cache->record_counter);
			node->answers[node->nrof_answers++] = copy;
		} else {
			log_debug(__func__, "WARNING: ANSWERS section is full.");
		}
		break;
	case AUTHORITIES:
		if (node->nrof_authorities < DNS_MAX_SECTION_RECORDS) {
			if (record->type == NS) {
				copy = dns_record_copy(record);
				copy->record_id = ++(cache->record_counter);
				node->authorities[node->nrof_authorities++] = copy;
			} else {
				log_debug(__func__, "WARNING: Attempt to add non-NS record (type = %d) to AUTHORITIES section.", record->type);
			}
		} else {
			log_debug(__func__, "WARNING: AUTHORITIES section is full.");
		}
		break;
	case ADDITIONALS:
		if (node->nrof_additionals < DNS_MAX_SECTION_RECORDS) {
			copy = dns_record_copy(record);
			copy->record_id = ++(cache->record_counter);
			node->additionals[node->nrof_additionals++] = copy;
		} else {
			log_debug(__func__, "WARNING: 	ADDITIONALS section is full.");
		}
		break;
	default:
		log_debug(__func__, "WARNING: Unknown message section.");
		break;
	}
}

DNSMessage *dns_cache_node_add_child(DNSCache *cache, DNSMessage *parent, char *label) {
	DNSMessage **tmp, *new_node;
	/* Ensure sufficient memory for new child node. */
	if (parent->nrof_children == parent->max_children) {
		/* Expand memory. */
		if ((tmp = realloc(parent->children, sizeof(DNSMessage *) * (parent->nrof_children + DNS_CACHE_NODE_NROF_CHILDREN))) == NULL) {
			log_debug(__func__, "Out of memory.");
			exit(EXIT_FAILURE);
		}
		parent->max_children += DNS_CACHE_NODE_NROF_CHILDREN;
		parent->children = tmp;
	}
	parent->children[parent->nrof_children] = calloc(1, sizeof(DNSMessage));
	new_node = parent->children[parent->nrof_children];
	new_node->domain_id = ++(cache->domain_counter);
	new_node->parent = parent;
	new_node->max_children = 0;
	new_node->label = allocstrcpy(label, strlen(label), 1);
	parent->nrof_children++;
	return new_node;

}

DNSMessage *dns_cache_find_domain(DNSCache *cache, char *qname) {
	DNSMessage *leaf, *root;
	int i, j;
	char *qname_tmp, *label, *copy;
	char *labels[DNS_MAX_LABELS];
	int nrof_labels;
	unsigned char level = 0, level_prev = 0;
	DNSMessage *result = NULL;
	char *name_split_ptr = NULL;

	/* Get cache lock. */
	pthread_mutex_lock(&cache->lock);

	/* log_debug(__func__, "Search for '%s' in cache.", qname); */

	/* Split domain name into labels. */
	i = 0;
	copy = allocstrcpy(qname, strlen(qname), 1);
	qname_tmp = copy;
	while ((labels[i] = strtok_r(qname_tmp, ".", &name_split_ptr)) != NULL) {
		if (qname_tmp != NULL)
			qname_tmp = NULL;
		i++;
	}
	nrof_labels = i;
	root = cache->root;

	leaf = root;
	/* Traverse tree. */
	for (i = nrof_labels - 1; i >= 0; i--) {
		label = labels[i];
		for (j = 0; j < leaf->nrof_children; j++) {
			if (strcasecmp(leaf->children[j]->label, label) == 0) {
				/* Label matches. Select new leaf node. */
				leaf = leaf->children[j];
				level++;
				break;
			}
		}

		/* Check if node matching FULL qname has been found. */
		if (i == 0 && level == nrof_labels) {
			if (i == 0) {
				/* This is the node we were looking for. */
				result = leaf;
				break;
			} else {
				/* The cache only contains information about parent domain. */
				break;
			}
		} else if (level_prev == level) {
			/* The full QNAME was not found in cache. */
			break;
		}
		level_prev = level;
	}
	free(copy);
	/* Release cache lock. */
	pthread_mutex_unlock(&cache->lock);
	return result;
}

DNSMessage *dns_cache_find_best_ns(DNSCache *cache, char *qname) {
	DNSMessage *leaf, *root;
	int i, j, x;
	char *qname_tmp, *label, *copy;
	char *labels[DNS_MAX_LABELS];
	int nrof_labels;
	unsigned char level = 0, level_prev = 0;
	DNSRecord *record;
	char *name_split_ptr = NULL;

	/* Get cache lock. */
	pthread_mutex_lock(&cache->lock);

	/* Split domain name into labels. */
	i = 0;
	copy = allocstrcpy(qname, strlen(qname), 1);
	qname_tmp = copy;
	while ((labels[i] = strtok_r(qname_tmp, ".", &name_split_ptr)) != NULL) {
		if (qname_tmp != NULL)
			qname_tmp = NULL;
		i++;
	}
	nrof_labels = i;
	root = cache->root;

	leaf = root;
	/* Traverse tree. */
	for (i = nrof_labels - 1; i >= 0; i--) {
		label = labels[i];
		for (j = 0; j < leaf->nrof_children; j++) {
			if (strcasecmp(leaf->children[j]->label, label) == 0) {
				/* Label matches. Select new leaf node. */
				leaf = leaf->children[j];
				level++;
				break;
			}
		}

		/* Check if best leaf node has been found. */
		if (level == level_prev || i == 0) {
			while (leaf->parent != NULL || leaf == root) {
				for (x = 0; x < leaf->nrof_authorities; x++) {
					record = leaf->authorities[x];
					if (record->type == NS) {
						free(copy);

						/* Release cache lock. */
						pthread_mutex_unlock(&cache->lock);
						/* TODO: It is probably safer to return a copy of the message. */
						return leaf;
					}
				}
				if (leaf == root) {
					/* The root does not have a parent. */
					free(copy);
					/* Release cache lock. */
					pthread_mutex_unlock(&cache->lock);
					return NULL;
				} else {
					/* Search for NS records for parent domain. */
					leaf = leaf->parent;
				}
			}
		}
		level_prev = level;
	}
	free(copy);
	/* Release cache lock. */
	pthread_mutex_unlock(&cache->lock);
	return NULL;
}

