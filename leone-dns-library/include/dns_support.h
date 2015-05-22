/*
 * dns_support.h
 *
 *  Created on: Apr 23, 2013
 *      Author: root
 */

#ifndef DNS_SUPPORT_H_
#define DNS_SUPPORT_H_

#include "leone_tools.h"
#include <limits.h>
#include <sys/time.h>
#include "dns_core.h"

#define RESOLV_CONF "/etc/resolv.conf"
#define DNS_FAKE_ROOT_SERVER_NAME "recursive-dns-server"
#define DNS_DEFAULT_TTL 3600

unsigned short dns_message_nwp(DNSMessage *msg, NetworkPreference nwp, DNSRecord ***nwp_records);
unsigned int chars_to_int(char *bgof_value);
unsigned short chars_to_short(char *bgof_value);
unsigned short chars_to_short(char *bgof_value);
void dns_cache_print(DNSMessage *root, char *parent);

void dns_create_packet(char *qname, DNSRecordType qtype, unsigned short flags, char **packet, unsigned short *packet_len, unsigned short *id);
void dns_message_add_record(DNSMessage *msg, DNSRecord *record, char increment_nrof);
unsigned short dns_message_flag(unsigned short *flags, enum dns_flags flag, unsigned short value);
DNSRecord *dns_message_find_question(DNSMessage *msg, char *name);
DNSRecord *dns_message_find_rr(DNSMessage *msg, DNSSection section, char *name, enum dns_record_type type);
DNSRecord *dns_message_find_answer(DNSMessage *msg, char *qname, NetworkPreference nwp);
DNSRecord *dns_message_find_duplicate(DNSMessage *msg, DNSRecord *record);
DNSMessage *dns_message_copy(DNSMessage *msg, NetworkPreference nwp);
void dns_message_free(DNSMessage *msg);
void dns_fix_pointers(DNSMessage *response, NetworkPreference nwp);
int dns_load_resolv_conf(DNSCache *cache, char *conf);

char *dns_cat_labels(char **labels, unsigned char start_label, char end_label);
char *dns_message_fqdn(DNSMessage *message);
unsigned char dns_count_labels(char *domain); /* Count number of labels in domain name. */

DNSRecord *dns_record_copy(DNSRecord *record);
DNSRecord *dns_record_create(DNSRecordType type, char *name, char *rdata, unsigned short rdata_len, unsigned int ttl, DNSSection section);

char dns_message_parse(DNSResolverState *state, DNSCache *cache, char *respbuf, unsigned int respbuf_len, char *qname);
char dns_parse_questions(char *respbuf, char **cursor, char *cursor_max, DNSMessage *response);
char dns_parse_rr_a(char **cursor, char *cursor_max, DNSMessage *response, DNSRecord *record);
DNSRecord *dns_rr_random(DNSMessage *msg, enum dns_section section, enum dns_record_type type, char *name);

char dns_parse_rr_ns(char *respbuf, char **cursor, char *cursor_max, DNSMessage *response, DNSRecord *record);
char dns_parse_rr_cname(char *respbuf, char **cursor, char *cursor_max, DNSMessage *response, DNSRecord *record);
char dns_parse_rr_soa(char *respbuf, char **cursor, char *cursor_max, DNSMessage *response, DNSRecord *record);
char dns_parse_rr_label(char *bgof_msg, char **cursor, char *cursor_max, struct buffer *output);
void dns_section_free(DNSMessage *msg, char section);
void record_debug(const char *func, DNSRecord *record);



#endif /* DNS_SUPPORT_H_ */
