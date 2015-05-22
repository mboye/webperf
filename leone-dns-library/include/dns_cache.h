/*
 * dns_cache.h
 *
 *  Created on: Feb 17, 2014
 *      Author: boyem1
 */

#ifndef DNS_CACHE_H_
#define DNS_CACHE_H_

void dns_cache_add_rr(DNSCache *cache, DNSRecord *record);
int dns_cache_load(DNSCache **cache, char *conf);
int dns_cache_ready(DNSCache *cache);
void dns_cache_reset();
void dns_cache_verify(DNSMessage *root, DNSMessage *node);
void dns_cache_print_csv(DNSMessage *root);
DNSCache *dns_cache_init();
DNSRecord *dns_cache_find_rr(DNSCache *cache, char *qname, DNSRecordType qtype, DNSSection section, DNSMessage **msg);
void dns_cache_node_add_record(DNSCache *cache, DNSMessage *node, DNSRecord *record);
void dns_cache_add_rr(DNSCache *cache, DNSRecord *record);
DNSMessage *dns_cache_node_add_child(DNSCache *cache, DNSMessage *parent, char *label);
DNSMessage *dns_cache_find_domain(DNSCache *cache, char *qname);
DNSMessage *dns_cache_find_best_ns(DNSCache *cache, char *qname);

#endif /* DNS_CACHE_H_ */
