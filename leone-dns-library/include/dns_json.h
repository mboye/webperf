/*
 * dns_json.h
 *
 *  Created on: May 27, 2013
 *      Author: root
 */

#ifndef DNS_JSON_H_
#define DNS_JSON_H_

char *dns_trace_json(DNSResolverState *state);
void dns_query_json(DNSQuery *query, Buffer *buf);
void dns_response_json(DNSMessage *response, Buffer *buf);
void dns_conf_json(DNSResolverState *state, Buffer *buf);
void dns_cache_json(DNSMessage *cache, Buffer *buf);

#endif /* DNS_JSON_H_ */
