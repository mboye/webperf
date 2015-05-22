/*
 * metrics.h
 *
 *  Created on: Jun 6, 2013
 *      Author: magnus
 */

#ifndef LEONE_METRICS_H_
#define LEONE_METRICS_H_

void leone_metrics_dns(Buffer *json, int resolve_retval, struct timeval *tm_start,
		char *qname, char *qname_final, DNSResolverState *state,
		float dns_exec_time, int print_trace, int print_final_cache);
char  *leone_dns_conf(DNSResolverState *state);

#endif /* METRICS_H_ */
