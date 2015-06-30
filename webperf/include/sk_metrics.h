/*
 * sk_metrics.h
 *
 *  Created on: Aug 7, 2014
 *      Author: boyem1
 */

#ifndef SK_METRICS_H_
#define SK_METRICS_H_

void print_sk_metrics_csv(int interrupted,
                          int fd_out);

double median_double(double *values,
                     unsigned int n);

double median_int(int *values,
                  unsigned int n);

double page_load_time(int completeness);

#endif /* SK_METRICS_H_ */
