/*
 * leone_tools.c
 *
 *  Created on: May 15, 2013
 *      Author: root
 */
#include <sys/time.h>
#include <math.h>

float timeval_to_msec(struct timeval *t) {
	float result;
	result = (float) t->tv_sec * (float) 1000;
	result += (float) t->tv_usec / (float) 1000;
	return result;
}
