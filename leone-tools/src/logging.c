#include <stdarg.h>
#include <stdio.h>
#include "leone_tools.h"
#include <pthread.h>

void log_debug(const char *func, const char *msg, ...) {
#ifndef NDEBUG
	char template[1024];
	va_list args;
	snprintf(template, sizeof template, "[%u] %s(): %s\n", (unsigned int)pthread_self(), func, msg);
	va_start(args, msg);
	vfprintf(stderr, template, args);
	va_end(args);
	fflush(stderr);
	
#endif
}
void write_log(const char *func, const char *msg, ...){
	FILE *fp;
	va_list args;
	char template[8192];
	va_start(args, msg);
	snprintf(template, sizeof template, "[%u] %s(): %s\n", (unsigned int) pthread_self(), func, msg);
	fp = fopen("/tmp/playback.log", "a");
	vfprintf(fp, template, args);
	va_end(args);
	fclose(fp);
}
