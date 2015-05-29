#include "hurl/hurl.h"
#include <string.h>
#include <sys/time.h>
#include "webperf.h"
#include <dns_support.h>

#ifndef HOOKS_H_
#define HOOKS_H_

void stat_header_received(HURLPath *path,
                          int response_code,
                          HURLHeader *headers,
                          size_t header_len);
void dns_resolve_wrapper(HURLDomain *domain,
                         HURLPath *path);
int stat_connected(HURLConnection *connection,
                   float connect_time,
                   float ssl_connect_time);
void stat_transfer_complete(HURLPath *path,
                            HURLConnection *connection,
                            HURLTransferResult result,
                            size_t content_length,
                            size_t overhead);
void stat_request_sent(HURLPath *path,
                       HURLConnection *connection);
void stat_connect_time(HURLPath *path,
                       float connect_time,
                       float connect_time_ssl,
                       int reused,
                       int pipelined);
void stat_body_recv(HURLPath *path,
                    char *data,
                    size_t data_len);
int stat_send_request(HURLPath *path,
                      HURLConnection *connection,
                      int pipelined);
int stat_pre_connect(HURLPath *path,
                     HURLConnection *connection);
void stat_post_connect(HURLPath *path,
                       HURLConnection *connection,
                       int retval);
void stat_response_code(HURLPath *path,
                        HURLConnection *connection,
                        int response_code,
                        char *response_code_text);
int stat_redirect(HURLPath *path,
                  int response_code,
                  char *redirect_url);
void stat_response_latency(HURLPath *path,
                           HURLConnection *conn,
                           char *data,
                           size_t data_len);
void stat_transfer_failed(HURLPath *path,
                          HURLConnection *conn,
                          size_t content_len,
                          size_t overhead);

#endif /* HOOKS_H_ */
