#include "hooks.h"
#include "webperf.h"
#include "arpa/inet.h"
#include "dns_core.h"
#include "dns_support.h"
#include "dns_cache.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include "leone_tools.h"
#include <errno.h>
#include <signal.h>
#include "hurl/hurl.h"
#include <string.h>
#include "config_parser.h"

#ifdef AUTO_STACKTRACE
#include <execinfo.h>
#endif

#include <openssl/sha.h>

void test_free();

void *timeout_killer(void *arg);

static void print_usage()
{
    printf("Usage: webperf --version\n");
    printf("       webperf <test.conf> <output-prefix>\n");
}

static void signal_handler(int signum,
                    siginfo_t *info,
                    void *context)
{
    (void)context;
    (void)info;

#ifdef AUTO_STACKTRACE
#ifndef NDEBUG
    void *array[10];
    size_t size;
    log_debug(__func__, "BEGIN STACKTRACE", signum);
    size = backtrace(array, 16);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    log_debug(__func__, "END STACKTRACE", signum);
#endif
#endif
    log_debug(__func__, "Signal: %d. Aborting...", signum);
    char *fn = NULL;
    /* Print statistics for all elements. */
    if (test != NULL && test->always_print_output)
    {
        /* The following call will not do anything useful:
           should set fn to something sensible. */
        print_results(test, -signum, fn);
    }
#ifdef AUTO_STACKTRACE
    abort();
#else
    exit(signum);
#endif
}

static int test_init()
{
    test = NULL;
    test = calloc(1, sizeof(WebperfTest));
    if (!test)
    {
        goto error;
    }

    pthread_mutex_init(&test->lock, NULL);

    if ((test->manager = hurl_manager_init()) == NULL)
    {
        goto error;
    }

    test->print_url_length = WEBPERF_PRINT_URL_LENGTH;
    test->dns_query_type = A;
    test->timestamp = time(NULL);
    test->tag = strdup("");
    test->stats.output_format = FORMAT_JSON;

    test->dns_state_template = dns_state_init();
    if (!test->dns_state_template)
    {
        goto error;
    }

    HURLManager *manager = test->manager;

    manager->connect_timeout = WEBPERF_TIMEOUT;
    manager->send_timeout = WEBPERF_TIMEOUT;
    manager->recv_timeout = WEBPERF_TIMEOUT;
    manager->max_connections = WEBPERF_MAX_CONNECTIONS;
    manager->max_domain_connections = WEBPERF_MAX_DOMAIN_CONNECTIONS;

    manager->hook_resolve = dns_resolve_wrapper;
    manager->hook_request_sent = stat_request_sent;
    manager->hook_transfer_complete = stat_transfer_complete;
    manager->hook_header_received = stat_header_received;
    manager->hook_send_request = stat_send_request;
    manager->hook_pre_connect = stat_pre_connect;
    manager->hook_post_connect = stat_post_connect;
    manager->hook_response_code = stat_response_code;
    manager->hook_body_recv = stat_body_recv;
    manager->hook_redirect = stat_redirect;
    manager->hook_recv = stat_response_latency;

    manager->retag = duplicate_element_stat;
    manager->free_tag = stat_free;

    test->cache = dns_cache_init();
    if (!test->cache)
    {
        goto error;
    }

    return 0;

error:
    test_free();
    return -1;
}

static void configure_signal_handling()
{
    struct sigaction sig_abort;
    memset(&sig_abort, 0, sizeof(sig_abort));

    sig_abort.sa_sigaction = &signal_handler;

    sigaction(SIGINT, &sig_abort, NULL);
    sigaction(SIGHUP, &sig_abort, NULL);
    sigaction(SIGTERM, &sig_abort, NULL);
    sigaction(SIGQUIT, &sig_abort, NULL);
    sigaction(SIGSEGV, &sig_abort, NULL);
}

int main(int argc,
         char *argv[])
{
    configure_signal_handling();


    char *config_file = NULL;
    char *output_prefix = NULL;

    if (argc >= 2 &&
        strcmp(argv[1], "--version") == 0)
    {
            printf("%s-v%d\n", WEBPERF_TEST_NAME, WEBPERF_TEST_VERSION);
            exit(0);
    }



    if (argc == 3)
    {
        test_init();

        config_file = argv[1];
        output_prefix = argv[2];

        config_parser_rc_t parser_rc = config_parse(config_file);
        if (parser_rc != CONFIG_PARSER_OK)
        {
            exit(1);
        }
    }
    else
    {
        print_usage();
        exit(1);
    }

    if (test->nrof_elements > 0)
    {
        pthread_t exec_timeout_thread = { 0 };
        pthread_create(&exec_timeout_thread,
                       NULL,
                       timeout_killer,
                       &test->exec_timeout);

        int retval =  hurl_exec(test->manager);
        if(retval)
        {
            print_results(test, 0, output_prefix);

            dns_cache_free(test->cache);
            test_free();
            exit(0);
        }
        else
        {
            exit(retval);
        }
    }
    else
    {
        printf("No target URLs loaded. Check your test configuration.");
        exit(WEBPERF_NO_TARGETS);
    }
}

void str_trim(char *str)
{
    unsigned int str_len;
    int i;
    str_len = strlen(str);
    /* Trim end of string. */
    for (i = str_len - 1; i >= 0; i--)
    {
        if ((*(str + i)) == '\n' || (*(str + i)) == ' ' || (*(str + i)) == '\n'
            || (*(str + i)) == '\r')
        {
            (*(str + i)) = '\0';
        }
        else
        {
            /* First non-spacing char detected. */
            break;
        }
    }

}



void test_free()
{
    if (test) {
        hurl_headers_free(test->stat_headers);
        hurl_manager_free(test->manager);

        free(test);
    }

    /* TODO: Implement this */
}

void *timeout_killer(void *arg)
{
    //how to pass argument for
    unsigned int sleep_time = *((unsigned int *)arg);
    char *fn = arg;
    log_debug(__func__,
              "Killer thread started. Waiting %u seconds before calling exit()",
              sleep_time);
    sleep(sleep_time);
    log_debug(__func__, "Execution timeout. Calling exit()");

    /* Print statistics for all elements. */
    if (test != NULL && test->always_print_output)
    {
        print_results(test, WEBPERF_EXEC_TIMEOUT, fn);
    }

    exit(WEBPERF_EXEC_TIMEOUT);
    return NULL;
}
