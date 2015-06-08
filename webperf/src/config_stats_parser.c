#include "webperf.h"
#include "internal/config_parser_common.h"

config_parser_rc_t config_stats_parse(const char* stats_key,
                                      const char *value)
{
    typedef struct metric_e {
        const char* name;
        int*  enabled;
    } metric_t;

    const metric_t metrics[] = {
        { "dns.queryName", &test->stats.dns.qname },
        { "dns.finalQueryName", &test->stats.dns.qname_final },
        { "dns.returnCode", &test->stats.dns.return_code },
        { "dns.networkTime", &test->stats.dns.network_time },
        { "dns.executionTime", &test->stats.dns.exec_time },
        { "dns.dataSent", &test->stats.dns.data_tx },
        { "dns.dataReceived", &test->stats.dns.data_rx },
        { "dns.messagesSent", &test->stats.dns.data_rx },
        { "dns.messagesReceived", &test->stats.dns.msg_rx },
        { "dns.queries", &test->stats.dns.queries },
        { "dns.answerA", &test->stats.dns.answer_a  },
        { "dns.answerAAAA", &test->stats.dns.answer_aaaa },
        { "dns.answerATTL", &test->stats.dns.answer_a_ttl },
        { "dns.answerAAAATTL", &test->stats.dns.answer_aaaa_ttl },
        { "dns.nrofAnswersA", &test->stats.dns.nrof_answers_a  },
        { "dns.nrofAnswersAAAA", &test->stats.dns.nrof_answers_aaaa },
        { "dns.trace", &test->stats.dns.trace },
        { "dns.beginResolve", &test->stats.dns.begin_resolve },
        { "http.TLS", &test->stats.http.tls },
        { "http.port", &test->stats.http.port },
        { "http.domain", &test->stats.http.domain },
        { "http.path", &test->stats.http.path },
        { "http.responseCode", &test->stats.http.response_code },
        { "http.connectTime", &test->stats.http.connect_time },
        { "http.connectTimeSSL", &test->stats.http.connect_time_ssl },
        { "http.connectionReused", &test->stats.http.connection_reused },
        { "http.downloadTime", &test->stats.http.download_time },
        { "http.readyTime", &test->stats.http.ready_time },
        { "http.allHeaders", &test->stats.http.all_headers },
        { "http.headerSize", &test->stats.http.header_size },
        { "http.downloadSize", &test->stats.http.download_size },
        { "http.overhead", &test->stats.http.overhead },
        { "http.contentType", &test->stats.http.content_type },
        { "http.chunkedEncoding", &test->stats.http.chunked_encoding },
        { "http.date", &test->stats.http.date },
        { "http.expiryDate", &test->stats.http.expiry_date },
        { "http.pipelined", &test->stats.http.pipelined },
        { "http.TCPStats", &test->stats.http.tcp_stats },
        { "http.beginConnect", &test->stats.http.begin_connect },
        { "http.redirectURL", &test->stats.http.redirect_url },
        { "http.redirector", &test->stats.http.redirector },
        { "http.redirectee", &test->stats.http.redirectee },
        { "http.requestSent", &test->stats.http.request_sent}
    };

    if (strcasecmp(stats_key, "http.URLLength") == 0)
    {
        return parse_int(value, &test->print_url_length, -1);
    }
    else if (strcasecmp(stats_key, "http.header") == 0)
    {
        if (!hurl_header_add(&test->stat_headers, value, "") == 0)
        {
            LOG_DEBUG("Failed to add header '%s' to list of headers to record.",
                      value);
            return CONFIG_PARSER_ERROR;
        }
        else
        {
            return CONFIG_PARSER_OK;
        }
    }
    else
    {
        for (size_t i = 0; i < sizeof(metrics) - 1; i++)
        {
            metric_t metric = metrics[i];
            if (strcmp(metric.name, stats_key) == 0)
            {
                return config_parse_boolean(metric.enabled,
                                            value);
            }
        }
    }

    return CONFIG_PARSER_ERROR;
}
