#include <gtest/gtest.h>
#include <string.h>
#include <stdlib.h>


extern "C" {
#include "hurl/internal/hurl_parse.h"
}

TEST(ProtocolParser, UnsupportedProtocols)
{
    HURLParsedURL url;
    memset(&url, 0, sizeof(HURLParsedURL));

    hurl_url_parser_error_t rc;

    rc = parse_protocol(&url, "://www.example.com/");
    EXPECT_EQ(HURL_URL_PARSER_ERROR_PROTOCOL, rc);
    EXPECT_STREQ(NULL, url.protocol);

    rc = parse_protocol(&url, "httpwww.example.com/");
    EXPECT_EQ(HURL_URL_PARSER_ERROR_PROTOCOL, rc);
    EXPECT_STREQ(NULL, url.protocol);

    rc = parse_protocol(&url, "ftp://www.example.com/");
    EXPECT_EQ(HURL_URL_PARSER_ERROR_PROTOCOL, rc);
    EXPECT_EQ(NULL, url.protocol);
}

TEST(ProtocolParser, SupportedProtocols)
{
    HURLParsedURL url;
    memset(&url, 0, sizeof(HURLParsedURL));

    hurl_url_parser_error_t rc;

    rc = parse_protocol(&url, "http://www.example.com/");
    EXPECT_EQ(HURL_URL_PARSER_ERROR_NONE, rc);
    EXPECT_STREQ("http", url.protocol);

    rc = parse_protocol(&url, "https://www.example.com/");
    EXPECT_EQ(HURL_URL_PARSER_ERROR_NONE, rc);
    EXPECT_STREQ("https", url.protocol);
}

TEST(HostnameParser, EmptyHostname)
{
    HURLParsedURL url;
    memset(&url, 0, sizeof(HURLParsedURL));
    const char* test_url = "http:///";
    const char* bgof_hostname = strstr(test_url, "://") + 3;
    const char* eof_test_url = test_url + strlen(test_url);

    hurl_url_parser_error_t rc =
        parse_hostname(&url, bgof_hostname, eof_test_url);

    EXPECT_EQ(HURL_URL_PARSER_ERROR_HOSTNAME, rc);
    EXPECT_EQ(NULL, url.hostname);
}

TEST(HostnameParser, HostnameIsFollowedByPort)
{
    HURLParsedURL url;
    memset(&url, 0, sizeof(HURLParsedURL));
    const char* hostname = "www.example.com";
    char test_url[1024];
    snprintf(test_url, sizeof(test_url), "http://%s:80/", hostname);
    const char* bgof_hostname = strstr(test_url, "://") + 3;
    const char* eof_test_url = test_url + strlen(test_url);

    hurl_url_parser_error_t rc =
        parse_hostname(&url, bgof_hostname, eof_test_url);

    EXPECT_EQ(HURL_URL_PARSER_ERROR_NONE, rc);
    EXPECT_STREQ(hostname, url.hostname);
}

TEST(HostnameParser, HostnameIsNotFollowedByPath)
{
    HURLParsedURL url;
    memset(&url, 0, sizeof(HURLParsedURL));
    const char* hostname = "www.example.com";
    char test_url[1024];
    snprintf(test_url, sizeof(test_url), "http://%s", hostname);
    const char* bgof_hostname = strstr(test_url, "://") + 3;
    const char* eof_test_url = test_url + strlen(test_url);

    hurl_url_parser_error_t rc =
        parse_hostname(&url, bgof_hostname, eof_test_url);

    EXPECT_EQ(HURL_URL_PARSER_ERROR_NONE, rc);
    EXPECT_STREQ(hostname, url.hostname);
}

TEST(HostnameParser, DomainLabelTooLong)
{
    HURLParsedURL url;
    memset(&url, 0, sizeof(HURLParsedURL));

    char long_label[512];
    memset(long_label, 'x', sizeof(long_label));

    char test_url[1024];
    snprintf(test_url, sizeof(test_url), "http://www.%s.com/", long_label);

    const char* bgof_hostname = strstr(test_url, "://") + 3;
    const char* eof_test_url = test_url + strlen(test_url);

    hurl_url_parser_error_t rc =
        parse_hostname(&url, bgof_hostname, eof_test_url);

    EXPECT_EQ(HURL_URL_PARSER_ERROR_HOSTNAME, rc);
    EXPECT_EQ(NULL, url.hostname);
}

TEST(PortParser, PortIsNegative)
{
    HURLParsedURL url;
    memset(&url, 0, sizeof(HURLParsedURL));

    const char* test_url = "http://www.example.com:-1/";
    const char* eof_test_url = test_url + strlen(test_url);
    const char* eof_hostname = test_url + strlen("http://www.example.com");

    hurl_url_parser_error_t rc =
        parse_port(&url, eof_hostname, eof_test_url);

    EXPECT_EQ(HURL_URL_PARSER_ERROR_PORT, rc);
    EXPECT_EQ(0, url.port);
}

TEST(PortParser, PortIsOutOfRange)
{
    HURLParsedURL url;
    memset(&url, 0, sizeof(HURLParsedURL));

    char test_url[1024];
    snprintf(test_url, sizeof(test_url), "http://www.example.com:%d/", UINT16_MAX + 1);
    const char* eof_test_url = test_url + strlen(test_url);
    const char* eof_hostname = test_url + strlen("http://www.example.com");

    hurl_url_parser_error_t rc =
        parse_port(&url, eof_hostname, eof_test_url);

    EXPECT_EQ(HURL_URL_PARSER_ERROR_PORT, rc);
    EXPECT_EQ(0, url.port);
}

TEST(PortParser, HasNoPort)
{
    typedef struct port_test_case_s {
        const char* url;
        const char* protocol;
        int eof_hostname_offset;
        uint16_t expected_port;
    } port_test_case_t;

    port_test_case_t test_parameters[] = {
        { "http://www.example.com/", "http", 22, 80 },
        { "http://www.example.com", "http", 22, 80 },
        { "https://www.example.com/", "https", 23, 443 },
        { "https://www.example.com", "https", 23, 443 }
    };

    for (int i = 0; i < 4; i++)
    {
        port_test_case_t params = test_parameters[i];
        const char* eof_test_url = params.url + strlen(params.url);

        HURLParsedURL url;
        memset(&url, 0, sizeof(HURLParsedURL));
        url.protocol = (char*)params.protocol;

        hurl_url_parser_error_t rc =
            parse_port(&url, params.url + params.eof_hostname_offset, eof_test_url);

        EXPECT_EQ(HURL_URL_PARSER_ERROR_NONE, rc);
        EXPECT_EQ(params.expected_port, url.port);
    }
}

TEST(PathParser, HasNoPath)
{
    const char* test_url = "http://www.example.com";
    const char* eof_hostname = test_url + strlen(test_url);
    const char* eof_url = eof_hostname;

    HURLParsedURL url = { };
    hurl_url_parser_error_t rc = parse_path(&url, eof_hostname, eof_url);

    EXPECT_EQ(HURL_URL_PARSER_ERROR_NONE, rc);
    EXPECT_STREQ("/", url.path);
}

TEST(URLParser, CommonHttpUrls)
{
    typedef struct test_url_s {
        const char* url;
        const char* expected_protocol;
        const char* expected_hostname;
        uint16_t expected_port;
        const char* expected_path;
    } test_url_t;

    test_url_t test_urls[] = {
        { "http://www.google.com/", "http", "www.google.com", 80, "/" },
        { "http://www.google.com/", "https", "www.google.com", 443, "/" },
    };

    size_t num_test_urls = sizeof(test_urls) / sizeof(test_urls[0]);

    for (int i = 0; i < num_test_urls; i++)
    {
        HURLParsedURL url = { };
        test_url_t test_url = test_urls[i];
        hurl_url_parser_error_t rc = hurl_parse_url(test_url.url, &url);

        EXPECT_EQ(HURL_URL_PARSER_ERROR_NONE, rc);

        EXPECT_STREQ(test_url.expected_protocol, url.protocol);
        EXPECT_STREQ(test_url.expected_hostname, url.hostname);
        EXPECT_EQ(test_url.expected_port, url.port);
        EXPECT_STREQ(test_url.expected_path, url.path);
    }
}

TEST(URLParser, FreeParsedUrl)
{
    // TODO: Implement this
}



int main(int argc,
         char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
