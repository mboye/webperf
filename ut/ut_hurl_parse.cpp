#include <gtest/gtest.h>
extern "C" {
#include <hurl_core.h>
}

TEST(SupportedProtocols, URLParser) {
	HURLParsedURL *result;
	int retval;
	// http
	retval = hurl_parse_url((char *)"http://www.google.com/", &result);
	EXPECT_EQ(HURL_URL_PARSE_OK, retval);
	EXPECT_STREQ("http", result->protocol);

	// https
	retval = hurl_parse_url((char *)"https://www.google.com/", &result);
	EXPECT_EQ(HURL_URL_PARSE_OK, retval);
	EXPECT_STREQ("https", result->protocol);
}


int main(int argc, char *argv[]) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
