HURL_UT_SRCS = $(wildcard libhurl/ut/*.cpp)
HURL_UT_OBJS = $(addprefix $(BUILD_DIR)/, $(patsubst %.cpp, %.obj, $(HURL_UT_SRCS)))

HURL_UT_INCLUDES = -I libhurl/include \
                   -I $(GTEST)/include

HURL_UT_LIBS = -lssl -lcrypto $(LIB_PTHREAD)

$(HURL_UT_OBJS): $(BUILD_DIR)/%.obj: %.cpp
	mkdir -p $(dir $@)
	$(CPP) -MMD $(CPPFLAGS) $(HURL_UT_INCLUDES) -c $< -o $@

$(BUILD_DIR)/bin/libhurl_ut: ut_check $(HURL_OBJS) $(HURL_UT_OBJS)
	mkdir -p $(dir $@)
	$(CPP) -MMD $(CPPFLAGS) $(HURL_UT_LIBPATH) \
		$(filter-out ut_check,$^) $(GTEST_A) $(HURL_UT_LIBS) -o $@
	-$@
