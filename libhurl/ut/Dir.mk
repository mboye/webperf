UT_SRCS = $(wildcard libhurl/ut/*.cpp)
UT_OBJS = $(patsubst %.cpp, %.obj, $(UT_SRCS))
UT_DEPS = $(patsubst %.cpp, %.d, $(UT_SRCS))

TRASH += $(UT_OBJS)
TRASH += $(UT_DEPS)
TRASH += libhurl/ut/libhurl_ut

UT_INCLUDES = -I libhurl/include \
              -I $(GTEST)/include

UT_LIBS = -lssl -lcrypto

libhurl/ut/libhurl_ut: $(HURL_OBJS) $(UT_OBJS)
	$(CPP) -MMD $(CPPFLAGS) $(UT_INCLUDES) $(UT_LIBPATH) -o $@ \
		$(HURL_OBJS) $(UT_OBJS) $(GTEST_A) $(UT_LIBS)
	$@

-include $(patsubst %.cpp, %.d, $(UT_SRCS))
