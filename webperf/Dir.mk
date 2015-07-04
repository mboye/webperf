WEBPERF_SRCS = $(wildcard webperf/src/*.c)
WEBPERF_OBJS = $(patsubst %.c, %.o, $(WEBPERF_SRCS))
WEBPERF_OBJS_EXT = $(HURL_OBJS) $(DNS_OBJS) $(TOOLS_OBJS)

TRASH += webperf/webperf
TRASH += $(WEBPERF_OBJS)
TRASH += $(patsubst %.c, %.d, $(WEBPERF_SRCS))

WEBPERF_LIBS += -lm -lssl -lcrypto

webperf/webperf: .hurl .dns .tools $(WEBPERF_OBJS)
	$(CC) -MMD $(CFLAGS) $(INCLUDES) -o $@ \
		$(WEBPERF_OBJS_EXT) $(WEBPERF_OBJS) $(WEBPERF_LIBS)
	@echo
	@echo "Output binary: $@"

-include $(patsubst %.c, %.d, $(WEBPERF_SRCS))
