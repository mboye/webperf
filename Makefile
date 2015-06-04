CC ?= clang
override CFLAGS += -Wall -pedantic -std=gnu99

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    override CFLAGS += -Wno-deprecated-declarations
else ifeq ($(UNAME_S),Linux)
    WEBPERF_LIBS = -pthread
endif

ifeq ($(DEBUG), yes)
    CFLAGS += -g3
else
    CFLAGS += -Os
endif

HURL_OBJS = $(patsubst %.c, %.o, $(wildcard libhurl/src/*.c))
DNS_OBJS = $(patsubst %.c, %.o, $(wildcard leone-dns-library/src/*.c))
TOOLS_OBJS = $(patsubst %.c, %.o, $(wildcard leone-tools/src/*.c))
WEBPERF_OBJS = $(patsubst %.c, %.o, $(wildcard webperf/src/*.c))
WEBPERF_DEPS = $(HURL_OBJS) $(DNS_OBJS) $(TOOLS_OBJS)

INCLUDES = -I leone-tools/include \
           -I leone-dns-library/include \
           -I libhurl/include \
           -I webperf/include

WEBPERF_LIBS += -lm -lssl -lcrypto

webperf/webperf: .hurl .dns .tools $(WEBPERF_OBJS)
	$(CC) -MMD $(CFLAGS) $(INCLUDES) -o $@ \
		$(WEBPERF_DEPS) $(WEBPERF_OBJS) $(WEBPERF_LIBS)
	@echo
	@echo "Output binary: $@"

.tools: $(TOOLS_OBJS)
	touch $@

.dns: $(DNS_OBJS)
	touch $@

.hurl: $(HURL_OBJS)
	touch $@

%.o: %.c
	$(CC) -MMD $(CFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -f $(wildcard */src/*.o)
	rm -f $(wildcard */src/*.d)
	rm -f webperf/webperf

OBJS=$(wildcard */src/*.c)
-include $(OBJS:%.c=%.d)
