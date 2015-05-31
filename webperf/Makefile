include ../Makefile.inc

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
DEP_OBJS += $(wildcard ../libhurl/src/*.o)
DEP_OBJS += $(wildcard ../leone-tools/src/*.o)
DEP_OBJS += $(wildcard ../leone-dns-library/src/*.o)

INCLUDES = -I include \
           -I ../leone-dns-library/include \
           -I ../leone-tools/include \
           -I ../libhurl/include

LIBS = -lm \
       -lssl \
       -lcrypto \

ifeq ($(UNAME_S),Linux)
    LIBS += -pthread
endif

all: leone-webperf

leone-webperf: $(OBJS) libleonetools.a libleonedns.a libhurl.a
	$(CC) $(INCLUDES) $(LD_PATHS) -o $@ $(OBJS) $(DEP_OBJS) $(LIBS)

libleonetools.a:
	test -f ../leone-tools/libleonetools.a

libleonedns.a:
	test -f ../leone-dns-library/libleonedns.a

libhurl.a:
	test -f ../libhurl/libhurl.a

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $^

functional-test: FORCE
	$(foreach test, $(wildcard ./ft/test_*), $(test)/test.sh)

clean:
	rm -f $(OBJS)
	rm -f leone-webperf

FORCE:

