CC=gcc -Wall -pedantic -std=gnu99

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
        export DYLD_FALLBACK_LIBRARY_PATH=$(GTEST)/lib/.libs
        CFLAGS += -Wno-deprecated-declarations
endif

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
CFLAGS += -Iinclude -fPIC -g3
LIBS = -lssl -lcrypto

all: libhurl.so libhurl.a

ut:
	make -C ut

libhurl.so: $(OBJS)
	$(CC) -v $(CFLAGS) -Os -shared -o libhurl.so $^ $(LIBS)

libhurl.a: $(OBJS)
	ar rvs libhurl.a $(OBJS)

debug: $(OBJS)
	$(CC) $(CFLAGS) -g3 -shared -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f $(OBJS)
	rm -f libhurl.so
	rm -f libhurl.a
