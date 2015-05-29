CC ?= gcc

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    export DYLD_FALLBACK_LIBRARY_PATH=$(GTEST)/lib/.libs
    CFLAGS += -Wno-deprecated-declarations
endif

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
CFLAGS += -Wall -pedantic -std=gnu99 -Iinclude -fPIC
LIBS = -lssl -lcrypto

ifeq ($(DEBUG), YES)
    CFLAGS += -g3
else
    CFLAGS += -Os
endif

all: libhurl.so libhurl.a

ut:
	make -C ut

libhurl.so: $(OBJS)
	$(CC) -v $(CFLAGS) -shared -o libhurl.so $^ $(LIBS)

libhurl.a: $(OBJS)
	ar rvs libhurl.a $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f $(OBJS)
	rm -f libhurl.so
	rm -f libhurl.a
