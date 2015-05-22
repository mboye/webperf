CC ?= gcc
CFLAGS += -Wall -pedantic -std=gnu99
INCLUDES = -I../leone-tools \
           -I../leone-dns-library \
           -I../libhurl/include

LD_PATHS = -L../leone-tools \
           -L../leone-dns-library \
		   -L../libhurl

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    export DYLD_FALLBACK_LIBRARY_PATH=$(GTEST)/lib/.libs
    CFLAGS += -Wno-deprecated-declarations
endif

ifeq ($(DEBUG), YES)
	CFLAGS += -g3
else
	CFLAGS += -Os
endif
