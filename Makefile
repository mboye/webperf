CC := clang
override CFLAGS += -Wall -Wextra -pedantic -std=gnu99

CPP := clang++
override CPPFLAGS += -Wall -pedantic

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    override CFLAGS += -Wno-deprecated-declarations
else ifeq ($(UNAME_S),Linux)
    WEBPERF_LIBS = -pthread
endif

ifeq ($(DEBUG), yes)
    override CFLAGS += -g3
    override CPPFLAGS += -g3
else
    override CFLAGS += -Os
    override CPPFLAGS += -Os
endif

GMOCK=gmock-1.7.0
GTEST=$(GMOCK)/gtest
GTEST_A=$(GTEST)/lib/.libs/libgtest.a
GMOCK_A=$(GMOCK)/lib/.libs/libgmock.a

all: webperf/webperf

include leone-tools/Dir.mk
include leone-dns-library/Dir.mk
include libhurl/Dir.mk
include webperf/Dir.mk

INCLUDES = -I leone-tools/include \
           -I leone-dns-library/include \
           -I libhurl/include \
           -I webperf/include

.ut-setup:
	wget -c https://googlemock.googlecode.com/files/gmock-1.7.0.zip
	unzip gmock-1.7.0.zip
	cd gmock-1.7.0 && \
	./configure CXX="clang++ -std=c++11 -stdlib=libc++ -DGTEST_USE_OWN_TR1_TUPLE=1" && \
	make
	touch $@

%.o: %.c
	$(CC) -MMD $(CFLAGS) $(INCLUDES) -c -o $@ $<

%.obj: %.cpp
	$(CPP) -MMD $(CPPFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -f $(TRASH)
