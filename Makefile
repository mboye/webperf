export COMPILER=/usr/bin/gcc -Wall -pedantic -std=gnu99
export GTEST=$(shell pwd)/gmock-1.7.0/gtest
export GMOCK=$(shell pwd)/gmock-1.7.0
export ODIR=$(shell pwd)/bin
export PWD=$(shell pwd)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
        export DYLD_FALLBACK_LIBRARY_PATH=$(GTEST)/lib/.libs
        CCFLAGS += -Wno-deprecated-declarations
endif

all: build-setup release

build-setup:
	-mkdir $(ODIR) > /dev/null 2>&1

ut: build-setup FORCE
	make -C ut

clean: FORCE
	rm -rf bin

release: src/hurl_core.c src/hurl_parse.c include/hurl.h 
	$(COMPILER) $(CCFLAGS) -Os -shared -fPIC -o bin/libhurl.so src/*.c -Iinclude -lm -pthread -lssl -lcrypto -DNDEBUG

debug: hurl_core.c hurl_parse.c hurl.h 
	$(COMPILER) -g3 -shared -fPIC -o $(ODIR)/libhurl.so *.c -lm -pthread -lssl -lcrypto

release-static: hurl_core.c hurl_parse.c hurl.h
	$(COMPILER) -c hurl_core.c -o hurl.o
	$(COMPILER) -c hurl_parse.c -o hurl_parse.o
	ar rvs $(ODIR)/libhurl.a hurl.o hurl_parse.o
    
debug-static: hurl_core.c hurl_parse.c hurl.h
	$(COMPILER) -g3 -c hurl_core.c -o hurl.o
	$(COMPILER) -g3 -c hurl_parse.c -o hurl_parse.o
	ar rvs $(ODIR)/libhurl.a hurl.o hurl_parse.o

clean: FORCE
	rm -f $(ODIR) $(PWD)/src/*.o

FORCE:
