# Recent Mac OS X versions deprecate OpenSSL, overruling that
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
        CCFLAGS += -Wno-deprecated-declarations
endif

#COMPILER=/usr/bin/gcc -std=gnu99 -pedantic -Wall $(CCFLAGS)
COMPILER=/usr/bin/clang -std=gnu99 -pedantic -Wall -Weverything $(CCFLAGS)

all: release

release: hurl_core.c hurl_parse.c hurl_core.h 
	$(COMPILER) -Os -shared -fPIC -o libhurl.so *.c -lm -pthread -lssl -lcrypto

debug: 	hurl_core.c hurl_parse.c hurl_core.h 
	$(COMPILER) -g3 -shared -fPIC -o libhurl.so *.c -lm -pthread -lssl -lcrypto

release-static: hurl_core.c hurl_parse.c hurl_core.h
	$(COMPILER) -c hurl_core.c -o hurl_core.o
	$(COMPILER) -c hurl_parse.c -o hurl_parse.o
	ar rvs libhurl.a hurl_core.o hurl_parse.o
    
debug-static: hurl_core.c hurl_parse.c hurl_core.h
	$(COMPILER) -g3 -c hurl_core.c -o hurl_core.o
	$(COMPILER) -g3 -c hurl_parse.c -o hurl_parse.o
	ar rvs libhurl.a hurl_core.o hurl_parse.o

clean: FORCE
	rm -f libhurl.so libhurl.a *.o

FORCE:
