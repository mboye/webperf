GCC=/usr/bin/gcc -std=gnu99 -pedantic -Wall

all: release

release: hurl_core.c hurl_parse.c hurl_core.h 
	$(GCC) -Os -shared -fPIC -o libhurl.so *.c -lm -pthread -lssl -lcrypto

debug: 	hurl_core.c hurl_parse.c hurl_core.h 
	$(GCC) -g3 -shared -fPIC -o libhurl.so *.c -lm -pthread -lssl -lcrypto

release-static: hurl_core.c hurl_parse.c hurl_core.h
	$(GCC) -c hurl_core.c -o hurl_core.o
	$(GCC) -c hurl_parse.c -o hurl_parse.o
	ar rvs libhurl.a hurl_core.o hurl_parse.o
    
debug-static: hurl_core.c hurl_parse.c hurl_core.h
	$(GCC) -g3 -c hurl_core.c -o hurl_core.o
	$(GCC) -g3 -c hurl_parse.c -o hurl_parse.o
	ar rvs libhurl.a hurl_core.o hurl_parse.o

clean: FORCE
	rm -f libhurl.so libhurl.a *.o
	
FORCE:
