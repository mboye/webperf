GCC=/usr/bin/gcc -std=gnu99 -pedantic -Wall

all: release

release: hurl_core.c hurl_parse.c hurl_core.h 
	$(GCC)  -Os -Wall -pedantic -shared -fPIC -o libhurl.so *.c -lm -pthread -lssl -lcrypto

debug: 	hurl_core.c hurl_parse.c hurl_core.h 
	$(GCC) -g3 -Wall -pedantic -shared -fPIC -o libhurl.so *.c -lm -pthread -lssl -lcrypto

clean: FORCE
	rm -f libhurl.so
	
FORCE:
