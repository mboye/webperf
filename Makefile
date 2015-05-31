include Makefile.inc

all: webperf

webperf: libhurl.so libleonedns.so libleonetools.so
	make -C webperf

libhurl.so:
	test -d libhurl
	make -C libhurl

libleonedns.so: libleonetools.so
	make -C leone-dns-library

libleonetools.so:
	make -C leone-tools

functional-test:
	make -C webperf functional-test

gerrit-check: clean webperf functional-test

clean:
	make -C leone-tools clean
	make -C leone-dns-library clean
	make -C webperf clean
	test -d libhurl && make -C libhurl clean
