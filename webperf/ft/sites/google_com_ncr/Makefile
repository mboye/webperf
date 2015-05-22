include ../Makefile.inc
URL=https://www.google.com/ncr

all: pre-test test post-test

pre-test:
	@echo Seting up test
	test -d tmp || mkdir tmp
	$(URLS_UPDATE) "$(URL)"

test:
	@echo Running test
	$(WEBPERF) webperf.conf > "tmp/webperf.stdout" 2>"tmp/webperf.stderr"

post-test:
	@echo Checking test results
