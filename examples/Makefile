# Recent Mac OS X versions deprecate OpenSSL, overruling that
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
        CCFLAGS += -Wno-deprecated-declarations
endif

COMPILER=/usr/bin/gcc -pedantic -Wall $(CCFLAGS)
#COMPILER=/usr/bin/clang -std=gnu99 -pedantic -Wall -Weverything $(CCFLAGS)

all: libhurl example1

libhurl: FORCE
	make -C .. all

libhurl-debug: FORCE
	make -C .. debug

example1: example1.c
	$(COMPILER) -o example1 example1.c -lhurl -I".." -L".."
	@echo
	@echo "How to run example: LD_LIBRARY_PATH=.. ./example1"
	@echo

clean: FORCE
	rm -f example1 

FORCE:
