export COMPILER=/usr/bin/gcc -Wall -pedantic -std=gnu99
export GTEST=$(shell pwd)/gmock-1.7.0/gtest
export GMOCK=$(shell pwd)/gmock-1.7.0
export ODIR=$(shell pwd)/bin
export PWD=$(shell pwd)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
        export DYLD_FALLBACK_LIBRARY_PATH=$(GTEST)/lib/.libs
endif

all: build-setup hurl ut

build-setup:
	-mkdir $(ODIR) > /dev/null 2>&1

hurl: FORCE
	make -C src

ut: build-setup FORCE
	make -C ut

clean: FORCE
	rm -rf bin

FORCE:
