BUILD_DIR := build
CACHE_DIR := .cache
PLATFORM := $(shell uname -s | tr 'A-Z' 'a-z')
ARCH := $(shell uname -m)

CC := clang
override CFLAGS += -Weverything -Wall -Wextra -pedantic -std=gnu99

CPP := clang++
override CPPFLAGS += -std=c++11 -Wall -pedantic

ifeq ($(DEBUG), yes)
    override CFLAGS += -g3
    override CPPFLAGS += -g3
else
    override CFLAGS += -Os
    override CPPFLAGS += -Os
endif

GMOCK ?= gmock-1.7.0
GTEST ?= $(GMOCK)/gtest
GTEST_A = $(GTEST)/lib/.libs/libgtest.a
GMOCK_A = $(GMOCK)/lib/.libs/libgmock.a

$(info Build directory is '$(BUILD_DIR)')
$(info Cache directory is '$(CACHE_DIR)')

all: webperf

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

include mk/platform/$(PLATFORM).mk
include leone-tools/Dir.mk
include leone-dns-library/Dir.mk
include libhurl/Dir.mk
include webperf/Dir.mk
include mk/*.mk

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean
