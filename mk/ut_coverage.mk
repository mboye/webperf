ut_coverage: CFLAGS += -fprofile-arcs -ftest-coverage
ut_coverage: CPPFLAGS += -fprofile-arcs -ftest-coverage

COV_SRC_DIRS = leone-tools/src \
               libhurl/src
COV_PARAMS = $(addprefix -d $(BUILD_DIR)/, $(COV_SRC_DIRS))
COV_STRIP = tools/strip-coverage-info.py
UT_COV_INFO=$(BUILD_DIR)/ut_coverage.info
UT_COV_REPORT=$(BUILD_DIR)/ut_coverage
UT_GENHTML_LOG=$(BUILD_DIR)/genhtml.log

# gcov does not work with clang on Linux
ifeq ($(PLATFORM), linux)
ut_coverage: CC=gcc
ut_coverage: CPP=g++
endif

ut_coverage: clean webperf $(BUILD_DIR)/bin/libhurl_ut $(BUILD_DIR)/bin/leone_tools_ut
	lcov --capture --ignore-errors gcov --no-recursion $(COV_PARAMS) -b . \
		-o $(UT_COV_INFO)

	$(COV_STRIP) $(shell pwd) $(UT_COV_INFO)

	genhtml --prefix $(shell pwd) $(UT_COV_INFO) -o $(UT_COV_REPORT) | \
		tee $(UT_GENHTML_LOG)

	./tools/coverage-percentage.py \
		$(UT_GENHTML_LOG) > $(BUILD_DIR)/ut_coverage.csv

.PHONY: ut_coverage
