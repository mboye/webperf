ut_coverage: CFLAGS += -fprofile-arcs -ftest-coverage
ut_coverage: CPPFLAGS += -fprofile-arcs -ftest-coverage

COV_DIRS = $(addprefix -d , $(wildcard $(BUILD_DIR)/*/src))
COV_STRIP = tools/strip-coverage-info.py
UT_COV_INFO=$(BUILD_DIR)/ut_coverage.info
UT_COV_REPORT=$(BUILD_DIR)/ut_coverage
UT_GENHTML_LOG=$(BUILD_DIR)/genhtml.log

ut_coverage: clean $(BUILD_DIR)/bin/libhurl_ut $(BUILD_DIR)/bin/leone_tools_ut
	lcov --capture --no-recursion $(COV_DIRS) -b . -o $(UT_COV_INFO)
	$(COV_STRIP) $(shell pwd) $(UT_COV_INFO)
	genhtml --prefix $(shell pwd) $(UT_COV_INFO) -o $(UT_COV_REPORT) | tee $(UT_GENHTML_LOG)
	./tools/coverage-percentage.py $(UT_GENHTML_LOG) > $(UT_COV_REPORT)/coverage_percentage.csv


.PHONY: ut_coverage
