REVIEW_COMMENTS := $(BUILD_DIR)/review-comments.txt

check_whitespace: $(BUILD_DIR)
	tools/gerrit/detect-trailing-whitespace.sh > "$(REVIEW_COMMENTS)"

check_cppcheck: $(BUILD_DIR)
	cppcheck --enable=all --inconclusive --xml --xml-version=2 \
		*/src */include 1>/dev/null 2> $(BUILD_DIR)/cppcheck.xml

check_ut_coverage:
	make -j 4 BUILD_DIR=ut_coverage_build ut_coverage > /dev/null 2>&1

check_ft: webperf_ft

.PHONY: check_whitespace check_cppcheck check_ut_coverage check_build check_ft \
	check_gerrit gerrit_review
