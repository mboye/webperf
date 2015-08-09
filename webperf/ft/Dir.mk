PHANTOMJS = "$(CACHE_DIR)/bin/phantomjs"
FT_CASES = $(wildcard webperf/ft/cases/*)
FT_WEBPERF = $(CURDIR)/webperf/ft

ft_webperf_run = cd $(CURDIR)/$1 && \

ft_setup: $(BUILD_DIR)/ft phantomjs

$(BUILD_DIR)/ft:
	mkdir "$@"

webperf_ft: webperf ft_setup
	ROOT=$(CURDIR) \
		BUILD_DIR=$(BUILD_DIR) \
		CACHE_DIR=$(CACHE_DIR) \
		webperf/ft/run-all-tests.sh
