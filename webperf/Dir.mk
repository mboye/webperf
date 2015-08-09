WEBPERF_SRCS = $(wildcard webperf/src/*.c)
WEBPERF_OBJS = $(addprefix $(BUILD_DIR)/, $(patsubst %.c, %.o, $(WEBPERF_SRCS)))
WEBPERF_INCLUDES = -I webperf/include \
                   -I leone-dns-library/include \
                   -I libhurl/include \
                   -I leone-tools/include

WEBPERF_LIBS += -lm -lssl -lcrypto $(LIB_PTHREAD)

$(WEBPERF_OBJS): $(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) -MMD $(CFLAGS) $(WEBPERF_INCLUDES) -c $< -o $@

$(BUILD_DIR)/bin/webperf: $(HURL_OBJS) $(DNS_OBJS) $(TOOLS_OBJS) $(WEBPERF_OBJS)
	mkdir -p $(dir $@)
	$(CC) -MMD $(CFLAGS) -o $@ $^ $(WEBPERF_LIBS)
	@echo
	@echo "Output binary: $@"

webperf: $(BUILD_DIR)/bin/webperf

.PHONY: webperf

include webperf/ft/Dir.mk
