HURL_SRCS = $(wildcard libhurl/src/*.c)
HURL_OBJS = $(addprefix $(BUILD_DIR)/, $(patsubst %.c, %.o, $(HURL_SRCS)))
HURL_INCLUDES = -I libhurl/include

$(HURL_OBJS): $(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) -MMD $(CFLAGS) $(HURL_INCLUDES) -c $< -o $@

include libhurl/ut/Dir.mk
