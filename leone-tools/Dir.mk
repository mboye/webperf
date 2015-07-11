TOOLS_SRCS = $(wildcard leone-tools/src/*.c)
TOOLS_OBJS = $(addprefix $(BUILD_DIR)/, $(patsubst %.c, %.o, $(TOOLS_SRCS)))
TOOLS_INCLUDES = -I leone-tools/include

$(TOOLS_OBJS): $(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) -MMD $(CFLAGS) $(TOOLS_INCLUDES) -c $< -o $@

include leone-tools/ut/Dir.mk
