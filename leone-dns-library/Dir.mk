DNS_SRCS = $(wildcard leone-dns-library/src/*.c)
DNS_OBJS = $(addprefix $(BUILD_DIR)/, $(patsubst %.c, %.o, $(DNS_SRCS)))
DNS_INCLUDES = -I leone-dns-library/include \
               -I leone-tools/include

$(DNS_OBJS): $(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) -MMD $(CFLAGS) $(DNS_INCLUDES) -c $< -o $@
