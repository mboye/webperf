HURL_SRCS = $(wildcard libhurl/src/*.c)
HURL_OBJS = $(patsubst %.c, %.o, $(HURL_SRCS))

TRASH += $(HURL_OBJS)
TRASH += $(patsubst %.c, %.d, $(HURL_SRCS))

.hurl: $(HURL_OBJS)
	touch $@

-include $(patsubst %.c, %.d, $(HURL_SRCS))
include libhurl/ut/Dir.mk
