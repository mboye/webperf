DNS_SRCS = $(wildcard leone-dns-library/src/*.c)
DNS_OBJS = $(patsubst %.c, %.o, $(DNS_SRCS))

TRASH += $(DNS_OBJS)
TRASH += $(patsubst %.c, %.d, $(DNS_SRCS))

.dns: $(DNS_OBJS)
	touch $@

-include $(patsubst %.c, %.d, $(DNS_SRCS))
