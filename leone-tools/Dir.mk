TOOLS_SRCS = $(wildcard leone-tools/src/*.c)
TOOLS_OBJS = $(patsubst %.c, %.o, $(TOOLS_SRCS))

TRASH += $(TOOLS_OBJS)
TRASH += $(patsubst %.c, %.d, $(TOOLS_SRCS))

.tools: $(TOOLS_OBJS)
	touch $@

-include $(patsubst %.c, %.d, $(TOOLS_SRCS))
