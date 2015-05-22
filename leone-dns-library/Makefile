include ../Makefile.inc

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
INCLUDES = -I include \
		   -I ../leone-tools/include

LIBS = -lm \
       -lleonetools

all: libleonedns.so libleonedns.a

libleonedns.so: $(OBJS)
	$(CC) -shared -fPIC $(LD_PATHS) -o $@ $^ $(LIBS)

libleonedns.a: $(OBJS)
	ar rvs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -c -o $@ $^

clean:
	rm -f $(OBJS)
	rm -f libleonedns.so
	rm -f libleonedns.a
