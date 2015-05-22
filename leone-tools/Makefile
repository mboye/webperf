include ../Makefile.inc
SRCS = $(wildcard src/*.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
LIBS = -lm
INCLUDES = -I include

all: libleonetools.so libleonetools.a

libleonetools.so: $(OBJS)
	$(CC) -shared -fPIC -o $@ $^ $(LIBS)

libleonetools.a: $(OBJS)
	ar rvs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -c -o $@ $^

clean:
	rm -f $(OBJS)
	rm -f libleonetools.so
	rm -f libleonetools.a
