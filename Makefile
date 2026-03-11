CC      = gcc
CFLAGS  = -std=c17 -Wall -Wextra -Wpedantic
LDFLAGS = -lpcap
TARGET  = ipk-L4-scan
SRCS    = $(wildcard src/*.c)
OBJS    = $(SRCS:.c=.o)
HDRS    = $(wildcard src/*.h)

.PHONY: all clean test NixDevShellName

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

test:
	@echo "No tests implemented yet."

clean:
	rm -f $(OBJS) $(TARGET)

NixDevShellName:
	@echo c
