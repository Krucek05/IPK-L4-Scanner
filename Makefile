CC      = gcc
CFLAGS  = -std=c17 -Wall -Wextra -Wpedantic -D_DEFAULT_SOURCE -D_GNU_SOURCE
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

test: $(TARGET)
	@echo "Running tests..."
	@chmod +x tests/test_nmap_comparison.py
	./tests/test_nmap_comparison.py 127.0.0.1 -i lo
	./tests/test_parsing.sh

clean:
	rm -f $(OBJS) $(TARGET)

NixDevShellName:
	@echo c
