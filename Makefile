CC      = gcc
CFLAGS  = -std=c17 -Wall -Wextra -Wpedantic -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDFLAGS = -lpcap
TARGET  = ipk-L4-scan
SRCS    = $(wildcard src/*.c)
OBJS    = $(SRCS:.c=.o)
HDRS    = $(wildcard src/*.h)

TEST_TARGET = tests/parsing_tests
TEST_SRCS   = tests/test_parsing.c src/L4-scan.c
TEST_CFLAGS = $(CFLAGS) -DUNIT_TEST
TEST_LDFLAGS = -lcriterion

.PHONY: all clean test test-parsing check-criterion NixDevShellName

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

test: test-parsing

test-parsing: check-criterion $(TEST_TARGET)
	@echo "Running Criterion parsing tests..."
	./$(TEST_TARGET)

check-criterion:
	@pkg-config --exists criterion || { \
		exit 1; \
	}

$(TEST_TARGET): $(TEST_SRCS) $(HDRS)
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_SRCS) $(TEST_LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGET)

NixDevShellName:
	@echo c
