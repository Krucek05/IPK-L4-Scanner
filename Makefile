CC      = gcc
CFLAGS  = -std=c17 -Wall -Wextra -Wpedantic -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDFLAGS = -lpcap
TARGET  = ipk-L4-scan

SRCS    = $(wildcard src/*.c)
OBJS    = $(SRCS:.c=.o)
HDRS    = $(wildcard src/*.h)

TEST_DIR = tests

PARSING_BIN   = $(TEST_DIR)/parsing_tests
EXIT_CODE_BIN = $(TEST_DIR)/exit_codes_tests
NETWORK_BIN   = $(TEST_DIR)/network_tests
TEST_SCRIPT   = $(TEST_DIR)/test_parsing.sh

TEST_CFLAGS  = $(CFLAGS) -DUNIT_TEST
TEST_LDFLAGS = -lpcap -lcriterion
TEST_SRCS    = src/L4-scan.c src/tcp_scan.c src/udp_scan.c src/addr_helpers.c

.PHONY: all clean test test-functional NixDevShellName

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

test: all
	@echo "--- 1. Running Bash Parsing Script ---"
	sudo ./$(TEST_SCRIPT)
	
	@echo -e "\n--- 2. Running Criterion Parsing Unit Tests ---"
	$(MAKE) $(PARSING_BIN)
	sudo ./$(PARSING_BIN)
	
	@echo -e "\n--- 3. Running Exit Code Tests ---"
	$(MAKE) $(EXIT_CODE_BIN)
	sudo ./$(EXIT_CODE_BIN)

	@echo -e "\n--- 4. Running Network Errors Tests ---"
	$(MAKE) $(NETWORK_BIN)
	sudo ./$(NETWORK_BIN)

test_exit_codes: all
	$(MAKE) $(EXIT_CODE_BIN)
	sudo ./$(EXIT_CODE_BIN)

# --- Test Compilation ---

$(PARSING_BIN): $(TEST_DIR)/test_parsing.c $(TEST_SRCS)
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

$(EXIT_CODE_BIN): $(TEST_DIR)/exit_codes.c $(TEST_SRCS)
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

$(NETWORK_BIN): $(TEST_DIR)/network_errors.c $(TEST_SRCS)
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

$(TEST_TARGET): $(TEST_SRCS) $(HDRS)
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_SRCS) $(TEST_LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGET) $(PARSING_BIN) $(EXIT_CODE_BIN) $(NETWORK_BIN)

NixDevShellName:
	@echo c
