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
TEST_SCRIPT   = $(TEST_DIR)/test_parsing.sh

TEST_CFLAGS = $(CFLAGS) -DUNIT_TEST
TEST_LDFLAGS = -lcriterion $(LDFLAGS)

.PHONY: all clean test test-functional NixDevShellName

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

test: all
	@echo "--- 1. Running Bash Parsing Script ---"
	chmod +x $(TEST_SCRIPT)
	./$(TEST_SCRIPT)
	
	@echo -e "\n--- 2. Running Criterion Parsing Unit Tests ---"
	$(MAKE) $(PARSING_BIN)
	./$(PARSING_BIN)
	
	@echo -e "\n--- 3. Running Exit Code Functional Tests ---"
	$(MAKE) $(EXIT_CODE_BIN)
	sudo ./$(EXIT_CODE_BIN)

test_exit_codes: all
	$(MAKE) $(EXIT_CODE_BIN)
	sudo ./$(EXIT_CODE_BIN)

# --- Test Compilation ---

$(PARSING_BIN): $(TEST_DIR)/test_parsing.c src/L4-scan.c
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

$(EXIT_CODE_BIN): $(TEST_DIR)/exit_codes.c src/L4-scan.c
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

$(TEST_TARGET): $(TEST_SRCS) $(HDRS)
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_SRCS) $(TEST_LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGET) $(PARSING_BIN) $(EXIT_CODE_BIN)

NixDevShellName:
	@echo c
