CC      = gcc
CFLAGS  = -std=c17 -Wall -Wextra -pedantic
TARGET  = ipk-L4-scan
SRCS    = src/L4-scan.c

.PHONY: all clean NixDevShellName

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

NixDevShellName:
	@echo c
