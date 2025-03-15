# Makefile for adversarial/ directory

CC := gcc
CFLAGS := -Wall -Wextra -Iinclude -Og -g
LDFLAGS :=
SRC_DIR := src
BUILD_DIR := build

# Common source files used by all samples
COMMON_SRC := $(SRC_DIR)/malware.c \
			  $(SRC_DIR)/utils.c \
			  $(SRC_DIR)/pmparser.c

# Object files built from the common source files
COMMON_OBJ := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(COMMON_SRC))

# Find all sample_*.c in src and produce a corresponding binary in build/
SAMPLE_SRCS := $(wildcard $(SRC_DIR)/sample_*.c)
SAMPLE_BINS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%, $(SAMPLE_SRCS))

.PHONY: all clean

# Default target: build all sample binaries
all: $(SAMPLE_BINS)

# Rule to build each sample binary from its .c + the common object files
$(BUILD_DIR)/%: $(SRC_DIR)/%.c $(COMMON_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(LDFLAGS)

# Rule to build the common object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Create the build/ directory if not present
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR)
