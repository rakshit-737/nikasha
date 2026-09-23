# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -O2
LDFLAGS ?=

BUILD   := build
AR      ?= ar

LIB_OBJS := $(BUILD)/hdr.o $(BUILD)/util.o

.PHONY: all clean

all: $(BUILD)/libhdr.a $(BUILD)/hdrcat

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/hdr.o: src/hdr.c include/hdr.h src/util.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -c src/hdr.c -o $@

$(BUILD)/util.o: src/util.c src/util.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -c src/util.c -o $@

$(BUILD)/libhdr.a: $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(BUILD)/hdrcat: tools/hdrcat.c $(BUILD)/libhdr.a | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc tools/hdrcat.c $(BUILD)/libhdr.a $(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD)
