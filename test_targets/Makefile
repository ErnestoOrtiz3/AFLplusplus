# Makefile for AFL++ scheduler test targets

CC = ../afl-clang-fast
CFLAGS += -g -O2 -Wall -Wextra

all: scheduler_test

scheduler_test: scheduler_test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f scheduler_test

.PHONY: all clean
