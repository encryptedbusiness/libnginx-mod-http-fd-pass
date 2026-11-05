CC ?= cc
CFLAGS ?= -std=c11 -O1 -g -Wall -Wextra -Werror -Wcast-align \
          -fsanitize=address,undefined -fno-omit-frame-pointer
INC := -I../../src

all: test_core

test_core: test_core.c ../../src/fd_pass_core.c ../../src/fd_pass_core.h
	$(CC) $(CFLAGS) $(INC) test_core.c ../../src/fd_pass_core.c -o $@

check: test_core
	./test_core

clean:
	rm -f test_core

.PHONY: all check clean
