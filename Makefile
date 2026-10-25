# ExiFS Makefile
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
FUSE_CFLAGS := $(shell pkg-config --cflags fuse3 2>/dev/null)
FUSE_LIBS   := $(shell pkg-config --libs fuse3 2>/dev/null)

all: mkexifs fsck.exifs exifs_fuse

mkexifs: src/mkexifs.c src/exifs_util.c include/exifs.h
	$(CC) $(CFLAGS) -Iinclude src/mkexifs.c src/exifs_util.c -o $@

fsck.exifs: src/fsck.exifs.c src/exifs_util.c include/exifs.h
	$(CC) $(CFLAGS) -Iinclude src/fsck.exifs.c src/exifs_util.c -o $@

exifs_fuse: src/exifs_fuse.c src/exifs_util.c include/exifs.h
	$(CC) $(CFLAGS) -D_FILE_OFFSET_BITS=64 -Iinclude \
		src/exifs_fuse.c src/exifs_util.c -o $@ \
		$(FUSE_CFLAGS) $(FUSE_LIBS) -lpthread

test:
	python3 tests/test_roundtrip.py

clean:
	rm -f mkexifs fsck.exifs exifs_fuse

.PHONY: all test clean
