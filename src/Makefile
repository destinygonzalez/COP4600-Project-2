CC = gcc
CFLAGS = -Wall -Wextra -pthread
LDFLAGS = -lcrypto -pthread

all: project2

project2: main.c hash.c b_worker.c hash_functions.c hash.h hash_functions.h
	$(CC) $(CFLAGS) main.c hash.c b_worker.c hash_functions.c $(LDFLAGS) -o project2

test: project2
	./project2 data/common-passwords.txt data/hashes.txt output.txt
	diff data/expected.txt output.txt

clean:
	rm -f project2 output.txt

.PHONY: all test clean
