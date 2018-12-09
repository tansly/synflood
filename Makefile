CC=gcc
CFLAGS=-Wall -Wextra -static -O2

all: sender.out

sender.out: sender.c
	$(CC) $(CFLAGS) sender.c -o sender.out

clean:
	rm -f *.out
