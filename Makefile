CC=gcc
CFLAGS=-Wall -Wextra -static -O2

all: sender

sender: sender.c

clean:
	rm -f sender
