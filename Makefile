CC=gcc
CFLAGS=-std=c99
CLIBS=-lm -lgmp -lcrypto -ljansson

all: auth.o

auth.o:
	$(CC) $(CFLAGS) $(CLIBS) -c auth.c -o auth.o
