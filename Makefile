CC=gcc
CFLAGS=-std=c99
CLIBS=-lm -lgmp -lcrypto -ljansson

all: bin bin/auth.o bin/generate_prime.o

bin:
	mkdir bin

bin/auth.o:
	$(CC) -c auth.c -o bin/auth.o $(CFLAGS) $(CLIBS)

bin/generate_prime.o:
	$(CC) generate_prime.c -o bin/generate_prime.o $(CFLAGS) $(CLIBS)
