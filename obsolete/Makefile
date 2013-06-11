CC=gcc
CFLAGS=-g -std=c99
CLIBS=-lm -lgmp -lcrypto -ljansson

all: bin bin/auth.o bin/generate_prime.o bin/aes_test.o

bin:
	mkdir bin

bin/auth.o:
	$(CC) -c auth.c -o bin/auth.o $(CFLAGS) $(CLIBS)

bin/generate_prime.o:
	$(CC) generate_prime.c -o bin/generate_prime.o $(CFLAGS) $(CLIBS)

bin/aes_test.o:
	$(CC) aes_test.c -o bin/aes_test.o $(CFLAGS) $(CLIBS)
