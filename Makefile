CC=gcc
CFLAGS=-std=c99
CLIBS=-lm -lgmp -lcrypto -ljansson

all: auth.o generate_prime.o

auth.o:
	$(CC) -c auth.c -o auth.o $(CFLAGS) $(CLIBS)

generate_prime.o:
	$(CC) generate_prime.c -o generate_prime.o $(CFLAGS) $(CLIBS)
