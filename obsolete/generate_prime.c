#include <stdio.h>
#include <stdlib.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

#define TRUE 1

int main(int n, char* args[]) {
  DH *prime = DH_generate_parameters(1024, 2, NULL, NULL);
  printf("%s\n", BN_bn2hex(prime->p));
}
