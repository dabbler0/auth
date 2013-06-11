#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <gmp.h>
#include <string.h>

int main(int n, char* args[]) {
  int random = open("/dev/random", 0);

  mpz_t r;
  mpz_init(r);

  OpenSSL_add_all_digests();

  //Init the cipher context:
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  unsigned char* salt;
  
  read(random, salt, 8);

  //Get the paramters we want for this cipher:
  const EVP_CIPHER *cipher;
  if (!(cipher = EVP_aes_128_ccm())) {
    puts("No cipher");
  }
  const EVP_MD *dgst = NULL;
  if (!(dgst = EVP_get_digestbyname("md5"))) {
    puts("No digest");
  }
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

  EVP_BytesToKey(cipher, dgst, salt, "hello", strlen("hello"), 1, key, iv);

  //Encrypt it:
  EVP_EncryptInit_ex(&ctx, EVP_aes_128_ccm(), NULL,  key, iv);
  char out[1000];
  int outl, templ;
  EVP_EncryptUpdate(&ctx, out, &outl, "asdf asdf asdf", strlen("Hello World"));
  EVP_EncryptFinal_ex(&ctx, out + outl, &templ);
  outl += templ;

  //Output it as hex.
  for (int i = 0; i < outl; ++i) {
    mpz_mul_ui(r, r, 256);
    mpz_add_ui(r, r, (int)out[i]);
  }
  puts(mpz_get_str(NULL, 16, r));
}
