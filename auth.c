#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>
#include <time.h>
#include <jansson.h>
#include <openssl/sha.h>
#include <gmp.h>

#define SALT 3
#define PASSWORD_VERIFIER 2
#define MUL_PARAM 3
#define GENERATOR 2
#define N_STRING "B62AB56BCAD9E423C6F871DC6198C9F28B4672A8D9BF219693359435181E17BD1E225FD5E178968D6E074AFF175F435A4F729C564B42AA5EC68DF7FEAC1C02F226F882ED570D25BEAA0BA9ADEAE7A7BCC83DF8EEB24EF89D4370A20486416C9E5B3C351243A3A178211993053491C3F13399E4E77C4DF40DE0397EE315F847B3"

mpz_t N; //A large safe prime
int devrand; //A file descriptor for random entropy collection

struct modulus_record {
  mpz_t N;
  mpz_t g;
};

void hash(mpz_t r, const char* str) {
  //Perform the hash:
  unsigned char digest[SHA512_DIGEST_LENGTH];
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, str, strlen(str));
  SHA512_Final(digest, &ctx);

  //Convert the hash string to a big integer:
  for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
    mpz_mul_ui(r, r, 256);
    mpz_add_ui(r, r, (int)digest[i]);
  }
}

int lookup_hex_column(mpz_t r, sqlite3* db, const char* uname, int col) {
  sqlite3_stmt* stmt;
  int prep_result = sqlite3_prepare_v2(db, "SELECT * FROM users WHERE uname=?", 33, &stmt, NULL);
  
  //Catch an error if one exists:
  if (prep_result != SQLITE_OK) return prep_result;

  //Bind a value to the uname query
  prep_result = sqlite3_bind_text(stmt, 1, uname, -1, SQLITE_TRANSIENT);
  
  //Error handling:
  if (prep_result != SQLITE_OK) return prep_result;
  
  int step_result;
  
  //Wait until the database is open for writing:
  struct timespec wait_time;
  wait_time.tv_sec = 0;
  wait_time.tv_nsec = 1000000;
  while ((step_result = sqlite3_step(stmt)) == SQLITE_BUSY) nanosleep(&wait_time, NULL);

  if (step_result == SQLITE_ROW || step_result == SQLITE_DONE) {
    //We are good to read out the salt value:
    mpz_set_str(r, sqlite3_column_text(stmt, col), 16);
  }
  //Error handling:
  else return step_result;

  //Finalize the statement:
  sqlite3_finalize(stmt);

  return SQLITE_OK;
}

unsigned long int entropy(int place) {
  //Read off an integer from a random entropy generator (usually /dev/random or /dev/urandom):
  int r;
  read(place, &r, sizeof(int));
  return r;
}

int srp_first_pass(mpz_t r, sqlite3* db, const char* uname, mpz_t A, int ent, struct modulus_record modulus, int (*output)(const char*)) {
  /*
    Generate a B value:
  */

  //Declare bignums for b, B, v, and kv.
  mpz_t b, B, v, kv;
  mpz_init(b);
  mpz_init(B);
  mpz_init(v);
  mpz_init(kv);

  //Initialize the random number generator:
  gmp_randstate_t state;
  gmp_randinit_mt(state);
  gmp_randseed_ui(state, entropy(ent));

  //Compute b:
  mpz_urandomm(b, state, modulus.N);

  //Compute g^b and set r to this:
  mpz_powm_sec(B, modulus.g, b, modulus.N);

  //Look up the password verifier and handle errors:
  int lookup_result;
  if ((lookup_result = lookup_hex_column(v, db, uname, PASSWORD_VERIFIER)) != SQLITE_OK) return lookup_result;
  
  //Compute kv:
  mpz_mul_ui(kv, v, MUL_PARAM);

  //We are now done with kv:
  mpz_clear(kv);

  //Add to B:
  mpz_add(B, B, kv);
  mpz_mod(B, B, modulus.N);

  /*
    Find the user's salt:
  */
  mpz_t s;
  mpz_init(s);
  lookup_hex_column(s, db, uname, SALT);

  /*
    JSON encode and send to the client:
  */

  json_t* out = json_pack("{ssss}", "salt", mpz_get_str(NULL, 16, s), "B", mpz_get_str(NULL, 16, B));
  
  output(json_dumps(out, JSON_COMPACT));
  
  //We are now done with s:
  mpz_clear(s);

  /*
    Compute the session key that we have just exchanged:
  */
  mpz_t S, u;
  mpz_init(u);
  mpz_init(S);
  
  //Compute u as hash(A, B):
  hash(u, strcat(mpz_get_str(NULL, 16, A), mpz_get_str(NULL, 16, B)));

  //Compute v^u:
  mpz_powm(S, v, u, modulus.N);

  //Compute Av^u:
  mpz_mul(S, S, A);
  
  //Compute (Av^u)^b:
  mpz_powm(S, S, b, modulus.N);
  
  //Output r:
  hash(r, mpz_get_str(NULL, 16, S));

  //We are now done with S, u, B, and b:
  mpz_clear(S);
  mpz_clear(u);
  mpz_clear(B);
  mpz_clear(b);
}
