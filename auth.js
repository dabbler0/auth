(function(window) {

  function hash(str) {
    //Compute the SHA512 hash of a string.
    var shaObj = new jsSHA(str, "TEXT");
    return str2bigInt(shaObj.getHash("SHA-512", "TEXT"), 16);
  }

  //Create a bignum for the large prime modulus that we are going to use:
  var g = 2,
      N = str2bigInt("C0C224E04CBBA802ED96D54963C97BA7FFFFD2A09BCCD2418260E269AD9A6CD954DA16CF662CACD585D957A84F8F76E584788D013E5F52A8034634236E27D57B", 16, 1, 1),
      prime_size = bitSize(N);

  //Function for the first SRP pass:
  function generate_A(N, g) {
    return powMod(g, (a = int2bigInt(randBigInt(bitSize(N), 0))), N);
  }

  //Function for computing the session key:
  function generate_session_key(data) {
    var u = hash(bigInt2str(data.A) + data.B),
        x = hash(data.salt + data.password),
        //Compute (B - kg^x) ^ (a + ux) (the unhashed session key):
        S = powMod(mod(sub(data.B, mult(data.k, powMod(data.g, x, data.N))), data.N), add(data.a, mult(u, x))),
        //Compute hash(S) (the hashed session key):
        K = hash(bigInt2str(S, 16)),
        //Compute a validation the validation hashes for this key:
        M = hash(bigInt2str(add(data.N, data.g), 16) + data.uname + data.salt + bigInt2str(data.A, 16) + bigInt2str(data.B, 16) + bigInt2str(K, 16)),
        V = hash(bigInt2str(data.A, 16) + bigInt2str(M) + bigInt2str(K));
    return {
      key:K,
      client_validator:M
      server_validator:V
    };
  }

  function encrypt_message(message, bf) {
    var checksum = hex_md5(message);
    return {
      guard:bf.encrypt(checksum),
      message:bf.encrypt(message)
    };
  }

  //Set up for use in external things:
  window["generate_A"] = generate_A;
  window["generate_session_key"] = generate_session_key;
  window["encrypt_message"] = encrypt_message;
}(window));
