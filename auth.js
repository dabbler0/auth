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
  function authenticate(username, password, target, callback) {
    var A, a;
    $.ajax({
      "url":target,
      data:{
        username:username,
        random:bigInt2str((A = powMod(g, (a = int2bigInt(randBigInt(prime_size, 0))), N)), 16);
      },
      dataType:"json",
      success:function(data) {
        var B = str2bigInt(data.B, 16),
            u = hash(bigInt2str(A) + data.B),
            x = hash(data.salt + password),
            //Compute (B - kg^x) ^ (a + ux) (the unhashed session key):
            S = powMod(mod(sub(B, mult(k, powMod(g, x, N))), N), add(a, mult(u, x)),
            //Compute hash(S) (the hashed session key):
            K = hash(bigInt2str(S));
        //Execute the callback function on K.
        callback(K);
      }
    });
  }

  //Set up for use in external things:
  window["authenticate"] = authenticate;
}(window));
