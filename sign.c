#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

#include <openssl/sha.h>
#include <sys/types.h>


#include "public.h"

SHA256_CTX sha_ctx;

void hash_input(BIGNUM* data)
{
  size_t len = BN_num_bytes(data);
  unsigned char *buf = OPENSSL_malloc(len);
  BN_bn2bin(data, buf);
	SHA256_Update(&sha_ctx, buf, len);
  OPENSSL_free(buf);
}

struct sign_struct sign(struct y_struct y, struct membership_struct membership)
{
  struct sign_struct sign;
  struct hash_struct hash;
  hash = init_hash();
  sign = init_sign();
  BN_CTX* ctx= BN_CTX_new();
  BIGNUM* one = BN_new();
  BN_one(one);
  BIGNUM* bn_val = BN_new();
  BIGNUM* bn_val1 = BN_new();
  BIGNUM* bn_val2 = BN_new();
  BIGNUM* w = BN_new();
  uint64_t int_temp;
  BIGNUM* invT1 = BN_new();
  BIGNUM* invT2 = BN_new();
  BIGNUM* invT3 = BN_new();

  // Calculate 2^2lp
  int_temp = lp + lp;
  BN_set_word(bn_val1, int_temp); // 2lp to BIGNUM 
  BN_add(bn_val, one, one); // 1 + 1
  BN_exp(bn_val2, bn_val, bn_val1, ctx); // 2^2lp
  BN_clear(bn_val1);
  BN_clear(bn_val);
  
  // Select random value w ∈ {0, 1}^2lp
  BN_rand_range(w, bn_val2); 
  BN_clear(bn_val2);

  // Calculate T1
  BN_mod_exp(bn_val, y.y, w, y.n, ctx); // y^w
  BN_mod_mul(sign.T1, bn_val, membership.A, y.n, ctx); // Ay^w 
  BN_clear(bn_val); 

  // Calculate T2
  BN_mod_exp(sign.T2, y.g, w, y.n, ctx); // g^w

  // Calculate T3
  BN_mod_exp(bn_val, y.g, membership.e, y.n, ctx); // g^e
  BN_mod_exp(bn_val1, y.h, w, y.n, ctx); // h^w 
  BN_mod_mul(sign.T3, bn_val1, bn_val, y.n, ctx); // g^eh^w 
  BN_clear(bn_val);
  BN_clear(bn_val1);

  // Choose r1 
  int_temp = epsilon * (gamma_2 + k); 
  BN_set_word(bn_val, int_temp); // set to BIGNUM
  BN_rand_range(hash.r1, bn_val);
  BN_clear(bn_val);

  // Choose r2
  int_temp = epsilon * (lambda_2 + k);
  BN_set_word(bn_val, int_temp); // set to BIGNUM
  BN_rand_range(hash.r2, bn_val);
  BN_clear(bn_val);

  // Choose r3
  int_temp = epsilon * (gamma_1 + 2*lp + k + 1);
  BN_set_word(bn_val, int_temp); // set to BIGNUM
  BN_rand_range(hash.r3, bn_val);
  BN_clear(bn_val);

  // Choose r4
  int_temp = epsilon * (2*lp + k);
  BN_set_word(bn_val, int_temp); // set to BIGNUM
  BN_rand_range(hash.r4, bn_val);
  BN_clear(bn_val);

  // Compute d1
  BN_mod_exp(bn_val, y.a, hash.r2, y.n, ctx); // a^r2
  BN_mod_inverse(bn_val2, bn_val, y.n, ctx); // 1/a^r2
  BN_clear(bn_val);
  BN_mod_exp(bn_val1, y.y, hash.r3, y.n, ctx); // y^r3
  BN_mod_inverse(bn_val, bn_val1, y.n, ctx); // 1/y^r3
  BN_mod_mul(bn_val1, bn_val2, bn_val, y.n, ctx);  // 1/a^r2 * 1/y^r3
  BN_clear(bn_val2);
  BN_clear(bn_val);
  BN_mod_exp(bn_val, sign.T1, hash.r1, y.n, ctx); // T1^r1
  BN_mod_mul(hash.d1, bn_val1, bn_val, y.n, ctx); // T1^r1/(a^r2 * y^r3)
  BN_clear(bn_val);
  BN_clear(bn_val1);
  BN_clear(bn_val2);
  
  // Compute d2
  BN_mod_exp(bn_val, y.g, hash.r3, y.n, ctx); // g^r3
  BN_mod_inverse(bn_val1, bn_val, y.n, ctx); // g^-r3
  BN_clear(bn_val);
  BN_mod_exp(bn_val, sign.T2, hash.r1, y.n, ctx); // T2^r1
  BN_mod_mul(hash.d2, bn_val, bn_val1, y.n, ctx); // T2^r1 *  g^-r3
  BN_clear(bn_val);
  BN_clear(bn_val1);

  // Compute d3
  BN_mod_exp(hash.d3, y.g, hash.r4, y.n, ctx); // g^r4
  printf("d3=g^r4=%s^%s mod %s\n", printer(y.g),printer(hash.r4), printer(y.n));

  // Compute d4
  BN_mod_exp(bn_val, y.g, hash.r1, y.n, ctx); // g^r1
  BN_mod_exp(bn_val1, y.h, hash.r4, y.n, ctx); // h^r4
  BN_mod_mul(hash.d4, bn_val1, bn_val, y.n, ctx); // g^r1 * h^r4
  BN_clear(bn_val);
  BN_clear(bn_val1);

  // Compute Hash
  unsigned char hash_digest[k];
  unsigned char memdump[k]; // NEEDED to prevent memory overwrite (no problem in mbedtls)
  SHA256_Init(&sha_ctx);

  hash_input(y.g);
  hash_input(y.h);
  hash_input(y.a0);
  hash_input(y.a);
  hash_input(sign.T1);
  hash_input(sign.T2);
  hash_input(sign.T3);
  // hash_input(hash.d1); // problem with calcualtion no problem in mbedtls
  hash_input(hash.d2);
  hash_input(hash.d3);
  hash_input(hash.d4);

  SHA256_Final(hash_digest, &sha_ctx);
  BN_bin2bn(hash_digest, k, sign.c);
  

  // printf("Hash = (r1, r2, r3, r4, d1, d2, d3, d4) = (%s, %s, %s, %s, %s, %s, %s, %s)\n", printer(hash.r1), printer(hash.r2), printer(hash.r3), printer(hash.r4), printer(hash.d1), printer(hash.d2), printer(hash.d3) ,printer(hash.d4))

  // Compute s1
  BN_add(bn_val, one, one); // 1+1
  BN_set_word(bn_val2, gamma_1); // gamma1 to BIGNUM 
  BN_exp(bn_val1, bn_val, bn_val2, ctx); // 2^gamma1
  BN_clear(bn_val);
  BN_sub(bn_val, membership.e, bn_val1); // e - 2^gamma1  
  BN_mul(bn_val1, sign.c, bn_val, ctx); // c(e - 2^gamma1)
  BN_sub(sign.s1, hash.r1, bn_val1); // r1 - c(e - 2^gamma1)
  BN_clear(bn_val);
  BN_clear(bn_val1);
  BN_clear(bn_val2);

  // Compute s2
  BN_add(bn_val, one, one); // 1 + 1
  BN_set_word(bn_val2, lambda_2); // lambda2 to BIGNUM 
  BN_exp(bn_val1, bn_val, bn_val2, ctx); // 2^lambda_2
  BN_clear(bn_val);
  BN_clear(bn_val2);
  BN_sub(bn_val, membership.x, bn_val1); // x1 -  2^lambda_2
  BN_mul(bn_val1, bn_val, sign.c, ctx); // c * (x1 -  2^lambda_2)
  BN_clear(bn_val);
  BN_sub(sign.s2, hash.r2, bn_val1); // r2 - c * (x1 -  2^lambda_2)
  BN_clear(bn_val1);

  // Compute s3
  BN_mul(bn_val, sign.c, w, ctx); // cw
  BN_mul(bn_val1, bn_val, membership.e, ctx); // ecw
  BN_sub(sign.s3, hash.r3, bn_val1); // r3 - ecw

  // Compute s4
  BN_mul(bn_val, sign.c, w, ctx); // cw
  BN_sub(sign.s4, hash.r4, bn_val); // r4 - cw

  printf("sig = (c, s1, s2, s3, s4, T1, t2, T3) = (%s, %s, %s, %s, %s, %s, %s, %s) \n", printer(sign.c), printer(sign.s1), printer(sign.s2), printer(sign.s3), printer(sign.s4), printer(sign.T1), printer(sign.T2), printer(sign.T3));
  
  return sign;
}

