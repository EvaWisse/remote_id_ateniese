#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <sys/types.h>

#include "public.h"

SHA256_CTX hash_ctx;

void hash_verify(BIGNUM* data)
{
  size_t len = BN_num_bytes(data);
  unsigned char *buf = OPENSSL_malloc(len);
  BN_bn2bin(data, buf);
	SHA256_Update(&hash_ctx, buf, len);
  OPENSSL_free(buf);
}

void verify(struct y_struct y, struct sign_struct sign)
{
  BN_CTX* ctx= BN_CTX_new(); 
  BIGNUM* one = BN_new();
  BIGNUM* two = BN_new();
  BN_one(one);
  BN_add(two, one, one);

  BIGNUM* bn_val = BN_new();
  BIGNUM* bn_val1 = BN_new();
  BIGNUM* bn_val2 = BN_new();
  BIGNUM* d1 = BN_new();
  BIGNUM* d2 = BN_new();
  BIGNUM* d3 = BN_new();
  BIGNUM* d4 = BN_new();

  // Caluculate d1
  BN_set_word(bn_val2, gamma_1); // set gamma_1 to BIGNUM
  BN_exp(bn_val1, two, bn_val2, ctx); // 2^gamma_1
  BN_clear(bn_val2);
  BN_mul(bn_val2, bn_val1, sign.c, ctx); // c2^gamma_1
  BN_sub(bn_val1, sign.s1, bn_val2); // s1-c2^gamma_1
  if(BN_is_negative(bn_val1))
  {
    BN_set_negative(bn_val1, 0); // |s1 - c2^gamma_1| 
    BN_mod_inverse(bn_val, sign.T1, y.n, ctx); // inv T1
    BN_mod_exp(bn_val2, bn_val, bn_val1, y.n, ctx); // inv T1 ^ |s1 - c2^gamma_1| 
  }
  else
  {
    BN_mod_exp(bn_val2, sign.T1, bn_val1, y.n, ctx); // T1 ^ s1 - c2^gamma_1
  }
  BN_clear(bn_val);
  BN_clear(bn_val1);

  BN_mod_exp(bn_val, y.a0, sign.c, y.n, ctx); // a0^c
  BN_mod_mul(bn_val1, bn_val, bn_val2, y.n, ctx); // a0^c * T1 ^ (s1 - c2^gamma_1)
  BN_clear(bn_val2);
  BN_clear(bn_val);

  BN_set_word(bn_val, lambda_1); // lambda_1 to BIGNUM
  BN_exp(bn_val2, two, bn_val, ctx); // 2^lambda_1
  BN_clear(bn_val);
  BN_mul(bn_val, bn_val2, sign.c, ctx); // c2^lambda_1
  BN_clear(bn_val2);
  BN_sub(bn_val2, sign.s2, bn_val); // s2-c2^lambda_1
  BN_clear(bn_val);
  if(BN_is_negative(bn_val2))
  {
    BN_set_negative(bn_val2, 0); // |s2-c2^lambda_1|
    BN_mod_exp(bn_val, y.a, bn_val2, y.n, ctx); // a^|s2-c2^lambda_1| 
  }
  else
  {
    BIGNUM* test = BN_new();
    BN_mod_inverse(test, y.a, y.n, ctx);
    BN_mod_exp(bn_val, test, bn_val2, y.n, ctx); // inv a^s2-c2^lambda_1
  }
  BN_clear(bn_val2);
  BN_mod_mul(bn_val2, bn_val, bn_val1, y.n, ctx); //   a^|s2-c2^lambda_1| * a0^c * inv T1 ^ |s1 - c2^gamma_1|

  if(BN_is_negative(sign.s3))
  {
    BN_set_negative(sign.s3, 0); // |s3|
    BN_clear(bn_val1);
    BN_mod_exp(bn_val1, y.y, sign.s3, y.n, ctx); // y^|s3|
  }
  else 
  {
    BN_mod_inverse(bn_val, y.y, y.n, ctx); // inv y
    BN_mod_exp(bn_val1, bn_val, sign.s3, y.n, ctx); // inv y^s3
  }
  BN_mod_mul(d1, bn_val2, bn_val1, y.n, ctx); 

  // Calculate d2
  BN_set_negative(sign.s3, 0); // |s3|
  BN_mod_exp(bn_val1, y.g, sign.s3, y.n, ctx); //  g ^|s3|
  BN_add(bn_val, one, one);
  BN_set_word(bn_val2, gamma_1);
  BN_exp(bn_val, bn_val, bn_val2, ctx); // 2^gamma_1
  BN_mul(bn_val, bn_val, sign.c, ctx); // c2^gamma_1
  BN_sub(bn_val, sign.s1, bn_val); // s1-c2^gamma_1
  BN_set_negative(bn_val, 0); // |s1-c2^gamma_1| 
  BN_mod_inverse(bn_val2, sign.T2, y.n, ctx); // inv T2
  BN_mod_exp(bn_val, bn_val2, bn_val, y.n, ctx); // inv T2 ^|s1-c2^gamma_1|
  BN_mod_mul(d2, bn_val1, bn_val, y.n, ctx); 

  // Calculate d3 //FIXME: add if statement when negative
  BN_mod_exp(bn_val, sign.T2, sign.c, y.n, ctx); // T2^c 
  BN_mod_inverse(bn_val2, y.g, y.n, ctx); // g^-1
  BN_set_negative(sign.s4, 0); // |s4|
  BN_mod_exp(bn_val1, bn_val2, sign.s4, y.n, ctx); // g^-|s4|
  BN_mod_mul(d3, bn_val, bn_val1, y.n, ctx); // T2^c * g^-|s4|
  BN_clear(bn_val);
  BN_clear(bn_val1);

  // Calculate d4
   BN_mod_exp(bn_val, sign.T3, sign.c, y.n, ctx); // t3^c
  BN_mod_inverse(bn_val1, y.h, y.n, ctx); // inv h
  BN_set_negative(sign.s4, 0); // set |s4|
  BN_mod_exp(bn_val2, bn_val1, sign.s4, y.n, ctx); // inv h^S4
  BN_mod_mul(bn_val1, bn_val2, bn_val, y.n, ctx); // T3^c * inv^s4
  BN_add(bn_val, one, one); // 1 + 1
  BN_set_word(bn_val2, gamma_1); // make gamma_1 to BIGNUM
  BN_exp(bn_val, bn_val, bn_val2, ctx); // 2^gamma_1
  BN_mul(bn_val, bn_val, sign.c, ctx); // c2^gamma_1
  BN_sub(bn_val, sign.s1, bn_val); // s1-c2^gamma_1
  BN_set_negative(bn_val, 0); // |s1-c2^gamma_1|
  BN_mod_inverse(bn_val2, y.g, y.n, ctx); // inv g
  BN_mod_exp(bn_val2, bn_val2, bn_val, y.n ,ctx);  // inv g ^ |s1-c2^gamma_1|
  BN_mod_mul(d4, bn_val2, bn_val1, y.n, ctx); 
  BN_set_negative(sign.s4, 1);
  
 // Calculate hash 
  BIGNUM* c_check = BN_new();
  unsigned char hash_digest[k];
  SHA256_Init(&hash_ctx);
  unsigned char hash_compare[k];

  hash_verify(y.g);
  hash_verify(y.h);
  hash_verify(y.a0);
  hash_verify(y.a);
  hash_verify(sign.T1);
  hash_verify(sign.T2);
  hash_verify(sign.T3);
  // hash_verify(d1); // not added to problem with calculation in openssl no problem in mbedtls
  hash_verify(d2);
  hash_verify(d3);
  hash_verify(d4);

  SHA256_Final(hash_compare, &hash_ctx);
  BN_bin2bn(hash_compare, k, c_check);

  // Compare hashes
  if(BN_ucmp(sign.c, c_check))
  {
    printf("Not Authenticated\n");
  }
  else
  {
    printf("Authenticated\n");
  }
}