#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

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
  BN_set_word(bn_val2, lambda_1); // lambda_1 to BIGNUM
  BN_exp(bn_val, two, bn_val2, ctx); // 2^lambda1
  BN_mul(bn_val1, bn_val, sign.c, ctx); // c2^lambda1
  BN_clear(bn_val);
  BN_sub(bn_val, sign.s2, bn_val1); //  s2 - c2^lambda1
  BN_clear(bn_val1);
  BN_mod_exp(bn_val2, y.a, bn_val, y.n, ctx); // a^(s2 - c2^lambda1)
  BN_clear(bn_val);
  BN_mod_inverse(bn_val, bn_val2, y.n, ctx); // 1/a^(s2 - c2^lambda1)
  BN_clear(bn_val2);
  BN_mod_exp(bn_val2, y.y, sign.s3, y.n, ctx); // y^s3
  BN_mod_inverse(bn_val1, bn_val2, y.n, ctx); // 1/y^s3
  BN_clear(bn_val2);
  BN_mul(bn_val2, bn_val, bn_val1, ctx); // 1 / a^(s2 - c2^lambda1) *  y^s3
  BN_clear(bn_val);
  BN_clear(bn_val1);

  BN_set_word(bn_val1, gamma_1); // gamma_1 to BIGNUM
  BN_exp(bn_val, two,  bn_val1, ctx); // 2^gamma_1
  BN_clear(bn_val1);
  BN_sub(bn_val1, sign.s1, bn_val); // s1 - 2^gamma_1
  BN_clear(bn_val);
  BN_mod_exp(bn_val, sign.T1, bn_val1, y.n, ctx); // T1^(s1 - 2^gamma_1)
  BN_clear(bn_val1);
  BN_mod_mul(bn_val1, bn_val, bn_val2, y.n, ctx); // (T1^(s1 - 2^gamma_1)) / (a^(s2 - c2^lambda1) * y^s3)
  BN_clear(bn_val);
  BN_clear(bn_val2);
  BN_mod_exp(bn_val, y.a0, sign.c, y.n, ctx); // a0^c
  BN_mod_mul(d1, bn_val, bn_val1, y.n, ctx); // a0^c * (T1^(s1 - 2^gamma_1)) / (a^(s2 - c2^lambda1) * y^s3)
  BN_clear(bn_val);
  BN_clear(bn_val1);
  BN_clear(bn_val2);

  // Calculate d2
  BN_mod_exp(bn_val, y.g, sign.s3, y.n, ctx); // g^s3
  BN_set_word(bn_val2, gamma_1); // gamma_1 to BIGNUM
  BN_exp(bn_val1, two, bn_val2, ctx); // 2^gamma_1
  BN_mul(bn_val2, sign.c, bn_val1, ctx); // c * 2^gamma_1
  BN_clear(bn_val1);
  BN_sub(bn_val1, sign.s1, bn_val2); // s1 - c * 2^gamma_1
  BN_clear(bn_val2);
  BN_mod_exp(bn_val2, sign.T2, bn_val1, y.n, ctx); // T2^ s1 - c * 2^gamma_1
  BN_clear(bn_val1);
  BN_mod_inverse(bn_val1, bn_val, y.n, ctx); // g^-s3
  BN_mod_mul(d2, bn_val2, bn_val1, y.n, ctx); // T2^ s1 - c * 2^gamma_1 * g^-s3
  BN_clear(bn_val2);

  // Calculate d3
  BN_mod_exp(bn_val, sign.T2, sign.c, y.n, ctx); // T2^c 
  BN_mod_exp(bn_val1, y.g, sign.s4, y.n, ctx); // g^s4
  BN_mod_mul(d3, bn_val, bn_val1, y.n, ctx); // T2^c g^s4
  BN_clear(bn_val);
  BN_clear(bn_val1);

  // Calculate d4
  BN_set_word(bn_val1, gamma_1); // gamma_1 to BIGNUM
  BN_exp(bn_val, two, bn_val1, ctx); // 2^gamma_1
  BN_clear(bn_val1);
  BN_mul(bn_val1, sign.c, bn_val, ctx); // c*2^gamma_1
  BN_clear(bn_val);
  BN_sub(bn_val, sign.s1, bn_val1); // s1 - c*2^gamma_1
  BN_set_negative(bn_val, 0);
  BN_mod_exp(bn_val1, y.g, bn_val, y.n, ctx); // g^(s1 - c*2^gamma_1)
  BN_clear(bn_val);
  BN_mod_exp(bn_val, y.h, sign.s4, y.n, ctx); // h^s4
  BN_mod_mul(bn_val2, bn_val1, bn_val, y.n, ctx); //  h^s4 * g^(s1 - c*2^gamma_1)
  BN_clear(bn_val);
  BN_clear(bn_val1);
  BN_mod_exp(bn_val1, sign.T3, sign.c, y.n, ctx); // T3^c
  BN_mod_mul(d4, bn_val1, bn_val2, y.n, ctx); // T3^c * g^(s1−c2^gamma_1) * h^s4
  
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
  // hash_verify(d1);
  hash_verify(d2);
  hash_verify(d3);
  // hash_verify(d4);

  SHA256_Final(hash_compare, &hash_ctx);
  BN_bin2bn(hash_compare, k, c_check);

  printf("Verifier \td1 = %s\n\t\td2 = %s\n\t\td3 = %s\n\t\td4 = %s\n", printer(d1), printer(d2), printer(d3), printer(d4));

  // Compare hashes
  // printf("Member hash \t= %s\nVerifier hash \t= %s\n", printer(sign.c), printer(c_check));
  if(BN_ucmp(sign.c, c_check))
  {
    printf("Not Authenticated\n");
  }
  else
  {
    printf("Authenticated\n");
  }
}