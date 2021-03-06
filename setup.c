#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>

#include "public.h"
struct s_struct s;
BIGNUM* select_QR(struct y_struct y)
{
  BN_CTX* ctx= BN_CTX_new(); 
  BIGNUM* one = BN_new();
  BN_one(one);
  BIGNUM* bn_val = BN_new();
  BIGNUM* bn_val1 = BN_new();
  BIGNUM* gcd = BN_new();
  BIGNUM* x = BN_new();
  while (!(BN_is_one(gcd) && BN_is_one(bn_val1)))
  {
    BN_clear(bn_val1);
    BN_clear(bn_val);
    while(!BN_is_one(gcd))
    {
      BN_clear(gcd);
      BN_rand_range(x, y.n); // select random x ∈ QR(n) 
      BN_gcd(gcd, x, y.n, ctx);
    }    
    BN_sub(bn_val, x, one); // x - 1
    BN_gcd(bn_val1, y.n, bn_val, ctx); // gcd(n, x - 1)
    BN_clear(bn_val);
    BN_add(bn_val, x, one); // x + 1
    BN_gcd(gcd, bn_val, y.n, ctx); // gcd(n, x + 1)
  }
  BN_mod_sqr(x, x, y.n, ctx); // x^2 
  BN_clear(bn_val1);
  BN_clear(bn_val);
  return x;
}
                                                                                                    
struct y_struct setup()
{
  // Initlize join struct and BN libary specific variables
  // struct s_struct s;
  struct y_struct y;
  s = init_s();
  y = init_y();
  BN_CTX* ctx= BN_CTX_new(); 
  BIGNUM* one = BN_new();
  BN_one(one);

  BIGNUM* p = BN_new();
  BIGNUM* q = BN_new();
  BIGNUM* bn_val = BN_new();
  BIGNUM* bn_val1 = BN_new();
  BIGNUM* gcd = BN_new();

  // Select random secret lp-bit primes p',q' such that p =2p' + 1 and q = 2q' + 1 are prime. 
  BN_generate_prime_ex(s.p, lp, true, NULL, NULL, NULL); // get p'
  BN_add(bn_val, s.p, s.p); // p' + p'
  BN_generate_prime_ex(p, lp+1, false, bn_val, one, NULL);
  BN_clear(bn_val);

  BN_generate_prime_ex(s.q, lp, true, NULL, NULL, NULL); // get q'
  BN_add(bn_val, s.q, s.q); // q' + q'
  BN_generate_prime_ex(q, lp+1, false, bn_val, one, NULL);
  BN_clear(bn_val);

  // Set the modulus n = pq
  BN_mul(y.n, p, q, ctx); // n = pq
 
  // Choose random elements a, a0, g, h ∈ QR(n) (of order p'q') use proposition 1 and collary 1. 
  y.a = select_QR(y);
  y.a0 = select_QR(y);
  y.g = select_QR(y);
  y.h = select_QR(y);

  // Choose a random secret element x ∈ Z/p'q' 
  BN_mul(bn_val, s.q, s.p, ctx); // p'q'
  BN_rand_range(s.x, bn_val); // select x ∈ Z/p'q'

  // Set y = g^x mod n
  BN_mod_exp(y.y, y.g, s.x, y.n, ctx); // g^x mod n

  printf("The Group Public Key \ty = (n, a, a0, y, g, h) = (%s, %s, %s, %s, %s, %s)\n", printer(y.n), printer(y.a), printer(y.a0), printer(y.y), printer(y.g), printer(y.h));
  printf("The GM Private Key \ts = (p', q', x) = (%s, %s, %s)\n", printer(s.p), printer(s.q), printer(s.x));
  return y;
}

void open(struct sign_struct sign, struct y_struct y)
{
  BN_CTX* ctx= BN_CTX_new(); 
  BIGNUM* one = BN_new();
  BN_one(one);
  BIGNUM* rec_A = BN_new();
  BIGNUM* bn_val = BN_new();
  BIGNUM* bn_val1= BN_new();
  char* char_TA;
  char* char_T2 ;
  char* char_y;
  char* char_g;
  double lhs;
  double rhs;

  // Recover Ai
  BN_mod_exp(bn_val, sign.T2, s.x, y.n, ctx); // T2^x
  BN_mod_inverse(bn_val1, bn_val, y.n, ctx); // inv T2^x
  BN_mod_mul(rec_A, bn_val1, sign.T1, y.n, ctx); // inv T2^x * T1

  // Convert (T1/Ai) and T2
  BN_mod_inverse(bn_val, rec_A, y.n, ctx); // inv Ai
  BN_mod_mul(bn_val1, bn_val, sign.T1, y.n, ctx); // T1/Ai
  char_TA = BN_bn2dec(bn_val1);
  char_T2 = BN_bn2dec(sign.T2);

  // Convert y and g
  char_y = BN_bn2dec(y.y);
  char_g = BN_bn2dec(y.g);
  

  // log_b(x) = log_k(x) / log_k(b)
  lhs = log(strtod(char_y, NULL)) / log(strtod(char_g, NULL));
  rhs = log(strtod(char_TA, NULL)) / log(strtod(char_T2,NULL));
  if(fabs(lhs-rhs) <0.5)
  {
    printf("IDENTIFIED They're close enough \n");
  }
  else{
    printf("NOT IDENTIFIED\n");
  }
}