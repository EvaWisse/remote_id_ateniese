#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>

#include "public.h"

struct manager_info_struct join_manager(BIGNUM* x, bool z, struct y_struct y);

struct manager_info_struct
{
  BIGNUM* a;
  BIGNUM* b; 
};

struct membership_struct join_member(struct y_struct y)
{
  BN_CTX* ctx= BN_CTX_new(); 
  BIGNUM* one = BN_new();
  BN_one(one);
  BIGNUM* x = BN_new();
  BIGNUM* r = BN_new();
  BIGNUM* C1 = BN_new();
  BIGNUM* C2 = BN_new();
  BIGNUM* bn_val = BN_new();
  BIGNUM* bn_val1 = BN_new();
  BIGNUM* bits_lambda_2 = BN_new();
  BIGNUM* bits_lambda_1 = BN_new();

  struct membership_struct membership;
  struct manager_info_struct manager_info;

  membership = init_membership();
  manager_info.a = BN_new();
  manager_info.b = BN_new();


  // Calculate 2^λ1
  BN_set_word(bn_val, lambda_1); // lambda1 to BIGNUM 
  BN_add(bn_val1, one, one); // 1 + 1
  BN_exp(bits_lambda_1, bn_val1, bn_val, ctx); // 2^λ1
  BN_clear(bn_val);

  // Calculate 2^λ2
  BN_set_word(bn_val, lambda_2); // lambda2 to BIGNUM 
  BN_exp(bits_lambda_2, bn_val1, bn_val, ctx); // 2^λ2
  BN_clear(bn_val);
  BN_clear(bn_val1);

  // Generate a secret exponent x ∈  ]0, 2^λ2[
  BN_clear(x);
  while(BN_is_zero(x) || !abs(BN_ucmp(x,bits_lambda_2)))
  {
    BN_rand_range(x, bits_lambda_2);
  }
      
  // Generate r  ∈ ]0, n^2[ 
  BN_sqr(bn_val, y.n, ctx); // n^2
  while(BN_is_zero(r) || !abs(BN_ucmp(r, bn_val)))
  {
    BN_rand_range(r, bn_val);
  }
  BN_clear(bn_val);

  // Calculate C1 = g^xh^r mod n
  BN_mod_exp(bn_val, y.g, x, y.n, ctx); // g^x
  BN_mod_exp(bn_val1, y.h, r, y.n, ctx); // h^r
  BN_mod_mul(C1, bn_val, bn_val1, y.n, ctx); // C1 = g^xh^r mod n
  BN_clear(bn_val);
  BN_clear(bn_val1);

  // Send C1 to manager
  manager_info = join_manager(C1, true, y); 

  // Compute x = =2^λ1 +(αixi + βi mod 2^λ2)
  BN_mod_mul(bn_val, manager_info.a, x, bits_lambda_2, ctx); // αi*xi
  BN_mod_add(bn_val1, bn_val, manager_info.b, bits_lambda_2, ctx); // αixi + βi
  BN_clear(bn_val);
  BN_clear(x);
  BN_add(x, bn_val1, bits_lambda_1); // 2^λ1 +(αixi + βi mod 2^λ2)
  membership.x = x;

  // Compute C2 = a^xi mod n
  BN_mod_exp(C2, y.a, membership.x, y.n, ctx);

  // Send C2 to manager
  manager_info = join_manager(C2, false, y);
  
  // Set membership certificate
  membership.A = manager_info.a;
  membership.e = manager_info.b;

  // Verifiy that a^xia0 ≡ Ai^ei (mod n).
  BN_mod_exp(bn_val, y.a, x, y.n, ctx); // a^x
  BN_mod_mul(bn_val1, bn_val, y.a0, y.n, ctx); // a^xia0
  BN_clear(bn_val);
  BN_mod_exp(bn_val, manager_info.a, manager_info.b, y.n, ctx); // Ai^ei

  if(BN_ucmp(bn_val, bn_val1)) 
  {
    printf("Join successfull\n");
    printf("Member certificate: [A, e, x] = [%s, %s, %s]\n", printer(membership.A), printer(membership.e), printer(membership.x));
  }
  else
  {
    printf("Join failed\n");
    printf("Member certificate: [A, e, x] = [%s, %s, %s]\n", printer(membership.A), printer(membership.e), printer(membership.x));
  }
  return membership;
}

struct manager_info_struct join_manager(BIGNUM* x, bool z, struct y_struct y)
{
  struct manager_info_struct info;
  info.a = BN_new();
  info.b = BN_new();
  BIGNUM* one = BN_new();
  BN_one(one);
  BIGNUM* bn_val = BN_new();
  BIGNUM* bn_val1 = BN_new();
  BN_CTX* ctx= BN_CTX_new(); 
  BIGNUM* bits_lambda_2 = BN_new();
  BIGNUM* bits_lambda_1 = BN_new();

  // Calculate 2^λ1
  BN_set_word(bn_val, lambda_1); // lambda1 to BIGNUM 
  BN_add(bn_val1, one, one); // 1 + 1
  BN_exp(bits_lambda_2, bn_val1, bn_val, ctx); // 2^λ1
  BN_clear(bn_val);

  // Calculate 2^λ2
  BN_set_word(bn_val, lambda_2); // lambda2 to BIGNUM 
  BN_exp(bits_lambda_2, bn_val1, bn_val, ctx); // 2^λ2
  BN_clear(bn_val);
  BN_clear(bn_val1);
  
  // PART 1
  if(z)
  {
    // Check that C1 ∈ QR(n)
    //TODO:

    // Select random αi and βi ∈ ]0, 2^λ2[ 
    BN_rand_range(info.a, bits_lambda_2); // select a
    BN_rand_range(info.b, bits_lambda_2); // select b

    // Send αi and βi to member
    return info;
  }
  // PART 2
  else
  {
    BN_clear(info.a);
    BN_clear(info.b);

    // Check that C2 ∈ QR(n)
    //TODO:

    // Select random prime ei ∈ Γ 
    BN_add(bn_val, bits_lambda_1, bits_lambda_2); // range Γ = ]2^gamma_1 - 2^gamma_2, 2^gamma_1 + 2^gamma_2[
    BN_rand_range(info.a, bn_val); // select e
    BN_clear(bn_val);
    
    // Compute Ai := (C2a0)^-ei mod n
    BN_mod_mul(bn_val, x, y.a0, y.n, ctx); // C2a0
    BN_mod_exp(bn_val1, bn_val, info.a, y.n, ctx); // (C2a0)^ei
    BN_mod_inverse(info.b, bn_val1, y.n, ctx); // (C2a0)^-ei

    // Send new membership certificate [Ai,ei]
    return info;
  }
}