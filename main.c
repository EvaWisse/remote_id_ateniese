#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h> 
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>

#include "public.h"

void main()
{
  struct y_struct y;
  struct membership_struct membership;
  struct sign_struct signature;
  
  membership =  init_membership();
  signature = init_sign();
  y = init_y();

  y = setup();
  membership = join_member(y);
  signature = sign(y, membership);
  verify(y, signature);
}

char* printer(BIGNUM* p)
{
  char * number_str = BN_bn2dec(p);
  return number_str;
}

struct sign_struct init_sign()
{
  struct sign_struct sign;
  sign.c = BN_new();
  sign.s1 = BN_new();
  sign.s2 = BN_new();
  sign.s3 = BN_new();
  sign.s4 = BN_new();
  sign.T1 = BN_new();
  sign.T2 = BN_new();
  sign.T3 = BN_new();
  return sign;
}

struct s_struct init_s()
{
  struct s_struct s;
  s.p =BN_new();
  s.q = BN_new();
  s.x = BN_new();
  return s;
}

struct y_struct init_y()
{
  struct y_struct y;
  y.n = BN_new();
  y.a = BN_new();
  y.a0 = BN_new();
  y.y = BN_new();
  y.g = BN_new();
  y.h = BN_new();
  return y;
}

struct membership_struct init_membership()
{
  struct membership_struct membership;
  membership.A = BN_new();
  membership.e = BN_new();
  membership.x = BN_new();
  return membership;
}
  struct hash_struct init_hash()
  {
    struct hash_struct hash;
    hash.r1 = BN_new();
    hash.r2 = BN_new();
    hash.r3 = BN_new();
    hash.r4 = BN_new();
    hash.d1 = BN_new();
    hash.d2 = BN_new();
    hash.d3 = BN_new();
    hash.d4 = BN_new(); 
    return hash;
  }