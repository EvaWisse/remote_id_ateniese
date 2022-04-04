#ifndef PUBLIC_H
#define PUBLIC_H

  // Define the security parameters
  static const uint64_t epsilon = 1;
  static const uint64_t k = 4;
  static const uint64_t lp = 6;
  static const uint64_t lambda_2 = (4 * lp) + 1;
  static const uint64_t lambda_1 = (epsilon * (lambda_2 + k) + 2) + 1;
  static const uint64_t gamma_2 = (lambda_1 + 2) + 1;
  static const uint64_t gamma_1 = (epsilon * ( gamma_2 + k) + 2) + 1;
  

  struct y_struct{
    BIGNUM* n;
    BIGNUM* a;
    BIGNUM* a0;
    BIGNUM* y;
    BIGNUM* g;
    BIGNUM* h;
  };

  struct sign_struct
  {
    BIGNUM* c;
    BIGNUM* s1;
    BIGNUM* s2;
    BIGNUM* s3;
    BIGNUM* s4;
    BIGNUM* T1;
    BIGNUM* T2;
    BIGNUM* T3;
  };

  struct membership_struct
  {
    BIGNUM* A;
    BIGNUM* e;
    BIGNUM* x;
  };

  struct s_struct
  {
  BIGNUM* p;
  BIGNUM* q;
  BIGNUM* x;
  };

  struct hash_struct 
  {
    BIGNUM* r1;
    BIGNUM* r2;
    BIGNUM* r3;
    BIGNUM* r4;
    BIGNUM* d1;
    BIGNUM* d2;
    BIGNUM* d3;
    BIGNUM* d4;
  };

  struct y_struct setup();
  char* printer(BIGNUM* p);
  struct membership_struct join_member(struct y_struct y);
  struct sign_struct sign(struct y_struct y, struct membership_struct membership);
  void verify(struct y_struct y, struct sign_struct sign); 
  void open(struct sign_struct sign, struct y_struct y);

  // Initlizing functions
  struct membership_struct init_membership();
  struct s_struct init_s();
  struct y_struct init_y();
  struct hash_struct init_hash();
  struct sign_struct init_sign();
#endif