#ifndef PUBLIC_H
  #define PUBLIC_H

  // Define the security parameters
  static const int lp = 5;

  struct y_struct{
    BIGNUM* n;
    BIGNUM* a;
    BIGNUM* a0;
    BIGNUM* y;
    BIGNUM* g;
    BIGNUM* h;
  };

  void setup();
  char* printer(BIGNUM* p);
#endif