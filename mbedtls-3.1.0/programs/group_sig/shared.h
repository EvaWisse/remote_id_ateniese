#ifndef SHARED_H_   
#define SHARED_H

  // Define the security parameters
  static const uint64_t epsilon = 1;
  static const uint64_t k = 4;
  static const uint64_t lp = 6;
  static const uint64_t lambda_2 = (4 * lp) + 1;
  static const uint64_t lambda_1 = (epsilon * (lambda_2 + k) + 2) + 1;
  static const uint64_t gamma_2 = (lambda_1 + 2) + 1;
  static const uint64_t gamma_1 = (epsilon * ( gamma_2 + k) + 2) + 1;
  
  struct pk_struct
  {
    mbedtls_mpi n;
    mbedtls_mpi a;
    mbedtls_mpi a0;
    mbedtls_mpi y;
    mbedtls_mpi g;
    mbedtls_mpi h;
  };

  struct cert_struct
  {
    mbedtls_mpi A;
    mbedtls_mpi e;
    mbedtls_mpi x;
  };

  struct manager_info_struct
  {
    mbedtls_mpi a;
    mbedtls_mpi b; 
  };

  struct sign_struct
  {
    mbedtls_mpi c;
    mbedtls_mpi s1;
    mbedtls_mpi s2;
    mbedtls_mpi s3;
    mbedtls_mpi s4;
    mbedtls_mpi T1;
    mbedtls_mpi T2;
    mbedtls_mpi T3;
  };

  struct pk_struct manager_setup();
  void print_pk_to_file( struct pk_struct pk );
  void print_cert_to_file( struct cert_struct cert );
  struct cert_struct member_join( struct pk_struct pk );
  struct manager_info_struct manager_join(mbedtls_mpi x, mbedtls_mpi n, int z, mbedtls_mpi a0);
  struct sign_struct gen_sign( struct pk_struct pk, struct cert_struct cert );
  void verify( struct pk_struct pk, struct sign_struct sign );
  void print_sign_to_file(  struct sign_struct sign );
#endif // SHARED_H