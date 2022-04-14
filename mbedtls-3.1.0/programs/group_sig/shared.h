#ifndef SHARED_H_   
#define SHARED_H

  // Define the security parameters
  static const uint64_t epsilon = 2;
  static const uint64_t k = 32;
  static const uint64_t lp = 1048;
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

  struct pk_struct manager_setup( int *exit_code );
  void print_pk_to_file( struct pk_struct pk );
  void print_cert_to_file( struct cert_struct cert);
  void print_sign_to_file(  struct sign_struct sign );
  int manager_join_part2( mbedtls_mpi C2, mbedtls_mpi n, mbedtls_mpi a0, mbedtls_mpi *A, mbedtls_mpi *e );
  int manager_join_part1( mbedtls_mpi *a, mbedtls_mpi *b );
  int member_join( struct pk_struct pk, struct cert_struct *cert );
  int gen_sign( struct pk_struct pk, struct cert_struct cert, struct sign_struct *sign );
#endif // SHARED_H