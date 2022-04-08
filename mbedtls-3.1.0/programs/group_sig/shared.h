#ifndef SHARED_H_   
#define SHARED_H

  struct pk_struct
  {
    mbedtls_mpi n;
    mbedtls_mpi a;
    mbedtls_mpi a0;
    mbedtls_mpi y;
    mbedtls_mpi g;
    mbedtls_mpi h;
  };

  struct pk_struct manager_setup();

#endif // SHARED_H