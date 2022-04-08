#ifndef MANAGER_H_   
#define MANAGER_H_

mbedtls_mpi select_order( mbedtls_mpi n );

struct sk_struct
{
  mbedtls_mpi p;
  mbedtls_mpi q;
  mbedtls_mpi x;
};

#endif // MANAGER_H_