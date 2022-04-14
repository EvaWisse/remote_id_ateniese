#ifndef MANAGER_H_   
#define MANAGER_H_

struct sk_struct
{
  mbedtls_mpi p;
  mbedtls_mpi q;
  mbedtls_mpi x;
};

int select_order( mbedtls_mpi n, size_t nbytes, mbedtls_mpi *x );
int gen_prime(mbedtls_mpi *x, mbedtls_mpi *x_prime);
struct manager_info_struct manager_join(mbedtls_mpi x, mbedtls_mpi n, int z, mbedtls_mpi a0);

#endif // MANAGER_H_