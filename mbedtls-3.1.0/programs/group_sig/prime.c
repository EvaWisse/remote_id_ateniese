/*
 * Simple group signature demonstration program
 *
 * This program call the group signature functions and demonstrates its use
 * 
 */

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_FS_IO)
#include "mbedtls/bignum.h"

#include <stdio.h>
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_GENPRIME) ||!defined(MBEDTLS_ENTROPY_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or "
           "MBEDTLS_FS_IO and/or MBEDTLS_CTR_DRBG_C and/or "
           "MBEDTLS_GENPRIME not defined.\n");
    mbedtls_exit( 0 ); 
}
#else

#include "mbedtls/platform.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "shared.h"

void test(mbedtls_mpi *x, mbedtls_mpi *y)
{
  mbedtls_mpi_read_string(x, 10, "3");
  mbedtls_mpi_read_string(y, 10, "89");
}





int test_prime()
{
  mbedtls_mpi p, p_prime;
  mbedtls_mpi_init( &p ); mbedtls_mpi_init( &p_prime);
  int ret = gen_prime(&p, &p_prime);
  mbedtls_mpi_write_file("did i t work ", &p, 10, NULL);
  mbedtls_mpi_write_file("? -> ", &p_prime, 10, NULL );
  printf( "ret = %d", ret);

  return 0;
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
