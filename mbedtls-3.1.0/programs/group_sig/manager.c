/*
 * The function of the group manager
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

#include "shared.h"
#include "manager.h"

struct pk_struct manager_setup()
{
  int exit_code = MBEDTLS_EXIT_FAILURE;

  // Intilize keys
  mbedtls_printf( "ok. Intilize keys, please wait...\n" );
  fflush( stdout );
  struct pk_struct pk;
  struct sk_struct sk;
  mbedtls_mpi_init( &pk.n ); mbedtls_mpi_init( &pk.a ); mbedtls_mpi_init( &pk.a0 ); 
  mbedtls_mpi_init( &pk.y ); mbedtls_mpi_init( &pk.g ); mbedtls_mpi_init( &pk.h ); 
  mbedtls_mpi_init( &sk.p ); mbedtls_mpi_init( &sk.q ); mbedtls_mpi_init( &sk.x );

  // Initilize and introduce temperoral variables
  mbedtls_printf( "ok. Initilize and introduce temperoral variables, please wait...\n" );
  fflush( stdout );
  int ret = 1; 
  mbedtls_mpi p, q, mpi_val, mpi_val1;
  mbedtls_mpi_init( &p ); mbedtls_mpi_init( &q ); mbedtls_mpi_init( &mpi_val ); mbedtls_mpi_init( &mpi_val1 );

  // Introduce variables for drbg
  mbedtls_printf( "ok. Introduce variables for drbg, please wait...\n" );
  fflush( stdout );
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init( &ctr_drbg );
  char personalization[] = "my_app_specific_string";

  // Introduce variables for entropy
  mbedtls_printf( "ok. Introduce variables for entropy, please wait...\n" );
  fflush( stdout );
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init( &entropy );

  // FIXME: Generate primes instead of hardcoding an example
  // Select random secret lp-bit primes p',q' such that p =2p' + 1 and q = 2q' + 1 are prime. 
  mbedtls_printf( "ok. Give values to p, q, p' and q', please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_read_string( &sk.p, 10, "41" ); // Set p' 
  mbedtls_mpi_read_string( &sk.q, 10, "29" ); // Set q' 

  mbedtls_mpi_read_string( &p, 10, "83" ); // Set p 
  mbedtls_mpi_read_string( &q, 10, "59" ); // Set q

  // Calculate the modulus n = pq
  mbedtls_printf( "ok. Calculate the modulus n = pq, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_mul_mpi( &pk.n, &p, &q ); 

  // Choose random elements a, a0, g, h ∈ QR(n) (of order p'q') use proposition 1 and collary 1. 
  mbedtls_printf( "ok. Choose random elements a, a0, g, h in QR(n) (of order p'q') using proposition 1 and collary 1., please wait...\n" );
  fflush( stdout );
  pk.a = select_order( pk.n );
  pk.a0 = select_order( pk.n );
  pk.g = select_order( pk.n );
  pk.h = select_order( pk.n );
  
  // Calculate range for x ∈ Z/p'q'
  mbedtls_printf( "ok. Calculate range for x in Z/p'q', please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_mul_mpi( &mpi_val, &sk.p, &sk.q ); // p'q'
  
  // Seed drbg
  mbedtls_printf( "ok. Seed drbg, please wait...\n" );
  fflush( stdout );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_ctr_drbg_seed got ret = %d\n", ret);
  }

  // Use seeded drbg to get x ∈ Z/p'q' variable FIXME: set correct range
  mbedtls_printf( "ok. Use seeded drbg to get x in Z/p'q', please wait...\n" );
  fflush( stdout );
  ret = mbedtls_mpi_fill_random( &sk.x, 2, mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
  }

  // Calculate y = g^x mod n
  mbedtls_printf( "ok. Calculate y = g^x mod n, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &pk.y, &pk.g, &sk.x, &pk.n, NULL);
  
  exit_code = MBEDTLS_EXIT_SUCCESS;

  mbedtls_printf( "ok. Clean up and return, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_free( &p ); mbedtls_mpi_free( &q ); mbedtls_mpi_free( &mpi_val ); mbedtls_mpi_free( &mpi_val1 );
  mbedtls_entropy_free( &entropy );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  
  if( exit_code != MBEDTLS_EXIT_SUCCESS )
  {
      mbedtls_printf( "\nAn error occurred.\n" );
  }

  mbedtls_printf("return\n");
  return pk;
}

mbedtls_mpi select_order( mbedtls_mpi n )
{
  mbedtls_mpi x, gcd, gcd1, mpi_1, mpi_2;
  
  mbedtls_mpi_init( &x );     mbedtls_mpi_init( &mpi_1 );
  mbedtls_mpi_init( &mpi_2);  mbedtls_mpi_init( &gcd ); 
  mbedtls_mpi_init( &gcd1 );  

  while( abs(mbedtls_mpi_cmp_int( &gcd, 1 )) && abs(mbedtls_mpi_cmp_int( &gcd1, 1 )) )
  {
    while( abs(mbedtls_mpi_cmp_int( &gcd, 1 )) )
    {
      // select random x ∈ QR(n) FIXME: select random instead of hardcoding
      mbedtls_mpi_read_string( &x, 10, "11" ); // temp fix for x
      mbedtls_mpi_gcd( &gcd, &x, &n ); // check gcd( x, n )
    }
    mbedtls_mpi_sub_int( &mpi_1, &x, 1 ); // x - 1
    mbedtls_mpi_gcd( &gcd, &x, &n ); // gcd( x - 1, n )
    mbedtls_mpi_add_int( &mpi_2, &x, 1 ); // x + 1
    mbedtls_mpi_gcd( &gcd1, &x, &n ); // gcd( x + 1, n)
  }
  mbedtls_mpi_mul_mpi( &x, &x, &x ); // x^2 
  mbedtls_mpi_mod_mpi( &x, &x, &n ); // mod n

  // clean up
  mbedtls_mpi_free( &mpi_1 ); mbedtls_mpi_free( &mpi_2);
  mbedtls_mpi_free( &gcd );   mbedtls_mpi_free( &gcd1 );
  return x;
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
