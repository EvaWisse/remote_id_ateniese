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

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "shared.h"
#include "manager.h"

struct pk_struct manager_setup()
{
  int exit_code = MBEDTLS_EXIT_FAILURE;
  mbedtls_printf( "####### KEY SETUP ####### \n" );
  fflush( stdout );

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

struct manager_info_struct manager_join(mbedtls_mpi x, mbedtls_mpi n, int z, mbedtls_mpi a0)
{
  mbedtls_printf( "\n\n####### JOIN MANAGER PART %d ####### \n", z - 1  );
  fflush( stdout );

  // Initilize certificate
  mbedtls_printf( "ok. Intilize manager info, please wait...\n" );
  fflush( stdout );
  struct manager_info_struct info;
  mbedtls_mpi_init( &info.a ); mbedtls_mpi_init( &info.b );

  // Initilize and introduce temperoral variables
  mbedtls_printf( "ok. Initilize and introduce temperoral variables, please wait...\n" );
  fflush( stdout );
  int ret;
  mbedtls_mpi mpi_val, mpi_val1;
  mbedtls_mpi_init( &mpi_val ); mbedtls_mpi_init( &mpi_val1 );
    
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

  if( z )
  {
    // Calculate range x ∈ 2^λ2
    mbedtls_printf( "ok. Calculate range for alpha and beta (2^lambda_2), please wait...\n" );
    fflush( stdout );
    int range = 1;
    range = range << (lambda_2 - 3 );
    char range_char = range + '0';
    const char *ptr = &range_char;
    mbedtls_mpi_read_string( &mpi_val, 10, ptr); // Set range as mpi
    
    // Seed drbg
    mbedtls_printf( "ok. Seed drbg, please wait...\n" );
    fflush( stdout );
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) );
    if( ret != 0 )
    {
      mbedtls_printf("ERROR. mbedtls_ctr_drbg_seed got ret = %d\n", ret);
    }

    // Use seeded drbg to generate a secret exponent alpha ∈  ]0, 2^λ2[
      // FIXME: fix range
    mbedtls_printf( "ok. Use seeded drbg to generate a secret exponent x in  ]0, 2^lambda_2[, please wait...\n" );
    fflush( stdout );
    ret = mbedtls_mpi_fill_random( &info.a, 10, mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
      mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
    }

    // Use seeded drbg to generate a secret exponent beta ∈  ]0, 2^λ2[
    mbedtls_printf( "ok. Use seeded drbg to generate a secret exponent x in  ]0, 2^lambda_2[, please wait...\n" );
    fflush( stdout );
    ret = mbedtls_mpi_fill_random( &info.b, 5, mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
      mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
    }

    mbedtls_printf( "ok. Clean up and return, please wait...\n" );
    fflush( stdout );
    mbedtls_mpi_free( &mpi_val );     mbedtls_mpi_free( &mpi_val1 );
    mbedtls_entropy_free( &entropy ); mbedtls_ctr_drbg_free( &ctr_drbg );

    // Return vulues to member
    mbedtls_printf( "ok. Return values to member , please wait...\n" );
    fflush( stdout );
    return info;
  }
  else
  {
    // Select random prime in range of Gamma
    mbedtls_printf( "ok. Select random prime in range of Gamma, please wait...\n" );
    fflush( stdout );
    // int range = (2^(gamma_1)) + (2^(gamma_2)); // range Γ = ]2^gamma_1 - 2^gamma_2, 2^gamma_1 + 2^gamma_2[

    // Seed drbg
    mbedtls_printf( "ok. Seed drbg, please wait...\n" );
    fflush( stdout );
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) );
    if( ret != 0 )
    {
      mbedtls_printf("ERROR. mbedtls_ctr_drbg_seed got ret = %d\n", ret);
    }

    // Use seeded drbg to generate a secret exponent alpha ∈  ]0, 2^λ2[
    mbedtls_printf( "ok. Use seeded drbg to get ei, please wait...\n" );
    fflush( stdout );
    ret = mbedtls_mpi_fill_random( &info.b, 5, mbedtls_ctr_drbg_random, &ctr_drbg ); //FIXME: use correct lenght
    if( ret != 0 )
    {
      mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
    }

    // Compute Ai = (C2a0)^1/ei mod n
    mbedtls_printf( "ok. Compute Ai, please wait...\n" );
    fflush( stdout );
    mbedtls_mpi_mul_mpi( &mpi_val, &a0, &x ); // C2*a0 
    mbedtls_mpi_inv_mod( &mpi_val1, &mpi_val, &n ); // 1 / C2*a0 
    mbedtls_mpi_exp_mod( &info.a, &mpi_val1, &info.b, &n, NULL ); // ( 1 / C2*a0 )^e

    mbedtls_printf( "ok. Clean up and return, please wait...\n" );
    fflush( stdout );
    mbedtls_mpi_free( &mpi_val );     mbedtls_mpi_free( &mpi_val1 );
    mbedtls_entropy_free( &entropy ); mbedtls_ctr_drbg_free( &ctr_drbg );

    // Return vulues to member
    mbedtls_printf( "ok. Return values to member , please wait...\n" );
    fflush( stdout );
    return info;
  }

  return info;
}

// void open( struct pk_struct pk, struct sign_stuct sign, struct cert_struct cert )
// {
//   mbedtls_printf( "\n\n####### MANAGER OPEN ####### \n" );
//   fflush( stdout );
//   if( verify( pk, sign ) )
//   {
//     // Initilize and introduce temperoral variables
//     mbedtls_printf( "ok. Initilize and introduce temperoral variables, please wait...\n" );
//     fflush( stdout );
//     mbedtls_mpi A, mpi_val;
//     mbedtls_mpi_init( &A ); mbedtls_mpi_init( &mpi_val );

//     // Calculate Ai 
//     mbedtls_printf( "ok. Caluclate Ai, please wait...\n" );
//     fflush( stdout );
//     mbedtls_mpi_exp_mod( &mpi_val, &sign.T2, &cert.x, &pk.n, NULL); // T2^c mod n 
//     mbedtls_mpi_inv_mod( &mpi_val, &mpi_val, &pk.n ); // inv T2^x mod n 
//     mbedtls_mpi_mul_mpi( &A, &mpi_val, &sign.T1 ); // T1/T2^x
//     mbedtls_mpi_mod_mpi( &A, &A, &pk.n ); //  T1/T2^x mod n 

//     // See whether Ai matches the certificate value
//     mbedtls_printf( "ok. Check whether A matches the certificate value, please wait...\n" );
//     fflush( stdout );
//   }
//   else 
//   {
//     mbedtls_printf( "ok. Signature can not be verified , please wait...\n" );
//     fflush( stdout );
//   }
// }

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
