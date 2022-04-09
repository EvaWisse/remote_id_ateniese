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

struct cert_struct member_join( struct pk_struct pk )
{
  mbedtls_printf( "\n\n####### JOIN MEMBER PART 1 ####### \n");
  fflush( stdout );
  int exit_code = MBEDTLS_EXIT_FAILURE;

  // Initilize certificate
  mbedtls_printf( "ok. Intilize certificate, please wait...\n" );
  fflush( stdout );
  struct cert_struct cert;
  mbedtls_mpi_init( &cert.A ); mbedtls_mpi_init( &cert.e ); mbedtls_mpi_init( &cert.x );

  // Initilize and introduce temperoral variables
  mbedtls_printf( "ok. Initilize and introduce temperoral variables, please wait...\n" );
  fflush( stdout );
  int ret = 1; 
  struct manager_info_struct manager_info;
  mbedtls_mpi C1, C2, mpi_val, mpi_val1, x, mpi_range, r;
  mbedtls_mpi_init( &C1 );  mbedtls_mpi_init( &C2 );              mbedtls_mpi_init( &mpi_val );         mbedtls_mpi_init( &mpi_val1 );
  mbedtls_mpi_init( &x );   mbedtls_mpi_init( &manager_info.a );  mbedtls_mpi_init( &manager_info.b );  mbedtls_mpi_init( &mpi_range); 
  mbedtls_mpi_init( &r );

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

  // Calculate range x ∈ 2^λ2
	mbedtls_printf( "ok. Calculate range for x (2^lambda_2), please wait...\n" );
  fflush( stdout );
  int range = 1;
  range = range << (lambda_2 -2);
  mbedtls_printf( " rang = %d, lambda_2 %d\n", range, lambda_2);
  char range_char = range + '0';
  const char *ptr = &range_char;
  mbedtls_mpi_read_string( &mpi_range, 10, ptr ); // Set range as mpi
	
  // Seed drbg
  mbedtls_printf( "ok. Seed drbg, please wait...\n" );
  fflush( stdout );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_ctr_drbg_seed got ret = %d\n", ret);
  }

  // Use seeded drbg to generate a secret exponent x ∈  ]0, 2^λ2[
  mbedtls_printf( "ok. Use seeded drbg to generate a secret exponent x in  ]0, 2^lamda_2[, please wait...\n" );
  fflush( stdout );
  ret = mbedtls_mpi_fill_random( &x, range, mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
  }
	
  // Calculate range r  ∈ ]0, n^2[   
  mbedtls_printf( "ok. Calculate range r (n^2), please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_mul_mpi( &mpi_val1, &pk.n, &pk.n ); // n * n 
  // mpi to int TODO:

  // Use seeded drbg to generate r in ]0, n^2[
  mbedtls_printf( "ok. Use seeded drbg to generate r in ]0, n^2[, please wait...\n" );
  fflush( stdout );
  ret = mbedtls_mpi_fill_random( &r, range, mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
  }

  // Calculate C1 = g^xh^r mod n
  mbedtls_printf( "ok. Calculate C1, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &mpi_val, &pk.g, &x, &pk.n, NULL); // g^x mod n
  mbedtls_mpi_exp_mod( &mpi_val1, &pk.h, &r, &pk.n, NULL); // h^r mod n
  mbedtls_mpi_mul_mpi( &C1, &mpi_val, &mpi_val1); // g^x * h^r
  mbedtls_mpi_mod_mpi( &C1, &C1, &pk.n); // g^x * h^r mod n

  // Send C1 to manager
  mbedtls_printf( "ok. Send C1 to manager, please wait...\n" );
  fflush( stdout );
  manager_info = manager_join( C1, pk.n, 1, pk.a0 );

  mbedtls_printf( "\n\n####### JOIN MEMBER PART 2 ####### \n");
  fflush( stdout );
  // Compute x = 2^λ1 +(αi xi + βi mod 2^λ2)
  mbedtls_printf( "ok. Compute x = 2^lamda_1 +(alpha_i * xi + beta_i mod 2^2), please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_mul_mpi( &mpi_val, &manager_info.a, &x); // ai * xi
  mbedtls_mpi_add_mpi( &mpi_val1, &mpi_val1, &manager_info.b); // ai * xi + Bi
  mbedtls_mpi_mod_mpi( &mpi_val1, &mpi_val1, &mpi_range); // ai * xi + Bi mod 2^delta2
  mbedtls_mpi_read_string( &mpi_val, 10, "1" ); // set mpi_val to 1
  mbedtls_mpi_shift_l( &mpi_val, lambda_1); // 1 * 2^lambda_1
  mbedtls_mpi_add_mpi( &cert.x, &mpi_val, &mpi_val1); // 2^lambda_1 + (ai * xi + Bi mod 2^delta2)

  // Compute C2 = a^xi mod n
  mbedtls_printf( "ok. Compute C2, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &C2, &pk.a, &cert.x, &pk.n, NULL); 

  // Send C2 to manager
  mbedtls_printf( "ok. Send C2 to manager, please wait...\n" );
  fflush( stdout );
  manager_info = manager_join( C2, pk.n, 0, pk.a0 );

  mbedtls_printf( "\n\n####### JOIN MEMBER PART 3 ####### \n");
  fflush( stdout );
  // Set membership certificate
  mbedtls_printf( "ok. Set membership certificate, please wait...\n" );
  fflush( stdout );
  
  mbedtls_mpi_write_file( " manager_info.a = ", &manager_info.a, 10, NULL);
  mbedtls_mpi_write_file( " manager_info.b = ", &manager_info.b, 10, NULL);
  cert.A = manager_info.a;
  cert.e = manager_info.b;

  mbedtls_mpi_write_file( " cert.a = ", &cert.A, 10, NULL);
  mbedtls_mpi_write_file( " cert.b = ", &cert.e, 10, NULL);
  
  exit_code = MBEDTLS_EXIT_SUCCESS;

  mbedtls_printf( "ok. Clean up and return, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_init( &C1 );  mbedtls_mpi_free( &C2 );              mbedtls_mpi_free( &mpi_val );         mbedtls_mpi_free( &mpi_val1 );
  mbedtls_mpi_free( &x );   mbedtls_mpi_free( &manager_info.a );  mbedtls_mpi_free( &manager_info.b );  mbedtls_mpi_free( &mpi_range); 
  mbedtls_mpi_free( &r );   mbedtls_entropy_free( &entropy );     mbedtls_ctr_drbg_free( &ctr_drbg );

  if( exit_code != MBEDTLS_EXIT_SUCCESS )
  {
	  mbedtls_printf( "\nAn error occurred.\n" );
  }

  return cert;
}


#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
