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
#include "mbedtls/sha256.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>

#include "shared.h"
mbedtls_sha256_context ctx;

struct cert_struct member_join( struct pk_struct pk )
{
  mbedtls_printf( "\n\n####### JOIN MEMBER PART 1 ####### \n");
  fflush( stdout );

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
  // mbedtls_printf( " rang = %d, lambda_2 %d\n", range, lambda_2);
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
  
  mbedtls_mpi_safe_cond_swap( &cert.A, &manager_info.a, 1 );
  mbedtls_mpi_safe_cond_swap( &cert.e, &manager_info.b, 1 );

  mbedtls_printf( "ok. Clean up and return, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_init( &C1 );  mbedtls_mpi_free( &C2 );              mbedtls_mpi_free( &mpi_val );         mbedtls_mpi_free( &mpi_val1 );
  mbedtls_mpi_free( &x );   mbedtls_mpi_free( &manager_info.a );  mbedtls_mpi_free( &manager_info.b );  mbedtls_mpi_free( &mpi_range); 
  mbedtls_mpi_free( &r );   mbedtls_entropy_free( &entropy );     mbedtls_ctr_drbg_free( &ctr_drbg );

  return cert;
}

void add_hash( mbedtls_mpi x )
{
  size_t len = mbedtls_mpi_bitlen( &x ); // get size
  const unsigned char *buf = ( unsigned char *) malloc(len); // initlize buffer
  mbedtls_mpi_write_string( &x, 10, buf, len, &len); // mpi to unsigned hash
  if ( ( mbedtls_sha256_update( &ctx, buf, len) ) != 0)
  {
    mbedtls_mpi_write_file("ERROR. Could not hash ", &x, 10, NULL );
    fflush( stdout );
  } 
  free((char*)buf);
}

struct sign_struct gen_sign( struct pk_struct pk, struct cert_struct cert )
{
  mbedtls_printf( "\n\n####### SIGN MEMBER PART ####### \n");
  fflush( stdout );

  // Initilize signature
  mbedtls_printf( "ok. Intilize signature, please wait...\n" );
  fflush( stdout );
  struct sign_struct sign; 
  mbedtls_mpi_init( &sign.c );  mbedtls_mpi_init( &sign.s1 ); mbedtls_mpi_init( &sign.s2 );
  mbedtls_mpi_init( &sign.s3 ); mbedtls_mpi_init( &sign.s4 ); mbedtls_mpi_init( &sign.T1 );
  mbedtls_mpi_init( &sign.T2 ); mbedtls_mpi_init( &sign.T3 );
 
  // Initilize and introduce temperoral variables
  mbedtls_printf( "ok. Initilize and introduce temperoral variables, please wait...\n" );
  fflush( stdout );
  int ret = 1; 
  mbedtls_mpi mpi_val, mpi_val1, mpi_val2, w, r1, r2, r3, r4, d1, d2, d3, d4;
  mbedtls_mpi_init( &mpi_val ); mbedtls_mpi_init( &mpi_val1 );  mbedtls_mpi_init( &mpi_val2 );  mbedtls_mpi_init( &w );
  mbedtls_mpi_init( &r1 );      mbedtls_mpi_init( &r2 );        mbedtls_mpi_init( &r3 );        mbedtls_mpi_init( &r4 );
  mbedtls_mpi_init( &d1 );      mbedtls_mpi_init( &d2 );        mbedtls_mpi_init( &d3 );        mbedtls_mpi_init( &d4 );

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

  // Seed drbg
  mbedtls_printf( "ok. Seed drbg, please wait...\n" );
  fflush( stdout );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_ctr_drbg_seed got ret = %d\n", ret);
  }

  // Use seeded drbg to generate a secret exponent w of lenght 2lp
  mbedtls_printf( "ok. Use seeded drbg to generate a secret exponent w of lenght 2lp, please wait...\n" );
  fflush( stdout );
  int range_ceil = ceil((2*lp>>3));
  ret = mbedtls_mpi_fill_random( &w, range_ceil, mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
  }

  // Calculate T1
  mbedtls_printf( "ok. Calculate T1, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &mpi_val, &pk.y, &w, &pk.n, NULL ); // y^w mod n
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &cert.A ); // A * y^w 
  mbedtls_mpi_mod_mpi( &sign.T1, &mpi_val1, &pk.n ); // A * y^w mod n

  // Calculate T2
  mbedtls_printf( "ok. Calculate T2, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &sign.T2, &pk.g, &w, &pk.n, NULL); // g^w mod n

  // Calculate T3
  mbedtls_printf( "ok. Calculate T3, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &mpi_val, &pk.g, &cert.e, &pk.n, NULL ); // g^e mod n
  mbedtls_mpi_exp_mod( &mpi_val1, &pk.h, &w, &pk.n, NULL ); // h^w mod n
  mbedtls_mpi_mul_mpi( &sign.T3, &mpi_val, &mpi_val1 ); // h^w * g^e
  mbedtls_mpi_mod_mpi( &sign.T3, &sign.T3, &pk.n ); // h^w * g^e mod n

  // Choose r1
  mbedtls_printf( "ok. Use seeded drbg to generate r1, please wait...\n" );
  fflush( stdout );
  range_ceil = ceil(( epsilon * ( gamma_2 + k )) >> 3);
  ret = mbedtls_mpi_fill_random( &r1, range_ceil , mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
  }
   
  // Choose r2
   mbedtls_printf( "ok. Use seeded drbg to generate r2, please wait...\n" );
  fflush( stdout );
  range_ceil = ceil(( epsilon * ( lambda_2 + k )) >> 3);
  ret = mbedtls_mpi_fill_random( &r2, range_ceil , mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
  }

  // Choose r3
  mbedtls_printf( "ok. Use seeded drbg to generate r3, please wait...\n" );
  fflush( stdout );
  range_ceil = ceil(( epsilon * ( gamma_1 + 2 * lp + k + 1 )) >> 3 );
  ret = mbedtls_mpi_fill_random( &r3, range_ceil , mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
  }
  
  // Choose r4
  mbedtls_printf( "ok. Use seeded drbg to generate r4, please wait...\n" );
  fflush( stdout );
  range_ceil = ceil((epsilon * ( 2 * lp + k )) >> 3);
  ret = mbedtls_mpi_fill_random( &r4, range_ceil , mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf("ERROR. mbedtls_mpi_fill_random got ret = %d\n", ret);
  }

  // Compute d1  = T1^r1/(a^r2y^r3)
  mbedtls_printf( "ok. Calculate d1, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &mpi_val1, &sign.T1, &r1, &pk.n, NULL ); // T1^r1 mod n 
  mbedtls_mpi_inv_mod( &mpi_val2, &pk.a, &pk.n ); // inv a mod n
  mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &r2, &pk.n, NULL ); // 1 / a^r2
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val ); // ( 1 / a^r2 ) * T1^r1
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); // ( 1 / a^r2 ) * T1^r1 mod n

  mbedtls_mpi_inv_mod( &mpi_val, &pk.y, &pk.n ); // inv y mod n
  mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val, &r3, &pk.n, NULL ); // 1 / y^r3 mod n
  mbedtls_mpi_mul_mpi( &d1, &mpi_val1, &mpi_val2 );  // ( a^r2 * T1^r1 ) / y^r3
  mbedtls_mpi_mod_mpi( &d1, &d1, &pk.n ); // ( a^r2 * T1^r1 ) / y^r3 mod n 

  // Compute d2  T2^r1/g^r3
  mbedtls_printf( "ok. Calculate d2, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_inv_mod( &mpi_val1, &pk.g, &pk.n ); // inv g
  mbedtls_mpi_exp_mod( &mpi_val, &mpi_val1, &r3, &pk.n, NULL ); // 1 / g^r3 
  mbedtls_mpi_exp_mod( &mpi_val1, &sign.T2, &r1, &pk.n, NULL ); // T2^r1
  mbedtls_mpi_mul_mpi( &d2, &mpi_val1, &mpi_val ); // T2^r1 * ( 1 / g^r3 )
  mbedtls_mpi_mod_mpi( &d2, &d2, &pk.n ); // T2^r1 * ( 1 / g^r3 ) mod n
  
  // Compute d3 = g^r4
  mbedtls_printf( "ok. Calculate d3, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &d3, &pk.g, &r4, &pk.n, NULL ); // g^r4 mod n

  // Compute d4  = g^r1 * h^r4
  mbedtls_printf( "ok. Calculate d4, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &mpi_val1, &pk.h, &r4, &pk.n, NULL ); // h^r4 mod n
  mbedtls_mpi_exp_mod( &mpi_val2, &pk.g, &r1, &pk.n, NULL ); // g^r1 mod n
  mbedtls_mpi_mul_mpi( &d4, &mpi_val1, &mpi_val2 ); // g^r1 * h^r4
  mbedtls_mpi_mod_mpi( &d4, &d4, &pk.n ); // g^r1 * h^r4 mod n

  // Create signature
  mbedtls_printf( "ok. Initilize sha256 variables, please wait...\n" );
  fflush( stdout );
  uint8_t hash[32];
  mbedtls_sha256_init( &ctx );
  if ( ( ret = mbedtls_sha256_starts( &ctx, 0) ) != 0 )
  {
    mbedtls_printf( "ERROR. mbedtls_sha256_starts_ret returns %d \n.", ret  );
  }

  add_hash( pk.a0 );
  add_hash( pk.a );
  add_hash( pk.g );
  add_hash( pk.h );
  add_hash( pk.n );
  add_hash( pk.y);

  add_hash( sign.T1 );
  add_hash( sign.T2 );
  add_hash( sign.T3 );

  // add_hash( d1 );
  // add_hash( d2 );
  // add_hash( d3 );
  // add_hash( d4 );

  mbedtls_printf( "ok. Finilize hash, please wait...\n" );
  fflush( stdout );
  if( ( ret = mbedtls_sha256_finish( &ctx, hash ) ) != 0 )
  {
    mbedtls_printf( "ERROR. Finilize hash\n" );
    fflush( stdout );
  }

  mbedtls_printf( "ok. Convert hash to Bignum, please wait...\n" );
  fflush( stdout );
  char buffer[256];
  int j = 0;
  for ( int i = 0; i < 32; i++ )
  {
    j += snprintf(buffer+j, 8, "%d", hash[i]); // concatenate values
  }
  mbedtls_mpi_read_string( &sign.c, 10, buffer); // write to sign.c

  mbedtls_printf( "ok. Calculate r1, please wait...\n" );
  fflush( stdout );
  int temp = 1;
  temp = temp << (gamma_1 - 3); // TODO: check wheteher we need to use bignum
  char temp_char = temp + '0';
  const char *ptr = &temp_char;
  mbedtls_mpi_read_string( &mpi_val, 10, ptr ); // 2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val1, &cert.e, &mpi_val ); //  e - 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &sign.c ); // c * (e - gamma_1 )
  mbedtls_mpi_sub_mpi( &sign.s1, &r1, &mpi_val2 ); // r1 - c * (e - gamma_1 )
  
  // s2 = r2 - c( x - 2^delta_1 )
  mbedtls_printf( "ok. Calculate r2, please wait...\n" );
  fflush( stdout ); 
  temp = 1;
  temp = temp << (lambda_1 - 3);
  temp_char = temp + '0';
  ptr = &temp_char;
  mbedtls_mpi_read_string( &mpi_val, 10, ptr ); // 2^lambda_1
  mbedtls_mpi_sub_mpi( &mpi_val1, &cert.x, &mpi_val ); //  x - 2^lambda_1
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &sign.c ); // c * ( x - 2^lambda_1 )
  mbedtls_mpi_sub_mpi( &sign.s2, &r2, &mpi_val2 ); // r2 - c * ( x - 2^lambda_1 )

  // s3 = r3 - c * e * w
  mbedtls_printf( "ok. Calculate r3, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_mul_mpi( &mpi_val, &sign.c, &cert.e ); // c * e
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &w); // w * c * e
  mbedtls_mpi_sub_mpi( &sign.s3, &r3, &mpi_val1 ); // r3 - c * e * w

  // s4 = r4 - c * w
  mbedtls_printf( "ok. Calculate r4, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_mul_mpi( &mpi_val, &sign.c, &w); // c * w
  mbedtls_mpi_sub_mpi( &sign.s4, &r4, &mpi_val ); // r4 -c * w

  mbedtls_printf( "ok. Clean up and return, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_free( &mpi_val );     mbedtls_mpi_free( &mpi_val1 );      mbedtls_mpi_free( &mpi_val2 );
  mbedtls_mpi_free( &w );           mbedtls_mpi_free( &r1 );            mbedtls_mpi_free( &r2 );          
  mbedtls_mpi_free( &r3 );          mbedtls_mpi_free( &r4 );            mbedtls_mpi_free( &d1 );      
  mbedtls_mpi_free( &d2 );          mbedtls_mpi_free( &d3 );            mbedtls_mpi_free( &d4 );
  mbedtls_entropy_free( &entropy ); mbedtls_ctr_drbg_free( &ctr_drbg );

 return sign;
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
