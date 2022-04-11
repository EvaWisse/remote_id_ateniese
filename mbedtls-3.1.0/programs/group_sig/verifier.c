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

int verify( struct pk_struct pk, struct sign_struct sign )
{
  mbedtls_printf( "\n\n####### VERIFY ####### \n");
  fflush( stdout );
  int exit_code = MBEDTLS_EXIT_FAILURE;

  // Initilize and introduce temperoral variables
  mbedtls_printf( "ok. Initilize and introduce temperoral variables, please wait...\n" );
  fflush( stdout );
  int ret = 1; 
  struct manager_info_struct manager_info;
  mbedtls_mpi mpi_val, mpi_val1, mpi_val2, d1, d2, d3, d4, neg; 
  mbedtls_mpi_init( &mpi_val ); mbedtls_mpi_init( &mpi_val1 );  mbedtls_mpi_init( &mpi_val2 ); 
  mbedtls_mpi_init( &d1 );      mbedtls_mpi_init( &d2 );        mbedtls_mpi_init( &d3 );     
  mbedtls_mpi_init( &d4 );      mbedtls_mpi_init( &neg );

  // Calculate d1 = a0^c T1^(s1 - c2^gamma_1) / (a^(s2-c2^delta_1) y^s3 )
  mbedtls_printf( "ok. Create d1 with public information, please wait...\n" );
  fflush( stdout );
  int temp = 1;
  temp = temp << gamma_1;
  char temp_char = temp + '0';
  const char *ptr = &temp_char;
  mbedtls_mpi_read_string( &mpi_val, 10, ptr ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  
  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) != 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val, &sign.T1, &pk.n ); // inv T1 mod n
    mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val, &mpi_val2, &pk.n, NULL ); // T1^(s1 - c2^gamma_1) FIXME: make pos
  }
  else
  {  
    mbedtls_mpi_exp_mod( &mpi_val1, &sign.T1, &mpi_val2, &pk.n, NULL ); // T1^(s1 - c2^gamma_1)
  }

  mbedtls_mpi_sub_mpi( &neg, &sign.s3, &sign.s3 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) != 0 )
  {
    mbedtls_mpi_exp_mod( &mpi_val, &pk.y, &sign.s3, &pk.n, NULL ); // 1 / y^s3 FIXME: make abs
  }
  else 
  {
    mbedtls_mpi_inv_mod( &mpi_val2, &pk.y, &pk.n ); // inv y
    mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &sign.s3, &pk.n, NULL ); // 1 / y^s3
  }
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T1^(s1 - c2^gamma_1) / y^s3 
  mbedtls_mpi_mod_int( &mpi_val, &mpi_val2, &pk.n ); // T1^(s1 - c2^gamma_1) / y^s3  mod n 
  
  temp = 1;
  temp = temp << lambda_1;
  temp_char = temp + '0';
  ptr = &temp_char;
  mbedtls_mpi_read_string( &mpi_val, 10, ptr ); // 2^lambda_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^lambda_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s2, &mpi_val1 ); // s2 - c*2^lambda_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) != 0 ) 
  {
    mbedtls_mpi_exp_mod( &mpi_val1, &pk.a, &mpi_val2, &pk.n, NULL ); // 1 / a^(s2-c2^delta_1) FIXME: make abs
  }
  else 
  {
    mbedtls_mpi_inv_mod( &mpi_val1, &pk.a, &pk.n ); // inv a mod n
    mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val1, &mpi_val2, &pk.n, NULL );  // 1 / a^(s2-c2^delta_1)
  }
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1)
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); // T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) mod n
  mbedtls_mpi_exp_mod( &mpi_val, &pk.a0, &sign.c, &pk.n, NULL ); // a0^c 
  mbedtls_mpi_mul_mpi( &d1, &mpi_val, &mpi_val2 ); // a0^c * T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) 
  mbedtls_mpi_mod_int( &d1, &d1, &pk.n ); // a0^c * T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) mod n


  // Compute d2 = T2^(s1 - c2^gamma_1 ) / g^s3
  mbedtls_printf( "ok. Create d2 with public information, please wait...\n" );
  fflush( stdout );
  temp = 1;
  temp = temp << gamma_1;
  temp_char = temp + '0';
  ptr = &temp_char;
  mbedtls_mpi_read_string( &mpi_val, 10, ptr ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) != 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val, &sign.T2, &pk.n ); // inv T2
    mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val, &mpi_val2, &pk.n, NULL ); // T2^ ( s1 - c*2^gamma_1 ) FIXME:mak pos
  }
  else
  {
    mbedtls_mpi_exp_mod( &mpi_val1, &sign.T2, &mpi_val2, &pk.n, NULL ); // T2^ ( s1 - c*2^gamma_1 )
  }
  
  mbedtls_mpi_sub_mpi( &neg, &sign.s3, &sign.s3 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) != 0 )
  {
    mbedtls_mpi_exp_mod( &mpi_val, &pk.g, &sign.s3, &pk.n, NULL ); // 1 / g^s3 FIXME: make pos
  }
  else
  {
    mbedtls_mpi_inv_mod( &mpi_val2, &pk.g, &pk.n ); // inv g mod n
    mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &sign.s3, &pk.n, NULL ); // 1 / g^s3
  }
  mbedtls_mpi_mul_mpi( &d2, &mpi_val, &mpi_val1 ); // T2^(s1 - c2^gamma_1 ) / g^s3
  mbedtls_mpi_mod_int( &d2, &d2, &pk.n ); // T2^(s1 - c2^gamma_1 ) / g^s3 mod n 

  // Compute d3 =  T2^c * g^s4
  mbedtls_printf( "ok. Create d3 with public information, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &mpi_val, &sign.T2, &sign.c, &pk.n, NULL ); // T2^c 

  mbedtls_mpi_sub_mpi( &neg, &sign.s4, &sign.s4 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) != 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val1, &pk.g, &pk.n ); // inv g mod n
    mbedtls_mpi_exp_mod( &mpi_val2, &mpi_val1, &sign.s4, &pk.n, NULL ); // g^s4 FIXME: make pos
  }
  else 
  {
    mbedtls_mpi_exp_mod( &mpi_val2, &pk.g, &sign.s4, &pk.n, NULL ); // g^s4
  }
  mbedtls_mpi_mul_mpi( &d3, &mpi_val, &mpi_val2 ); // T2^c * g^s4
  mbedtls_mpi_mod_int( &d3, &d3, &pk.n); // T2^c * g^s4 mod n 

  // Compute T3^c g^(s1- c2^gamma1) * h^s4
  mbedtls_printf( "ok. Create d4 with public information, please wait...\n" );
  fflush( stdout );
  temp = 1;
  temp = temp << gamma_1;
  temp_char = temp + '0';
  ptr = &temp_char;
  mbedtls_mpi_read_string( &mpi_val, 10, ptr ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) != 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val, &pk.g, &pk.n ); // inv g mod n
    mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val, &mpi_val2, &pk.n, NULL ); // g^(s1 - c*2^gamma_1) FIXME: make pos
  }
  else 
  {
    mbedtls_mpi_exp_mod( &mpi_val1, &pk.g, &mpi_val2, &pk.n, NULL ); // g^(s1 - c*2^gamma_1) 
  }
  mbedtls_mpi_exp_mod( &mpi_val, &sign.T3, &sign.c, &pk.n, NULL ); // T3^c mod n 
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T3^c * g^(s1 - c*2^gamma_1) 
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); //  T3^c * g^(s1 - c*2^gamma_1)  mod n 

  mbedtls_mpi_sub_mpi( &neg, &sign.s4, &sign.s4 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) != 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val1, &pk.h, &pk.n); // inv h mod n 
    mbedtls_mpi_exp_mod( &mpi_val, &mpi_val1, &sign.s4, &pk.n, NULL ); // h^s4 mod n  FIXME: make pos
  }
  else 
  {
    mbedtls_mpi_exp_mod( &mpi_val, &pk.h, &sign.s4, &pk.n, NULL ); // h^s4 mod n 
  }
  mbedtls_mpi_mul_mpi( &d4, &mpi_val2, &mpi_val); // h^s4 * T3^c * g^(s1 - c*2^gamma_1)
  mbedtls_mpi_mod_int( &d4, &d4, &pk.n ); // // h^s4 * T3^c * g^(s1 - c*2^gamma_1) mod n

//   TODO: create sign

//   TODO: compore

  mbedtls_printf( "ok. Clean up and return, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_free( &mpi_val ); mbedtls_mpi_free( &mpi_val1 );  mbedtls_mpi_free( &mpi_val2 );         
  mbedtls_mpi_free( &d1 );      mbedtls_mpi_free( &d2 );        mbedtls_mpi_free( &d3 );            
  mbedtls_mpi_free( &d4 );      mbedtls_mpi_free( &neg );
  
  return 1; 
}


#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */