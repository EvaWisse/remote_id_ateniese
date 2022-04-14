/*
 * Simple group signature demonstration program
 *
 * This program call the group signature functions and demonstrates its use
 * 
 * Max value is 2^(8*1024) since BEDTLS_MPI_MAX_SIZE = 1024 -> the Maximum number of bytes for usable MPIs.
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

int main( void )
{
  int exit_code = MBEDTLS_EXIT_FAILURE; 
  struct pk_struct pk;
  struct cert_struct cert;
  struct sign_struct sign;
  mbedtls_mpi_init( &pk.n );    mbedtls_mpi_init( &pk.a );    mbedtls_mpi_init( &pk.a0 );
  mbedtls_mpi_init( &pk.y );    mbedtls_mpi_init( &pk.g );    mbedtls_mpi_init( &pk.h );
  mbedtls_mpi_init( &cert.A );  mbedtls_mpi_init( &cert.e );  mbedtls_mpi_init( &cert.x );
  mbedtls_mpi_init( &sign.c );  mbedtls_mpi_init( &sign.s1 ); mbedtls_mpi_init( &sign.s2 );
  mbedtls_mpi_init( &sign.s3 ); mbedtls_mpi_init( &sign.s4 ); mbedtls_mpi_init( &sign.T1 );
  mbedtls_mpi_init( &sign.T2 ); mbedtls_mpi_init( &sign.T3 );
 
  pk = manager_setup( &exit_code );
  if ( exit_code != 0 )
  {
    mbedtls_printf( " Failed setup ");
    goto exit;
  }
  print_pk_to_file( pk );
  if ( member_join( pk, &cert ) != 0 )
  {
    mbedtls_printf( " Failed join ");
    goto exit;
  }
  print_cert_to_file( cert );
  
  if ( gen_sign( pk, cert, &sign ) != 0 )
   {
    mbedtls_printf( " Failed signature gen ");
    goto exit;
  }
  print_sign_to_file( sign );
  if ( verify( pk, sign ) != 0 ) printf(  "authentication failed \n");
  else printf("authenticated\n");
  
  // if ( open( pk, sign, cert ) !=0 )
  // {
  //   printf("could not be opened" );
  // }
  // else 
  // { 
  //   printf("opend\n");
  // }


exit:
  return 0;
}

void print_sign_to_file(  struct sign_struct sign )
{
  FILE *fout;
  if( ( fout = fopen( "group_sig/sign.txt", "w" ) ) == NULL )
  {
    mbedtls_printf( " failed.  Could not create result.txt\n" );
  }
  mbedtls_mpi_write_file( "sign.c = ", &sign.c, 10, fout );
  mbedtls_mpi_write_file( "sign.s1 = ", &sign.s1, 10, fout );
  mbedtls_mpi_write_file( "sign.s2 = ", &sign.s2, 10, fout );
  mbedtls_mpi_write_file( "sign.s3 = ", &sign.s3, 10, fout );
  mbedtls_mpi_write_file( "sign.s4 = ", &sign.s4, 10, fout );
  mbedtls_mpi_write_file( "sign.T1 = ", &sign.T1, 10, fout );
  mbedtls_mpi_write_file( "sign.T2 = ", &sign.T2, 10, fout );
  mbedtls_mpi_write_file( "sign.T3 = ", &sign.T3, 10, fout );
}

void print_cert_to_file( struct cert_struct cert)
{
  FILE *fout;
  if( ( fout = fopen( "group_sig/cert.txt", "w" ) ) == NULL )
  {
    mbedtls_printf( " failed.  Could not create result.txt\n" );
  }
  mbedtls_mpi_write_file( "cert.A = ", &cert.A, 10, fout );
  mbedtls_mpi_write_file( "cert.e = ", &cert.e, 10, fout );
  mbedtls_mpi_write_file( "cert.x = ", &cert.x, 10, fout );
}

void print_pk_to_file( struct pk_struct pk )
{
  FILE *fout;
  if( ( fout = fopen( "group_sig/pk.txt", "w" ) ) == NULL )
  {
    mbedtls_printf( " failed.  Could not create result.txt\n" );
  }
  mbedtls_mpi_write_file( "pk.n = ", &pk.n, 10, fout );
  mbedtls_mpi_write_file( "pk.a = ", &pk.a, 10, fout );
  mbedtls_mpi_write_file( "pk.a0 = ", &pk.a0, 10, fout );
  mbedtls_mpi_write_file( "pk.y = ", &pk.y, 10, fout );
  mbedtls_mpi_write_file( "pk.g = ", &pk.g, 10, fout );
  mbedtls_mpi_write_file( "pk.h = ", &pk.h, 10, fout );
  fclose( fout );
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
