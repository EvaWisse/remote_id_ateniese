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

int main( void )
{
  int exit_code = MBEDTLS_EXIT_FAILURE;
  struct pk_struct pk;
  struct cert_struct cert; 
  mbedtls_mpi_init( &pk.n ); mbedtls_mpi_init( &pk.a ); mbedtls_mpi_init( &pk.a0 );
  mbedtls_mpi_init( &pk.y ); mbedtls_mpi_init( &pk.g ); mbedtls_mpi_init( &pk.h );
  mbedtls_mpi_init( &cert.A ); mbedtls_mpi_init( &cert.e ); mbedtls_mpi_init( &cert.x );

  pk = manager_setup();
  print_pk_to_file( pk );
  cert = member_join( pk );
  // print_cert_to_file( cert );

  exit_code = MBEDTLS_EXIT_SUCCESS;

  if( exit_code != MBEDTLS_EXIT_SUCCESS )
  {
      mbedtls_printf( "\nAn error occurred.\n" );
  }

  mbedtls_exit( exit_code );
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
