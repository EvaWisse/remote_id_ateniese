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
#include "mbedtls/sha256.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "shared.h"
#include "manager.h"
mbedtls_sha256_context ctx_hash;

void verify_hash( mbedtls_mpi x )
{
  size_t len = mbedtls_mpi_bitlen( &x ); // get size
  const unsigned char *buf = ( unsigned char *) malloc(len); // initlize buffer
  mbedtls_mpi_write_string( &x, 10, buf, len, &len); // mpi to unsigned hash
  if ( ( mbedtls_sha256_update( &ctx_hash, buf, len) ) != 0)
  {
    mbedtls_mpi_write_file("ERROR. Could not hash ", &x, 10, NULL );
    fflush( stdout );
  } 
  free((char*)buf);
}

void verify( struct pk_struct pk, struct sign_struct sign )
{
  mbedtls_printf( "\n\n####### VERIFY ####### \n");
  fflush( stdout );

  // Initilize and introduce temperoral variables
  mbedtls_printf( "ok. Initilize and introduce temperoral variables, please wait...\n" );
  fflush( stdout );
  int ret = 1; 
  mbedtls_mpi mpi_val, mpi_val1, mpi_val2, d1, d2, d3, d4, neg, c, max, two, temp_range; 
   char char_temp[64];
  mbedtls_mpi_init( &mpi_val ); mbedtls_mpi_init( &mpi_val1 );  mbedtls_mpi_init( &mpi_val2 ); 
  mbedtls_mpi_init( &d1 );      mbedtls_mpi_init( &d2 );        mbedtls_mpi_init( &d3 );     
  mbedtls_mpi_init( &d4 );      mbedtls_mpi_init( &two );       mbedtls_mpi_init( &c );
  mbedtls_mpi_init( &max );     mbedtls_mpi_init( &temp_range );
  mbedtls_mpi_read_string( &two, 10, "2" )  ;
  mbedtls_mpi_read_string( &max, 10, "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708340403154190335");

  // Calculate d1 = a0^c T1^(s1 - c2^gamma_1) / (a^(s2-c2^delta_1) y^s3 )
  mbedtls_printf( "ok. Create d1 with public information, please wait...\n" );
  fflush( stdout );
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &temp_range, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &temp_range, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1
  mbedtls_mpi_exp_mod( &mpi_val1, &sign.T1, &mpi_val2, &pk.n, NULL ); // T1^(s1 - c2^gamma_1)
  mbedtls_mpi_inv_mod( &mpi_val2, &pk.y, &pk.n ); // inv y
	mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &sign.s3, &pk.n, NULL ); // 1 / y^s3
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T1^(s1 - c2^gamma_1) / y^s3 
  mbedtls_mpi_mod_mpi( &mpi_val, &mpi_val2, &pk.n ); // T1^(s1 - c2^gamma_1) / y^s3  mod n 

  snprintf(char_temp, 64, "%lld", lambda_1);
  mbedtls_mpi_read_string( &temp_range, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &temp_range, &max, NULL ); // 2^lambda_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^lambda_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s2, &mpi_val1 ); // s2 - c*2^lambda_1
	mbedtls_mpi_inv_mod( &mpi_val1, &pk.a, &pk.n ); // inv a mod n
	mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val1, &mpi_val2, &pk.n, NULL );  // 1 / a^(s2-c2^delta_1)
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1)
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); // T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) mod n
  mbedtls_mpi_exp_mod( &mpi_val, &pk.a0, &sign.c, &pk.n, NULL ); // a0^c 
  mbedtls_mpi_mul_mpi( &d1, &mpi_val, &mpi_val2 ); // a0^c * T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) 
  mbedtls_mpi_mod_mpi( &d1, &d1, &pk.n ); // a0^c * T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) mod n


  // Compute d2 = T2^(s1 - c2^gamma_1 ) / g^s3
  mbedtls_printf( "ok. Create d2 with public information, please wait...\n" );
  fflush( stdout );
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &temp_range, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &temp_range, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  mbedtls_mpi_exp_mod( &mpi_val1, &sign.T2, &mpi_val2, &pk.n, NULL ); // T2^ ( s1 - c*2^gamma_1 )
	mbedtls_mpi_inv_mod( &mpi_val2, &pk.g, &pk.n ); // inv g mod n
  mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &sign.s3, &pk.n, NULL ); // 1 / g^s3
  mbedtls_mpi_mul_mpi( &d2, &mpi_val, &mpi_val1 ); // T2^(s1 - c2^gamma_1 ) / g^s3
  mbedtls_mpi_mod_mpi( &d2, &d2, &pk.n ); // T2^(s1 - c2^gamma_1 ) / g^s3 mod n 

  // Compute d3 =  T2^c * g^s4
  mbedtls_printf( "ok. Create d3 with public information, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_exp_mod( &mpi_val, &sign.T2, &sign.c, &pk.n, NULL ); // T2^c 
	mbedtls_mpi_exp_mod( &mpi_val2, &pk.g, &sign.s4, &pk.n, NULL ); // g^s4
  mbedtls_mpi_mul_mpi( &d3, &mpi_val, &mpi_val2 ); // T2^c * g^s4
  mbedtls_mpi_mod_mpi( &d3, &d3, &pk.n); // T2^c * g^s4 mod n 

  // Compute T3^c g^(s1- c2^gamma1) * h^s4
  mbedtls_printf( "ok. Create d4 with public information, please wait...\n" );
  fflush( stdout );
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &temp_range, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &temp_range, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  mbedtls_mpi_exp_mod( &mpi_val1, &pk.g, &mpi_val2, &pk.n, NULL ); // g^(s1 - c*2^gamma_1) 
  mbedtls_mpi_exp_mod( &mpi_val, &sign.T3, &sign.c, &pk.n, NULL ); // T3^c mod n 
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T3^c * g^(s1 - c*2^gamma_1) 
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); //  T3^c * g^(s1 - c*2^gamma_1)  mod n 
  mbedtls_mpi_exp_mod( &mpi_val, &pk.h, &sign.s4, &pk.n, NULL ); // h^s4 mod n 
  mbedtls_mpi_mul_mpi( &d4, &mpi_val2, &mpi_val); // h^s4 * T3^c * g^(s1 - c*2^gamma_1)
  mbedtls_mpi_mod_mpi( &d4, &d4, &pk.n ); // // h^s4 * T3^c * g^(s1 - c*2^gamma_1) mod n

  // Create signature
  mbedtls_printf( "ok. Initilize sha256 variables, please wait...\n" );
  fflush( stdout );
  uint8_t hash[32];
  mbedtls_sha256_init( &ctx_hash );
  if ( ( ret = mbedtls_sha256_starts( &ctx_hash, 0) ) != 0 )
  {
    mbedtls_printf( "ERROR. mbedtls_sha256_starts_ret returns %d \n.", ret  );
  }

  verify_hash( pk.a0 );
  verify_hash( pk.a );
  verify_hash( pk.g );
  verify_hash( pk.h );
  verify_hash( pk.n );
  verify_hash( pk.y);

  verify_hash( sign.T1 );
  verify_hash( sign.T2 );
  verify_hash( sign.T3 );

  // verify_hash( d1 );
  // verify_hash( d2 );
  // verify_hash( d3 );
  // verify_hash( d4 );

  mbedtls_printf( "ok. Finilize hash, please wait...\n" );
  fflush( stdout );
  if( ( ret = mbedtls_sha256_finish( &ctx_hash, hash ) ) != 0 )
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
  mbedtls_mpi_read_string( &c, 10, buffer); // write to sign.c

	if( (ret = mbedtls_mpi_cmp_mpi( &sign.c, &c ) ) != 0 )
	{
		mbedtls_printf( "ERROR. Hash not equal please wait...\n" );
 		fflush( stdout );
	}
	else
	{
		mbedtls_printf( "ok. Verified, please wait...\n" );
  	fflush( stdout );
	}
	
  mbedtls_printf( "ok. Clean up and return, please wait...\n" );
  fflush( stdout );
  mbedtls_mpi_free( &mpi_val ); mbedtls_mpi_free( &mpi_val1 );  mbedtls_mpi_free( &mpi_val2 );         
  mbedtls_mpi_free( &d1 );      mbedtls_mpi_free( &d2 );        mbedtls_mpi_free( &d3 );            
  mbedtls_mpi_free( &d4 );      mbedtls_mpi_free( &two );       mbedtls_mpi_free( &max );
}


#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */