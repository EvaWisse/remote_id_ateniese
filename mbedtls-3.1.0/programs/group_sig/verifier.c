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

int verify_hash( mbedtls_mpi x )
{
  int  error_code = EXIT_FAILURE;
  size_t len = mbedtls_mpi_bitlen( &x ); // get size
  const unsigned char *buf = ( unsigned char *) malloc(len); // initlize buffer
  mbedtls_mpi_write_string( &x, 10, (char *) buf, len, &len); // mpi to unsigned hash
  if ( ( mbedtls_sha256_update( &ctx_hash, buf, len) ) != 0)
  {
    goto exit;
  } 
  
  error_code = EXIT_SUCCESS;

exit:
  free((char*)buf);

  return error_code;
}

int verify( struct pk_struct pk, struct sign_struct sign )
{
  int exit_code = EXIT_FAILURE;
  int j = 0;
  char char_temp[64];
  char buffer[256];
  uint8_t hash[32];
  mbedtls_mpi mpi_val, mpi_val1, mpi_val2, d1, d2, d3, d4, c, max, two; 

  mbedtls_mpi_init( &mpi_val ); mbedtls_mpi_init( &mpi_val1 );  mbedtls_mpi_init( &mpi_val2 ); 
  mbedtls_mpi_init( &d1 );      mbedtls_mpi_init( &d2 );        mbedtls_mpi_init( &d3 );     
  mbedtls_mpi_init( &d4 );      mbedtls_mpi_init( &two );       mbedtls_mpi_init( &c );
  mbedtls_mpi_init( &max );     mbedtls_sha256_init( &ctx_hash );
  mbedtls_mpi_read_string( &two, 10, "2" )  ;
  mbedtls_mpi_read_string( &max, 10, "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708340403154190335");

  // Calculate d1 = a0^c T1^(s1 - c2^gamma_1) / (a^(s2-c2^delta_1) y^s3 )
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1
  mbedtls_mpi_exp_mod( &mpi_val1, &sign.T1, &mpi_val2, &pk.n, NULL ); // T1^(s1 - c2^gamma_1)
  mbedtls_mpi_inv_mod( &mpi_val2, &pk.y, &pk.n ); // inv y
	mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &sign.s3, &pk.n, NULL ); // 1 / y^s3
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T1^(s1 - c2^gamma_1) / y^s3 
  mbedtls_mpi_mod_mpi( &mpi_val, &mpi_val2, &pk.n ); // T1^(s1 - c2^gamma_1) / y^s3  mod n 

  snprintf(char_temp, 64, "%lld", lambda_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^lambda_1
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
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_exp_mod( &mpi_val1, &sign.T2, &mpi_val2, &pk.n, NULL ); // T2^ ( s1 - c*2^gamma_1 )
	mbedtls_mpi_inv_mod( &mpi_val2, &pk.g, &pk.n ); // inv g mod n
  mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &sign.s3, &pk.n, NULL ); // 1 / g^s3
  mbedtls_mpi_mul_mpi( &d2, &mpi_val, &mpi_val1 ); // T2^(s1 - c2^gamma_1 ) / g^s3
  mbedtls_mpi_mod_mpi( &d2, &d2, &pk.n ); // T2^(s1 - c2^gamma_1 ) / g^s3 mod n 

  // Compute d3 =  T2^c * g^s4
  mbedtls_mpi_exp_mod( &mpi_val, &sign.T2, &sign.c, &pk.n, NULL ); // T2^c 
	mbedtls_mpi_exp_mod( &mpi_val2, &pk.g, &sign.s4, &pk.n, NULL ); // g^s4
  mbedtls_mpi_mul_mpi( &d3, &mpi_val, &mpi_val2 ); // T2^c * g^s4
  mbedtls_mpi_mod_mpi( &d3, &d3, &pk.n); // T2^c * g^s4 mod n 

  // Compute T3^c g^(s1- c2^gamma1) * h^s4
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_exp_mod( &mpi_val1, &pk.g, &mpi_val2, &pk.n, NULL ); // g^(s1 - c*2^gamma_1) 
  mbedtls_mpi_exp_mod( &mpi_val, &sign.T3, &sign.c, &pk.n, NULL ); // T3^c mod n 
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T3^c * g^(s1 - c*2^gamma_1) 
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); //  T3^c * g^(s1 - c*2^gamma_1)  mod n 
  mbedtls_mpi_exp_mod( &mpi_val, &pk.h, &sign.s4, &pk.n, NULL ); // h^s4 mod n 
  mbedtls_mpi_mul_mpi( &d4, &mpi_val2, &mpi_val); // h^s4 * T3^c * g^(s1 - c*2^gamma_1)
  mbedtls_mpi_mod_mpi( &d4, &d4, &pk.n ); // // h^s4 * T3^c * g^(s1 - c*2^gamma_1) mod n

  // Create signature
  if ( mbedtls_sha256_starts( &ctx_hash, 0) != 0 )
  {
    goto exit;
  }

  if ( verify_hash( pk.a0 ) != 0 ) goto exit;
  if ( verify_hash( pk.a ) != 0 ) goto exit;
  if ( verify_hash( pk.g ) != 0 ) goto exit;
  if ( verify_hash( pk.h ) != 0 ) goto exit;
  if ( verify_hash( pk.n ) != 0 ) goto exit;
  if ( verify_hash( pk.y) != 0 ) goto exit;

  if ( verify_hash( sign.T1 ) != 0 ) goto exit;
  if ( verify_hash( sign.T2 ) != 0 ) goto exit;
  if ( verify_hash( sign.T3 ) != 0 ) goto exit;

  // if ( verify_hash( d1 ) != 0 ) goto exit;
  // if ( verify_hash( d2 ) != 0 ) goto exit;
  // if ( verify_hash( d3 ) != 0 ) goto exit;
  // if ( verify_hash( d4 ) != 0 ) goto exit;

  if( mbedtls_sha256_finish( &ctx_hash, hash ) != 0 )
  {
    goto exit;
  }

  for ( int i = 0; i < 32; i++ )
  {
    j += snprintf(buffer+j, 8, "%d", hash[i]); // concatenate values
  }
  mbedtls_mpi_read_string( &c, 10, buffer); // write to sign.c

	if( mbedtls_mpi_cmp_mpi( &sign.c, &c ) != 0 )
	{
		goto exit;
	}
	
  exit_code = EXIT_SUCCESS;

exit:
  mbedtls_mpi_free( &mpi_val ); mbedtls_mpi_free( &mpi_val1 );  mbedtls_mpi_free( &mpi_val2 );         
  mbedtls_mpi_free( &d1 );      mbedtls_mpi_free( &d2 );        mbedtls_mpi_free( &d3 );            
  mbedtls_mpi_free( &d4 );      mbedtls_mpi_free( &two );       mbedtls_mpi_free( &max );

  return exit_code;
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */