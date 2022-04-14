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

int member_join( struct pk_struct pk, struct cert_struct *cert )
{
  int exit_code = MBEDTLS_EXIT_FAILURE; 
  int nbytes;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  char personalization[] = "my_other_other_app_specific_string";
  char char_temp[64];
  mbedtls_mpi C1, C2, mpi_val, mpi_val1, x, r, max, two, alpha, beta;
  
  // initlize
  mbedtls_entropy_init( &entropy ); 
  mbedtls_ctr_drbg_init( &ctr_drbg ); mbedtls_mpi_init( &two );             mbedtls_mpi_init( &C1 );      mbedtls_mpi_init( &C2 );   
  mbedtls_mpi_init( &mpi_val );       mbedtls_mpi_init( &mpi_val1 );        mbedtls_mpi_init( &x );       mbedtls_mpi_init( &alpha );           
  mbedtls_mpi_init( &beta );          mbedtls_mpi_init( &r );               mbedtls_mpi_init( &max );         
  mbedtls_mpi_read_string( &max, 10, "1044389964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708340403154190335" ); 
  mbedtls_mpi_read_string( &two, 10, "2" );

  snprintf(char_temp, 64, "%lld", lambda_2);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL); // 2^lambda_2
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ; // number of bytes

  // Seed drbg
  if ( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) ) != 0 )
  {
    goto exit;
  }

  // Use seeded drbg to generate a secret exponent x ∈  ]0, 2^λ2[
  if ( mbedtls_mpi_fill_random( &x, nbytes, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  { 
    goto exit;
  }
	
  // Calculate range r  ∈ ]0, n^2[   
  mbedtls_mpi_mul_mpi( &mpi_val1, &pk.n, &pk.n ); // n * n 
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val1 ) ) >> 3 ) + 1 ; // number of bytes

  // Use seeded drbg to generate r in ]0, n^2[
  if ( mbedtls_mpi_fill_random( &r, nbytes, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  { 
    goto exit;
  }

  // Calculate C1 = g^xh^r mod n
  mbedtls_mpi_exp_mod( &mpi_val, &pk.g, &x, &pk.n, NULL); // g^x mod n
  mbedtls_mpi_exp_mod( &mpi_val1, &pk.h, &r, &pk.n, NULL); // h^r mod n
  mbedtls_mpi_mul_mpi( &C1, &mpi_val, &mpi_val1); // g^x * h^r
  mbedtls_mpi_mod_mpi( &C1, &C1, &pk.n); // g^x * h^r mod n

  // Send C1 to manager
  if ( manager_join_part1( &alpha, &beta ) != 0 )
  {
    goto exit;
  }

  // Compute x = 2^λ1 +(αi xi + βi mod 2^λ2)
  mbedtls_mpi_mul_mpi( &mpi_val, &alpha, &x); // ai * xi
  mbedtls_mpi_add_mpi( &mpi_val1, &mpi_val1, &beta ); // ai * xi + Bi
  mbedtls_mpi_mod_mpi( &mpi_val1, &mpi_val1, &mpi_val); // ai * xi + Bi mod 2^lambda_2
  mbedtls_mpi_read_string( &mpi_val, 10, "1" ); // set mpi_val to 1
  mbedtls_mpi_shift_l( &mpi_val, lambda_1); // 1 * 2^lambda_1
  mbedtls_mpi_add_mpi( &cert->x, &mpi_val, &mpi_val1); // 2^lambda_1 + (ai * xi + Bi mod 2^lambda_2)
 
  mbedtls_mpi_exp_mod( &C2, &pk.a, &cert->x, &pk.n, NULL); // C2 = a^xi mod n 
  if ( manager_join_part2( C2, pk.n, pk.a0,  &cert->A, &cert->e ) != 0 )
  {
    goto exit;
  }

  exit_code = EXIT_SUCCESS;

exit:
  mbedtls_mpi_init( &C1 );  mbedtls_mpi_free( &C2 );    mbedtls_mpi_free( &mpi_val );     mbedtls_mpi_free( &mpi_val1 );
  mbedtls_mpi_free( &x );   mbedtls_mpi_free( &alpha ); mbedtls_mpi_free( &beta );        mbedtls_mpi_free( &r );  
  mbedtls_mpi_free( &max);  mbedtls_mpi_free( &two );   mbedtls_entropy_free( &entropy ); mbedtls_ctr_drbg_free( &ctr_drbg ); 

  return exit_code;
}

int create_hash( mbedtls_mpi x )
{
  int  error_code = EXIT_FAILURE;
  size_t len = mbedtls_mpi_bitlen( &x ); // get size
  const unsigned char *buf = ( unsigned char *) malloc(len); // initlize buffer
  mbedtls_mpi_write_string( &x, 10, (char *) buf, len, &len); // mpi to unsigned hash
  if ( ( mbedtls_sha256_update( &ctx, buf, len) ) != 0)
  {
    goto exit;
  } 
  
  error_code = EXIT_SUCCESS;

exit:
  free((char*)buf);

  return error_code;
}

int gen_sign( struct pk_struct pk, struct cert_struct cert, struct sign_struct *sign )
{
  int exit_code = EXIT_FAILURE;
  int nbytes;
  int j = 0;
  uint8_t hash[32];
  char buffer[256];
  char char_temp[64];
  char personalization[] = "my_app_specific_string";
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_mpi mpi_val, mpi_val1, mpi_val2, w, r1, r2, r3, r4, d1, d2, d3, d4, max, two;

  mbedtls_mpi_init( &mpi_val );     mbedtls_mpi_init( &mpi_val1 );      mbedtls_mpi_init( &mpi_val2 );
  mbedtls_mpi_init( &w );           mbedtls_mpi_init( &r1 );            mbedtls_mpi_init( &r2 );          
  mbedtls_mpi_init( &r3 );          mbedtls_mpi_init( &r4 );            mbedtls_mpi_init( &d1 );      
  mbedtls_mpi_init( &d2 );          mbedtls_mpi_init( &d3 );            mbedtls_mpi_init( &d4 );
  mbedtls_entropy_init( &entropy ); mbedtls_ctr_drbg_init( &ctr_drbg ); mbedtls_sha256_init( &ctx );
  mbedtls_mpi_read_string( &max, 10, "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708340403154190335" ); 
 
  if ( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) ) != 0 )
  {
    goto exit;
  }

  // Use seeded drbg to generate a secret exponent w of lenght 2lp
  snprintf(char_temp, 64, "%lld", 2 * lp);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp ); 
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ; // number of bytes
  if ( mbedtls_mpi_fill_random( &w, nbytes, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  {
    goto exit;
  }
 
  // Calculate T1
  mbedtls_mpi_exp_mod( &mpi_val, &pk.y, &w, &pk.n, NULL ); // y^w mod n
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &cert.A ); // A * y^w 
  mbedtls_mpi_mod_mpi( &sign->T1, &mpi_val1, &pk.n ); // A * y^w mod n

  // Calculate T2
  mbedtls_mpi_exp_mod( &sign->T2, &pk.g, &w, &pk.n, NULL); // g^w mod n
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );

  // Calculate T3
  mbedtls_mpi_exp_mod( &mpi_val, &pk.g, &cert.e, &pk.n, NULL ); // g^e mod n
  mbedtls_mpi_exp_mod( &mpi_val1, &pk.h, &w, &pk.n, NULL ); // h^w mod n
  mbedtls_mpi_mul_mpi( &sign->T3, &mpi_val, &mpi_val1 ); // h^w * g^e
  mbedtls_mpi_mod_mpi( &sign->T3, &sign->T3, &pk.n ); // h^w * g^e mod n

  // Choose r1
  snprintf(char_temp, 64, "%lld", ( epsilon * ( gamma_2 + k )) >> 3);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ;
  if ( mbedtls_mpi_fill_random( &r1, nbytes , mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  {
    goto exit;
  }
   
  // Choose r2
  snprintf(char_temp, 64, "%lld",( epsilon * ( lambda_2 + k )) >> 3);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ;
  if ( mbedtls_mpi_fill_random( &r2, nbytes , mbedtls_ctr_drbg_random, &ctr_drbg ) != 0)
  {
    goto exit;
  }
  
  // Choose r3
  snprintf(char_temp, 64, "%lld", ( epsilon * ( gamma_1 + 2 * lp + k + 1 )) >> 3 );
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ;
  if ( mbedtls_mpi_fill_random( &r3, nbytes , mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  {
    goto exit;
  }
  
  // Choose r4
  snprintf(char_temp, 64, "%lld", (epsilon * ( 2 * lp + k )) >> 3);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ;
  if ( mbedtls_mpi_fill_random( &r4, nbytes , mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  {
    goto exit;
  }

  // Compute d1  = T1^r1/(a^r2y^r3)
  mbedtls_mpi_exp_mod( &mpi_val1, &sign->T1, &r1, &pk.n, NULL ); // T1^r1 mod n 
  mbedtls_mpi_inv_mod( &mpi_val2, &pk.a, &pk.n ); // inv a mod n
  mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &r2, &pk.n, NULL ); // 1 / a^r2
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val ); // ( 1 / a^r2 ) * T1^r1
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); // ( 1 / a^r2 ) * T1^r1 mod n

  mbedtls_mpi_inv_mod( &mpi_val, &pk.y, &pk.n ); // inv y mod n
  mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val, &r3, &pk.n, NULL ); // 1 / y^r3 mod n
  mbedtls_mpi_mul_mpi( &d1, &mpi_val1, &mpi_val2 );  // ( a^r2 * T1^r1 ) / y^r3
  mbedtls_mpi_mod_mpi( &d1, &d1, &pk.n ); // ( a^r2 * T1^r1 ) / y^r3 mod n 

  // Compute d2  T2^r1/g^r3
  mbedtls_mpi_inv_mod( &mpi_val1, &pk.g, &pk.n ); // inv g
  mbedtls_mpi_exp_mod( &mpi_val, &mpi_val1, &r3, &pk.n, NULL ); // 1 / g^r3 
  mbedtls_mpi_exp_mod( &mpi_val1, &sign->T2, &r1, &pk.n, NULL ); // T2^r1
  mbedtls_mpi_mul_mpi( &d2, &mpi_val1, &mpi_val ); // T2^r1 * ( 1 / g^r3 )
  mbedtls_mpi_mod_mpi( &d2, &d2, &pk.n ); // T2^r1 * ( 1 / g^r3 ) mod n
  
  // Compute d3 = g^r4
  mbedtls_mpi_exp_mod( &d3, &pk.g, &r4, &pk.n, NULL ); // g^r4 mod n

  // Compute d4  = g^r1 * h^r4
  mbedtls_mpi_exp_mod( &mpi_val1, &pk.h, &r4, &pk.n, NULL ); // h^r4 mod n
  mbedtls_mpi_exp_mod( &mpi_val2, &pk.g, &r1, &pk.n, NULL ); // g^r1 mod n
  mbedtls_mpi_mul_mpi( &d4, &mpi_val1, &mpi_val2 ); // g^r1 * h^r4
  mbedtls_mpi_mod_mpi( &d4, &d4, &pk.n ); // g^r1 * h^r4 mod n

  // Create signature
  if ( ( mbedtls_sha256_starts( &ctx, 0) ) != 0 )
  {
    goto exit;
  }

  if ( create_hash( pk.a0 ) !=0 ) goto exit;
  if ( create_hash( pk.a ) !=0 ) goto exit;
  if ( create_hash( pk.g ) !=0 ) goto exit;
  if ( create_hash( pk.h ) !=0 ) goto exit;
  if ( create_hash( pk.n ) !=0 ) goto exit;
  if ( create_hash( pk.y) !=0 ) goto exit;

  if ( create_hash( sign->T1 ) !=0 ) goto exit;
  if ( create_hash( sign->T2 ) !=0 ) goto exit;
  if ( create_hash( sign->T3 ) !=0 ) goto exit;

  // if ( create_hash( d1 ) !=0 ) goto exit;
  // if ( create_hash( d2 ) !=0 ) goto exit;
  // if ( create_hash( d3 ) !=0 ) goto exit;
  // if ( create_hash( d4 ) !=0 ) goto exit;

  if( ( mbedtls_sha256_finish( &ctx, hash ) ) != 0 )
  {
    goto exit;
  }

  for ( int i = 0; i < 32; i++ )
  {
    j += snprintf(buffer+j, 8, "%d", hash[i]); // concatenate values
  }
  mbedtls_mpi_read_string( &sign->c, 10, buffer); // write to sign->c

  // s1 = r1 - c * (e - gamma_1 )
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val1, &cert.e, &mpi_val ); //  e - 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &sign->c ); // c * (e - gamma_1 )
  mbedtls_mpi_sub_mpi( &sign->s1, &r1, &mpi_val2 ); // r1 - c * (e - gamma_1 )
  
  // s2 = r2 - c( x - 2^delta_1 )
  snprintf(char_temp, 64, "%lld", lambda_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^lambda_1
  mbedtls_mpi_sub_mpi( &mpi_val1, &cert.x, &mpi_val ); //  x - 2^lambda_1
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &sign->c ); // c * ( x - 2^lambda_1 )
  mbedtls_mpi_sub_mpi( &sign->s2, &r2, &mpi_val2 ); // r2 - c * ( x - 2^lambda_1 )

  // s3 = r3 - c * e * w
  mbedtls_mpi_mul_mpi( &mpi_val, &sign->c, &cert.e ); // c * e
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &w); // w * c * e
  mbedtls_mpi_sub_mpi( &sign->s3, &r3, &mpi_val1 ); // r3 - c * e * w

  // s4 = r4 - c * w
  mbedtls_mpi_mul_mpi( &mpi_val, &sign->c, &w); // c * w
  mbedtls_mpi_sub_mpi( &sign->s4, &r4, &mpi_val ); // r4 -c * w

  exit_code = EXIT_SUCCESS;

exit:
  mbedtls_mpi_free( &mpi_val );     mbedtls_mpi_free( &mpi_val1 );      mbedtls_mpi_free( &mpi_val2 );
  mbedtls_mpi_free( &w );           mbedtls_mpi_free( &r1 );            mbedtls_mpi_free( &r2 );          
  mbedtls_mpi_free( &r3 );          mbedtls_mpi_free( &r4 );            mbedtls_mpi_free( &d1 );      
  mbedtls_mpi_free( &d2 );          mbedtls_mpi_free( &d3 );            mbedtls_mpi_free( &d4 );
  mbedtls_entropy_free( &entropy ); mbedtls_ctr_drbg_free( &ctr_drbg ); mbedtls_sha256_free( &ctx );

 return exit_code;
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
