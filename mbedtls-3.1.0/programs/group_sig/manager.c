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

struct pk_struct manager_setup( int *exit_code )
{
  // Intilize keys
  struct pk_struct pk;
  struct sk_struct sk;
  mbedtls_mpi_init( &pk.n ); mbedtls_mpi_init( &pk.a ); mbedtls_mpi_init( &pk.a0 ); 
  mbedtls_mpi_init( &pk.y ); mbedtls_mpi_init( &pk.g ); mbedtls_mpi_init( &pk.h ); 
  mbedtls_mpi_init( &sk.p ); mbedtls_mpi_init( &sk.q ); mbedtls_mpi_init( &sk.x );

  // Initilize and introduce temperoral variables
  int ret = 1; 
  size_t nbytes;
  *exit_code = MBEDTLS_EXIT_FAILURE;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  char personalization[] = "my_app_specific_string";
  mbedtls_mpi p, q, mpi_val, mpi_val1;
  mbedtls_mpi_init( &p );         mbedtls_mpi_init( &q );             mbedtls_mpi_init( &mpi_val );       
  mbedtls_mpi_init( &mpi_val1 );  mbedtls_ctr_drbg_init( &ctr_drbg ); mbedtls_entropy_init( &entropy );  

  // Generate p, p', q and q'
  if ( (ret = gen_prime( &p, &sk.p )) != 0)
  {
    goto exit;
  }
  if ( (ret = gen_prime( &q, &sk.q )) != 0)
  {
    goto exit;
  }

  mbedtls_mpi_mul_mpi( &pk.n, &p, &q );  // n = p * q

  // Choose random elements a, a0, g, h ∈ QR(n) (of order p' * q') use proposition 1 and collary 1. 
  nbytes = (( mbedtls_mpi_bitlen( &pk.n ) ) >> 3 ) + 1 ; // number of bytes
  if ( (select_order( pk.n, nbytes, &pk.a ) || select_order( pk.n, nbytes, &pk.a0 ) || 
        select_order( pk.n, nbytes, &pk.g ) ||select_order( pk.n, nbytes, &pk.h ) )  != 0 )
  {
    goto exit;
  }

  mbedtls_mpi_mod_mpi( &mpi_val, &sk.p, &sk.q ); // p' * q'
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ; // number of bytes

  if( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) ) != 0)
  {
    goto exit;
  }
  
  if( mbedtls_mpi_fill_random( &sk.x, nbytes, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  {
    goto exit;
  }

  mbedtls_mpi_mod_mpi( &sk.x, &sk.x, &mpi_val ); // x mod p'q'
  mbedtls_mpi_exp_mod( &pk.y, &pk.g, &sk.x, &pk.n, NULL); // y =  g ^ x mod n

  *exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
  mbedtls_mpi_free( &p );         mbedtls_mpi_free( &q );             mbedtls_mpi_free( &mpi_val );       
  mbedtls_mpi_free( &mpi_val1 );  mbedtls_ctr_drbg_free( &ctr_drbg ); mbedtls_entropy_free( &entropy );  
  
  return pk;
}

int select_order( mbedtls_mpi n, size_t nbytes, mbedtls_mpi *x )
{
  int exit_code = MBEDTLS_EXIT_FAILURE;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  char personalization[] = "my_other_app_specific_string";
  mbedtls_mpi gcd, gcd1, mpi_1, mpi_2;
  mbedtls_mpi_init( &mpi_1 ); mbedtls_mpi_init( &mpi_2);  
  mbedtls_mpi_init( &gcd );   mbedtls_mpi_init( &gcd1 );  mbedtls_ctr_drbg_init( &ctr_drbg ); 
  mbedtls_entropy_init( &entropy );  

  if( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) ) != 0)
  {
    goto exit;
  }

  while( abs(mbedtls_mpi_cmp_int( &gcd, 1 )) && abs(mbedtls_mpi_cmp_int( &gcd1, 1 )) )
  {
    while( abs(mbedtls_mpi_cmp_int( &gcd, 1 )) )
    {
      if( mbedtls_mpi_fill_random( x, nbytes, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
      {
        goto exit;
      }
      mbedtls_mpi_gcd( &gcd, x, &n ); // check gcd( x, n )
    }
    mbedtls_mpi_sub_int( &mpi_1, x, 1 ); // x - 1
    mbedtls_mpi_gcd( &gcd, x, &n ); // gcd( x - 1, n )
    mbedtls_mpi_add_int( &mpi_2, x, 1 ); // x + 1
    mbedtls_mpi_gcd( &gcd1, x, &n ); // gcd( x + 1, n)
  }
  mbedtls_mpi_mul_mpi( x, x, x ); // x^2 
  mbedtls_mpi_mod_mpi( x, x, &n ); // mod n

  exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
  mbedtls_mpi_free( &mpi_1 ); mbedtls_mpi_free( &mpi_2);
  mbedtls_mpi_free( &gcd );   mbedtls_mpi_free( &gcd1 );

  return exit_code;
}

int gen_prime(mbedtls_mpi *x, mbedtls_mpi *x_prime)
{
  int ret;
  int exit_code = MBEDTLS_EXIT_FAILURE;
  const char *pers = "dh_genprime";
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_ctr_drbg_init( &ctr_drbg ); mbedtls_entropy_init( &entropy );

  if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
  {
    goto exit;
  }

  if( ( ret = mbedtls_mpi_gen_prime( x, lp, 1, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
  {
    goto exit;
  }

  if( ( ret = mbedtls_mpi_sub_int( x_prime, x, 1 ) ) != 0 )
  {
    goto exit;
  }

  if( ( ret = mbedtls_mpi_div_int( x_prime, NULL, x_prime, 2 ) ) != 0 )
  {
    goto exit;
  }

  if( ( ret = mbedtls_mpi_is_prime_ext( x_prime, 50, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
  {
    goto exit;
  }

  exit_code = MBEDTLS_EXIT_SUCCESS;
  
exit:
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );

  return exit_code;
}

int manager_join_part1( mbedtls_mpi *a, mbedtls_mpi *b )
{
  int exit_code = MBEDTLS_EXIT_FAILURE; 
  int nbytes;
  mbedtls_mpi mpi_val, mpi_val1, two, max;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  char char_temp[64] = "";
  char personalization[] = "my_other_other_other_app_specific_string";
  
  // initilize 
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );
  mbedtls_mpi_init( &two );       mbedtls_mpi_init( &mpi_val );
  mbedtls_mpi_init( &mpi_val1 );  mbedtls_mpi_init( &max ); 
  mbedtls_mpi_read_string( &max, 10, "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708340403154190335" ); 
  mbedtls_mpi_read_string( &two, 10, "2" );

  // Calculate range x ∈ 2^λ2
  snprintf( char_temp, 64, "%lld", lambda_2);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL); // Set range as mpi
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ; // number of bytes
  
  // Seed drbg
  if ( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) ) != 0 )
  {
    goto exit;
  }

  // Use seeded drbg to generate a secret exponent alpha ∈  ]0, 2^λ2[
  if ( mbedtls_mpi_fill_random( a, nbytes, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  {
    goto exit;
  }
  
  // Use seeded drbg to generate a secret exponent beta ∈  ]0, 2^λ2[
  if ( mbedtls_mpi_fill_random( b, nbytes, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  {
    goto exit;
  }

  exit_code = MBEDTLS_EXIT_SUCCESS;

  exit:
    mbedtls_mpi_free( &mpi_val );     mbedtls_mpi_free( &mpi_val1 );
    mbedtls_entropy_free( &entropy ); mbedtls_ctr_drbg_free( &ctr_drbg );

  return exit_code;
} 

int manager_join_part2( mbedtls_mpi C2, mbedtls_mpi n, mbedtls_mpi a0, mbedtls_mpi *A, mbedtls_mpi *e )
{
  int exit_code = MBEDTLS_EXIT_FAILURE; 
  int nbytes;
  mbedtls_mpi mpi_val, mpi_val1, two, max;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  char char_temp[64] = "";
  char personalization[] = "my_other_other_other_app_specific_string";
  
  // initilize 
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );
  mbedtls_mpi_init( &two );       mbedtls_mpi_init( &mpi_val );
  mbedtls_mpi_init( &mpi_val1 );  mbedtls_mpi_init( &max ); 
  mbedtls_mpi_read_string( &max, 10, "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708340403154190335" ); 
  mbedtls_mpi_read_string( &two, 10, "2" );
  
  // Calculate range
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^gamma_1
  snprintf(char_temp, 64, "%lld", gamma_2);
  mbedtls_mpi_read_string( &mpi_val1, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val1, &two, &mpi_val1, &max, NULL ); // 2^gamma_2
  mbedtls_mpi_add_mpi( &mpi_val, &mpi_val1, &mpi_val); // 2^gamma_1 + 2^gamma_2 
  nbytes = (( mbedtls_mpi_bitlen( &mpi_val ) ) >> 3 ) + 1 ; // number of bytes

  // Seed drbg
  if( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) ) != 0 )
  {
    goto exit;
  }

  // Use seeded drbg to generate a secret exponent e  in  Gamma
  if( mbedtls_mpi_fill_random( e, nbytes, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0 )
  {
    goto exit;
  }

  // Compute Ai = (C2a0)^1/ei mod n
  mbedtls_mpi_mul_mpi( &mpi_val, &a0, &C2 ); // C2*a0 
  mbedtls_mpi_inv_mod( &mpi_val1, &mpi_val, &n ); // 1 / C2*a0 
  mbedtls_mpi_exp_mod( A, &mpi_val1, e, &n, NULL ); // ( 1 / C2*a0 )^e

  exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
  mbedtls_mpi_free( &mpi_val );     mbedtls_mpi_free( &mpi_val1 );
  mbedtls_entropy_free( &entropy ); mbedtls_ctr_drbg_free( &ctr_drbg );

  return exit_code;
}

int open( struct pk_struct pk, struct sign_struct sign, struct cert_struct cert )
{
  int exit_code = EXIT_FAILURE;
  if( verify( pk, sign ) )
  {
    // Initilize and introduce temperoral variables
    mbedtls_mpi A, mpi_val;
    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &mpi_val );

    // Calculate Ai
    mbedtls_mpi_exp_mod( &mpi_val, &sign.T2, &cert.x, &pk.n, NULL); // T2^c mod n 
    mbedtls_mpi_inv_mod( &mpi_val, &mpi_val, &pk.n ); // inv T2^x mod n 
    mbedtls_mpi_mul_mpi( &A, &mpi_val, &sign.T1 ); // T1/T2^x
    mbedtls_mpi_mod_mpi( &A, &A, &pk.n ); //  T1/T2^x mod n 

    // See whether Ai matches the certificate value
    if ( mbedtls_mpi_cmp_mpi( &A, &cert.A ) != 0 ) 
    { 
      goto exit;
    }

  }
  else 
  {
    goto exit;
  }

  exit_code = EXIT_SUCCESS;

exit:
  return exit_code;
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
