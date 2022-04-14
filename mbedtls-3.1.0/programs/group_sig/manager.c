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
  mbedtls_mpi_read_string( &max, 10, "1090748135619415929462984244733782862448264161996232692431832786189721331849119295216264234525201987223957291796157025273109870820177184063610979765077554799078906298842192989538609825228048205159696851613591638196771886542609324560121290553901886301017900252535799917200010079600026535836800905297805880952350501630195475653911005312364560014847426035293551245843928918752768696279344088055617515694349945406677825140814900616105920256438504578013326493565836047242407382442812245131517757519164899226365743722432277368075027627883045206501792761700945699168497257879683851737049996900961120515655050115561271491492515342105748966629547032786321505730828430221664970324396138635251626409516168005427623435996308921691446181187406395310665404885739434832877428167407495370993511868756359970390117021823616749458620969857006263612082706715408157066575137281027022310927564910276759160520878304632411049364568754920967322982459184763427383790272448438018526977764941072715611580434690827459339991961414242741410599117426060556483763756314527611362658628383368621157993638020878537675545336789915694234433955666315070087213535470255670312004130725495834508357439653828936077080978550578912967907352780054935621561090795845172954115972927479877527738560008204118558930004777748727761853813510493840581861598652211605960308356405941821189714037868726219481498727603653616298856174822413033485438785324024751419417183012281078209729303537372804574372095228703622776363945290869806258422355148507571039619387449629866808188769662815778153079393179093143648340761738581819563002994422790754955061288818308430079648693232179158765918035565216157115402992120276155607873107937477466841528362987708699450152031231862594203085693838944657061346236704234026821102958954951197087076546186622796294536451620756509351018906023773821539532776208676978589731966330308893304665169436185078350641568336944530051437491311298834367265238595404904273455928723949525227184617404367854754610474377019768025576605881038077270707717942221977090385438585844095492116099852538903974655703943973086090930596963360767529964938414598185705963754561497355827813623833288906309004288017321424808663962671333528009232758350873059614118723781422101460198615747386855096896089189180441339558524822867541113212638793675567650340362970031930023397828465318547238244232028015189689660418822976000815437610652254270163595650875433851147123214227266605403581781469090806576468950587661997186505665475715792896" ); 
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
