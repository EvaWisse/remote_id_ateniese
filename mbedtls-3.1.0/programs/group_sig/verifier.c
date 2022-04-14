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
  mbedtls_mpi mpi_val, mpi_val1, mpi_val2, d1, d2, d3, d4, c, max, two, neg, pos, zero; 

  mbedtls_mpi_init( &mpi_val ); mbedtls_mpi_init( &mpi_val1 );  mbedtls_mpi_init( &mpi_val2 ); 
  mbedtls_mpi_init( &d1 );      mbedtls_mpi_init( &d2 );        mbedtls_mpi_init( &d3 );     
  mbedtls_mpi_init( &d4 );      mbedtls_mpi_init( &two );       mbedtls_mpi_init( &c );
  mbedtls_mpi_init( &neg );     mbedtls_mpi_init( &pos );       mbedtls_mpi_init( &max );     
  mbedtls_sha256_init( &ctx_hash );  
  mbedtls_mpi_read_string( &two, 10, "2" );
  mbedtls_mpi_read_string( &max, 10, "1090748135619415929462984244733782862448264161996232692431832786189721331849119295216264234525201987223957291796157025273109870820177184063610979765077554799078906298842192989538609825228048205159696851613591638196771886542609324560121290553901886301017900252535799917200010079600026535836800905297805880952350501630195475653911005312364560014847426035293551245843928918752768696279344088055617515694349945406677825140814900616105920256438504578013326493565836047242407382442812245131517757519164899226365743722432277368075027627883045206501792761700945699168497257879683851737049996900961120515655050115561271491492515342105748966629547032786321505730828430221664970324396138635251626409516168005427623435996308921691446181187406395310665404885739434832877428167407495370993511868756359970390117021823616749458620969857006263612082706715408157066575137281027022310927564910276759160520878304632411049364568754920967322982459184763427383790272448438018526977764941072715611580434690827459339991961414242741410599117426060556483763756314527611362658628383368621157993638020878537675545336789915694234433955666315070087213535470255670312004130725495834508357439653828936077080978550578912967907352780054935621561090795845172954115972927479877527738560008204118558930004777748727761853813510493840581861598652211605960308356405941821189714037868726219481498727603653616298856174822413033485438785324024751419417183012281078209729303537372804574372095228703622776363945290869806258422355148507571039619387449629866808188769662815778153079393179093143648340761738581819563002994422790754955061288818308430079648693232179158765918035565216157115402992120276155607873107937477466841528362987708699450152031231862594203085693838944657061346236704234026821102958954951197087076546186622796294536451620756509351018906023773821539532776208676978589731966330308893304665169436185078350641568336944530051437491311298834367265238595404904273455928723949525227184617404367854754610474377019768025576605881038077270707717942221977090385438585844095492116099852538903974655703943973086090930596963360767529964938414598185705963754561497355827813623833288906309004288017321424808663962671333528009232758350873059614118723781422101460198615747386855096896089189180441339558524822867541113212638793675567650340362970031930023397828465318547238244232028015189689660418822976000815437610652254270163595650875433851147123214227266605403581781469090806576468950587661997186505665475715792896");
  mbedtls_mpi_read_string( &zero, 10, "0" );

  // Calculate d1 = a0^c T1^(s1 - c2^gamma_1) / (a^(s2-c2^delta_1) y^s3 )
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) == 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val, &sign.T1, &pk.n ); // inv T1 mod n
    mbedtls_mpi_add_abs( &pos, &mpi_val2, &zero);
    mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val, &pos, &pk.n, NULL ); // T1^(s1 - c2^gamma_1) mod n
  }
  else
  {  
    mbedtls_mpi_exp_mod( &mpi_val1, &sign.T1, &mpi_val2, &pk.n, NULL ); // T1^(s1 - c2^gamma_1) mod n
  }

  mbedtls_mpi_sub_mpi( &neg, &sign.s3, &sign.s3 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) == 0 )
  {
    mbedtls_mpi_add_abs( &pos, &sign.s3, &zero );
    mbedtls_mpi_exp_mod( &mpi_val, &pk.y, &pos, &pk.n, NULL ); // 1 / y^s3 mod n
  }
  else 
  {
    mbedtls_mpi_inv_mod( &mpi_val2, &pk.y, &pk.n ); // inv y
    mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &sign.s3, &pk.n, NULL ); // 1 / y^s3 mod n
  }
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T1^(s1 - c2^gamma_1) / y^s3 
  mbedtls_mpi_mod_mpi( &mpi_val1, &mpi_val2, &pk.n ); // T1^(s1 - c2^gamma_1) / y^s3  mod n 

  snprintf(char_temp, 64, "%lld", lambda_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^lambda_1
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val, &sign.c ); // c*2^lambda_1
  mbedtls_mpi_sub_mpi( &mpi_val, &sign.s2, &mpi_val2 ); // s2 - c*2^lambda_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val, &mpi_val );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) == 0 ) 
  {
    mbedtls_mpi_add_abs( &pos, &mpi_val, &zero );
    mbedtls_mpi_exp_mod( &mpi_val, &pk.a, &pos, &pk.n, NULL ); // 1 / a^(s2-c2^delta_1) mod n
  }
  else 
  {
    mbedtls_mpi_inv_mod( &mpi_val2, &pk.a, &pk.n ); // inv a mod n
    mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &mpi_val, &pk.n, NULL );  // 1 / a^(s2-c2^delta_1) mod n
  }
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1)
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); // T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) mod n
  
  mbedtls_mpi_exp_mod( &mpi_val, &pk.a0, &sign.c, &pk.n, NULL ); // a0^c mod n
  mbedtls_mpi_mul_mpi( &d1, &mpi_val, &mpi_val2 ); // a0^c * T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) 
  mbedtls_mpi_mod_mpi( &d1, &d1, &pk.n ); // a0^c * T1^(s1 - c2^gamma_1) / y^s3  mod n  * 1 / a^(s2-c2^delta_1) mod n

  // Compute d2 = T2^(s1 - c2^gamma_1 ) / g^s3
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) == 0)
  {
    mbedtls_mpi_inv_mod( &mpi_val1, &sign.T2, &pk.n ); // inv T2
    mbedtls_mpi_add_abs( &pos, &mpi_val2, &zero ); 
    mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val1, &pos, &pk.n, NULL ); // T2^ ( s1 - c*2^gamma_1 )
  }
  else
  {
    mbedtls_mpi_exp_mod( &mpi_val1, &sign.T2, &mpi_val2, &pk.n, NULL ); // T2^ ( s1 - c*2^gamma_1 )
  }
  mbedtls_mpi_mod_mpi( &mpi_val1, &mpi_val1, &pk.n ); // T2^ ( s1 - c*2^gamma_1 ) mod n

  mbedtls_mpi_sub_mpi( &neg, &sign.s3, &sign.s3 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) == 0 )
  {
    mbedtls_mpi_add_abs( &pos, &sign.s3, &zero );
    mbedtls_mpi_exp_mod( &mpi_val, &pk.g, &pos, &pk.n, NULL ); // g^s3
  }
  else
  {
    mbedtls_mpi_inv_mod( &mpi_val2, &pk.g, &pk.n ); // inv g mod n
    mbedtls_mpi_exp_mod( &mpi_val, &mpi_val2, &sign.s3, &pk.n, NULL ); // 1 / g^s3
  }
  mbedtls_mpi_mul_mpi( &d2, &mpi_val, &mpi_val1 ); // T2^(s1 - c2^gamma_1 ) / g^s3
  mbedtls_mpi_mod_mpi( &d2, &d2, &pk.n ); // T2^(s1 - c2^gamma_1 ) / g^s3 mod n 

  // Compute d3 =  T2^c * g^s4
  mbedtls_mpi_exp_mod( &mpi_val, &sign.T2, &sign.c, &pk.n, NULL ); // T2^c 
  mbedtls_mpi_sub_mpi( &neg, &sign.s4, &sign.s4 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) == 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val1, &pk.g, &pk.n ); // inv g mod n
    mbedtls_mpi_add_abs( &pos, &sign.s4, &zero);
    mbedtls_mpi_exp_mod( &mpi_val2, &mpi_val1, &pos, &pk.n, NULL ); // g^s4 
  }
  else 
  {
    mbedtls_mpi_exp_mod( &mpi_val2, &pk.g, &sign.s4, &pk.n, NULL ); // g^s4
  }
  mbedtls_mpi_mul_mpi( &d3, &mpi_val, &mpi_val2 ); // T2^c * g^s4
  mbedtls_mpi_mod_mpi( &d3, &d3, &pk.n); // T2^c * g^s4 mod n 

  // Compute d4 = T3^c g^(s1- c2^gamma1) * h^s4
  snprintf(char_temp, 64, "%lld", gamma_1);
  mbedtls_mpi_read_string( &mpi_val, 10, char_temp );
  mbedtls_mpi_exp_mod( &mpi_val, &two, &mpi_val, &max, NULL ); // 2^gamma_1
  mbedtls_mpi_mul_mpi( &mpi_val1, &mpi_val, &sign.c ); // c*2^gamma_1
  mbedtls_mpi_sub_mpi( &mpi_val2, &sign.s1, &mpi_val1 ); // s1 - c*2^gamma_1

  mbedtls_mpi_sub_mpi( &neg, &mpi_val2, &mpi_val2 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) == 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val, &pk.g, &pk.n ); // inv g mod n
    mbedtls_mpi_add_abs( &pos, &mpi_val2, &zero);
    mbedtls_mpi_exp_mod( &mpi_val1, &mpi_val, &pos, &pk.n, NULL ); // g^(s1 - c*2^gamma_1) 
  }
  else 
  {
    mbedtls_mpi_exp_mod( &mpi_val1, &pk.g, &mpi_val2, &pk.n, NULL ); // g^(s1 - c*2^gamma_1) 
  }

  mbedtls_mpi_exp_mod( &mpi_val, &sign.T3, &sign.c, &pk.n, NULL ); // T3^c mod n 
  mbedtls_mpi_mul_mpi( &mpi_val2, &mpi_val1, &mpi_val); // T3^c * g^(s1 - c*2^gamma_1) 
  mbedtls_mpi_mod_mpi( &mpi_val2, &mpi_val2, &pk.n ); //  T3^c * g^(s1 - c*2^gamma_1)  mod n 

  mbedtls_mpi_sub_mpi( &neg, &sign.s4, &sign.s4 );
  if( mbedtls_mpi_cmp_int( &neg, 0 ) == 0 )
  {
    mbedtls_mpi_inv_mod( &mpi_val1, &pk.h, &pk.n); // inv h mod n 
    mbedtls_mpi_add_abs( &pos, &sign.s4, &zero);
    mbedtls_mpi_exp_mod( &mpi_val, &mpi_val1, &pos, &pk.n, NULL ); // h^s4 mod n
  }
  else 
  {
    mbedtls_mpi_exp_mod( &mpi_val, &pk.h, &sign.s4, &pk.n, NULL ); // h^s4 mod n 
  }
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
  if ( verify_hash( d2 ) != 0 ) goto exit;
  if ( verify_hash( d3 ) != 0 ) goto exit;
  if ( verify_hash( d4 ) != 0 ) goto exit;


  printf("\nVerifier\n");
  mbedtls_mpi_write_file("d1\t", &d1, 10, NULL );

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