#ifndef DES_H
#define DES_H

#define DES_KEY_SIZE 8 // 56 bits used, but must supply 64 (8 are ignored)

typedef enum 
{ 
  TLS_NULL_WITH_NULL_NULL               = 0x0000,
  TLS_RSA_WITH_NULL_MD5                 = 0x0001,
  TLS_RSA_WITH_NULL_SHA                 = 0x0002,
  TLS_RSA_EXPORT_WITH_RC4_40_MD5        = 0x0003,
  TLS_RSA_WITH_RC4_128_MD5              = 0x0004,
  TLS_RSA_WITH_RC4_128_SHA              = 0x0005,
  TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5    = 0x0006,
  TLS_RSA_WITH_IDEA_CBC_SHA             = 0x0007,
  TLS_RSA_EXPORT_WITH_DES40_CBC_SHA     = 0x0008,
  TLS_RSA_WITH_DES_CBC_SHA              = 0x0009,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA         = 0x000A,
  TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  = 0x000B,
  TLS_DH_DSS_WITH_DES_CBC_SHA           = 0x000C,
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = 0x000D,
  TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x000E,
  TLS_DH_RSA_WITH_DES_CBC_SHA           = 0x000F,
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = 0x0010,
  TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
  TLS_DHE_DSS_WITH_DES_CBC_SHA          = 0x0012,
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = 0x0013,
  TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
  TLS_DHE_RSA_WITH_DES_CBC_SHA          = 0x0015,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = 0x0016,
  TLS_DH_anon_EXPORT_WITH_RC4_40_MD5    = 0x0017,
  TLS_DH_anon_WITH_RC4_128_MD5          = 0x0018,
  TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
  TLS_DH_anon_WITH_DES_CBC_SHA          = 0x001A,
  TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = 0x001B,

  // 1C & 1D were used by SSLv3 to describe Fortezza suites
  // End of list of algorithms defined by RFC 2246

  // These are all defined in RFC 4346 (v1.1), not 2246 (v1.0)
  //
  TLS_KRB5_WITH_DES_CBC_SHA           = 0x001E,
  TLS_KRB5_WITH_3DES_EDE_CBC_SHA      = 0x001F,
  TLS_KRB5_WITH_RC4_128_SHA           = 0x0020,
  TLS_KRB5_WITH_IDEA_CBC_SHA          = 0x0021,
  TLS_KRB5_WITH_DES_CBC_MD5           = 0x0022,
  TLS_KRB5_WITH_3DES_EDE_CBC_MD5      = 0x0023,
  TLS_KRB5_WITH_RC4_128_MD5           = 0x0024,
  TLS_KRB5_WITH_IDEA_CBC_MD5          = 0x0025,
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026,
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027,
  TLS_KRB5_EXPORT_WITH_RC4_40_SHA     = 0x0028,
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029,
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A,
  TLS_KRB5_EXPORT_WITH_RC4_40_MD5     = 0x002B,

  // TLS_AES ciphersuites - RFC 3268
  TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA   = 0x0030,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA   = 0x0031,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033,
  TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034,
  TLS_RSA_WITH_AES_256_CBC_SHA      = 0x0035,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA   = 0x0036,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA   = 0x0037,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA  = 0x0038,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x0039,
  TLS_DH_anon_WITH_AES_256_CBC_SHA  = 0x003A,

  MAX_SUPPORTED_CIPHER_SUITE        = 0x003B
} CipherSuiteIdentifier;


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void des_encrypt( const unsigned char *plaintext, 
         const int plaintext_len,
         unsigned char *ciphertext, 
         void *iv, 
         const unsigned char *key );
void des3_encrypt( const unsigned char *plaintext, 
         const int plaintext_len,
         unsigned char *ciphertext, 
         void *iv, 
         const unsigned char *key );
void des_decrypt( const unsigned char *ciphertext, 
         const int ciphertext_len,
         unsigned char *plaintext, 
         void *iv,
         const unsigned char *key );
void des3_decrypt( const unsigned char *ciphertext, 
         const int ciphertext_len,
         unsigned char *plaintext, 
         void *iv,
         const unsigned char *key );

#ifdef __cplusplus
}
#endif /* __cplusplus */

typedef struct
{
  unsigned char MAC_secret[20]; //20=suite->hash_size
  unsigned char key[32];         //24=suite->key_size
  unsigned char IV[16];          //8=suite->IV_size
  CipherSuiteIdentifier suite;
  unsigned long         seq_num;
}
SubParameters; 
typedef struct
{
  unsigned char MAC_secret[20]; //20=suite->hash_size
  unsigned char key[24];         //24=suite->key_size
  unsigned char IV[8];          //8=suite->IV_size
  CipherSuiteIdentifier suite;
  unsigned long         seq_num;
}
SubParameters2; 
#endif
