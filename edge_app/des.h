#ifndef DES_H
#define DES_H

#define DES_KEY_SIZE 8 // 56 bits used, but must supply 64 (8 are ignored)


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



#endif
