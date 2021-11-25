#ifndef DECRY_H
#define DECRY_H
#include "tls.h"
#ifdef __cplusplus
extern "C"{
#endif/* __cplusplus*/
int decry(unsigned char *encrypt, unsigned char *decrypt,SubParameters *parameter);
#ifdef __cplusplus
}
#endif /* __cplusplus*/
#ifdef __cplusplus
extern "C"{
#endif/* __cplusplus*/
void display( unsigned char *buffer, int buffer_size);
#ifdef __cplusplus
}
#endif /* __cplusplus*/
#endif