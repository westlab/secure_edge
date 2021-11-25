#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include "tls.h"
#include "des.h"

int main(int argc, char *argv[ ] )

{
    int bufsz =189;
    SubParameters *parameter;
    parameter=malloc(sizeof(*parameter));
    unsigned char *encrypt[184];
    TLSPlaintext *header;
    header =malloc(sizeof(TLSPlaintext));
    short length;
    unsigned char *plaintext[184];
    read_file(parameter,bufsz,header,encrypt,1);
    length =header->length;
    des3_decrypt(encrypt,length,plaintext,&parameter->IV,&parameter->key);
    file_out(encrypt,length,2);
    file_out(plaintext,length,3);
    printf("%s",plaintext);
    printf("\n");
    free(parameter);
    return 0;
}