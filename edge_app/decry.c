#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif
#include "tls.h"
#include "decry.h"
#include<time.h>
#include<sys/time.h>
#define BUFFER_SIZE 255

void display(unsigned char *buffer, int buffer_size)
{
    
    static char recv_buf[BUFFER_SIZE+1];
    memcpy(&recv_buf,buffer,buffer_size);
    recv_buf[buffer_size] ='\0';
    printf("%s",recv_buf);
    printf("\n");

} 

int decry(unsigned char *encrypt, unsigned char *decrypt,SubParameters *parameter)
{
  TLSPlaintext *header;
  header=malloc(sizeof(TLSPlaintext));
  memcpy(header,encrypt,5);
  short send_buffer_size;
  //send_buffer_size =header->length;
  send_buffer_size =encrypt[4];
  unsigned char *encrypt2,
                *decrypt2;
  encrypt2 =(unsigned char *)malloc(send_buffer_size);
  decrypt2 =(unsigned char *)malloc(send_buffer_size);
  memcpy(encrypt2,encrypt+5,send_buffer_size);
  send_buffer_size = tls_decrypt2(header,encrypt2,send_buffer_size,&decrypt2,parameter);
  //decrypt2[send_buffer_size]='\0';
  memcpy(decrypt,decrypt2,send_buffer_size);
  free(header);
  free(encrypt2);
  free(decrypt2);

return send_buffer_size;

}
#ifdef TEST_DECRY
int main ( int argc, char *argv[] )
{
  SubParameters *par2;
  struct timeval stTime,fiTime;
  short send_buffer_size;
gettimeofday(&stTime,NULL);
  FILE *hf;
  FILE *kf;
  hf=fopen("1buffer.dat","rb");
  kf=fopen("key.dat","rb");
  
  unsigned char *encrypt2,
                *decrypt2;
  par2 =malloc(sizeof(*par2));
  encrypt2 =(unsigned char *)malloc(189);
  decrypt2 =(unsigned char *)malloc(184);

  fread(encrypt2,189,1,hf);
  fread(par2,sizeof(*par2),1,kf);
  
  send_buffer_size= decry(encrypt2,decrypt2,par2);
  gettimeofday(&fiTime,NULL);
  display(decrypt2,send_buffer_size);
  
  free(par2); 
  
  free(encrypt2);
  free(decrypt2);
  fclose(hf);
  int sec,usec;
	sec=fiTime.tv_sec-stTime.tv_sec;
	usec=fiTime.tv_usec-stTime.tv_usec;

	FILE *ef;
	ef =fopen("decry.csv","a");
	fprintf(ef,"%d.%5d\n",sec,usec);
	fclose(ef);
  return 0 ;

}
#endif
