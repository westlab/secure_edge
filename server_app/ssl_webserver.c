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
#include "base64.h"
#include "tls2.h"

#define HTTP_PORT 80
#define HTTPS_PORT 8443
#define DEFAULT_LINE_LEN 255
int stop=0;
char *read_line( int connection, TLSParameters *tls_context )
{
  static int line_len = DEFAULT_LINE_LEN;
  static char *line = NULL;
  int size;
  char c;    // must be c, not int
  int pos = 0;

  if ( !line )
  {
    line = malloc( line_len );
  }

  while ( ( size = tls_recv( connection, &c, 1, 0, tls_context ) ) >= 0 )
  {
    if ( ( c == '\n' ) && ( line[ pos - 1 ] == '\r' ) )
    {
      line[ pos - 1 ] = '\0';
      break;
    }
    line[ pos++ ] = c;

    if ( pos > line_len )
    {
      line_len *= 2;
      line = realloc( line, line_len );
    }
  }

  return line;
}

static void build_success_response( int connection, TLSParameters *tls_context )
{
  char buf[ 255 ];
//50words
   /* sprintf( buf, "HTTP/1.1 200 Success!\r\n\
Content-Type:text/html\r\n\
\r\n" );  */
//100words
 /* sprintf( buf, "HTTP/1.1 200 Success\r\nConnection: Close\r\n\
Content-Type:text/html\r\n\
\r\n<html><head></head>1234</html>\
\r\n" );  */ 
//150words
/* sprintf( buf, "HTTP/1.1 200 Success\r\nConnection: Close\r\n\
Content-Type:text/html\r\n\
\r\n<html><head></head>abcdefghijklmnopqrstuvwxyz123456789</html>\r\n\
abcdefghijklmnopq\r\n" );   */
//200words
/* sprintf( buf, "HTTP/1.1 200 Success\r\nConnection: Close\r\n\
Content-Type:text/html\r\n\
\r\n<html><head></head>abcdefghijklmnopqrstuvwxyz123456789</html>\r\n\
abcdefghijklmnopqstuvwxyz1234567890\r\n\
abcdefghijklmnopqrstuvwxyz1234\r\n" );  
 */
//250words
sprintf( buf, "HTTP/1.1 200 Success\r\nConnection: Close\r\n\
Content-Type:text/html\r\n\
\r\n<html><head></head>connection success </html>\r\n\
\r\n" ); 


  // Technically, this should account for short writes.
  if ( tls_send( connection, buf, strlen( buf ), 0, tls_context ) < strlen( buf ) )
  {
    perror( "Trying to respond" );
  }
}

//conectionwo gisousiotetotuyatu
/*static void build_success_key_response( int connection, TLSParameters *tls_context, TLSParameters *tls_context2 )
{
  char buf[ 255 ];
  
  ProtectionParameters *parameters ;
  parameters = &tls_context2->active_send_parameters;
 
 sprintf(buf, "key is %s, IV is %s\n", parameters->key,parameters->IV);
  // Technically, this should account for short writes.
  if ( tls_send( connection, buf, sreertrlen( buf ), 0, tls_context) < strlen( buf ) )
  {
    perror( "Trying to respond" );
  }
}*/


static void build_success_key_response( int connection, TLSParameters *tls_context )
{
  char *buf;
  FILE *fp;
  buf =(char *)malloc(sizeof(SubParameters));
  /* ProtectionParameters *parameterse ,*parameterre;
 parameterse = &tls_context->active_send_parameters;
 parameterre = &tls_context->active_recv_parameters;

 memcpy(buf,parameterre->MAC_secret,20);
 memcpy((buf)+20,parameterre->key,24);
 memcpy((buf)+20+24,parameterre->IV,8);
 memcpy((buf)+20+24+8,parameterre->seq_num,sizeof(long)); */
 key_out(tls_context);
 fp=fopen("./keyfile/key0.dat","rb");
 fread(buf,sizeof(SubParameters),1,fp);
 fclose(fp);

 //fprintf(stderr,"tls_point is %p\n",tls_context);
  //sprintf(buf,"%s and %s",&tls_context->active_send_parameters->IV, &tls_context->active_send_parameters->key);
  // Technically, this should account for short writes.
  if ( tls_send( connection, buf, strlen( buf ), 0, tls_context ) < strlen( buf ) )
  {
    perror( "Trying to respond" );
  }
}


static void build_error_response( int connection, 
                                  int error_code, 
                                  TLSParameters *tls_context )
{
  char buf[ 255 ];
  sprintf( buf, "HTTP/1.1 %d Error Occurred\r\n\r\n", error_code );

  // Technically, this should account for short writes.
  if ( tls_send( connection, buf, strlen( buf ), 0, tls_context ) < strlen( buf ) )
  {
    perror( "Trying to respond" );
  }
}

static void process_https_request( int connection )

{
  char *request_line; 
  TLSParameters tls_context;

  if ( tls_accept( connection, &tls_context ) )
  {
    perror( "Unable to establish SSL connection" );
  } 
  else
  {
    request_line = read_line( connection, &tls_context );
//fprintf(stderr,"line %s\n",request_line);
   
   if (!strncmp( request_line, "KEY", 3 ) )
    {
      while ( strcmp( read_line( connection, &tls_context ), "" ) )
      {
        printf( "skipped a header line\n" );
      }
      
      //tls_recv(connection-1,NULL,0,0, &tls_context2);
      //build_success_key_response( connection, &tls_context , &tls_context2 );
      build_success_key_response( connection, &tls_context);
    }
   
   
    else if ( strncmp( request_line, "GET", 3 ) )
    {
      // Only supports "GET" requests
      build_error_response( connection, 400, &tls_context );
    }
    
    
    else
    { 
      // Skip over all header lines, don't care
      while ( strcmp( read_line( connection, &tls_context ), "" ) )
      {
        printf( "skipped a header line\n" );
      }

      build_success_response( connection, &tls_context );
    }
   // fprintf(stderr,"connection is %d\n",connection);
    //fprintf(stderr,"tls_point is %p\n",&tls_context);
    
    //tls_message_finish( connection, &tls_context );
    tls_shutdown( connection, &tls_context );
    
  }
#ifdef WIN32
  if ( closesocket( connection ) == -1 )
#else
  if ( close( connection ) == -1 )
#endif
 {
    perror( "Unable to close connection" );
  }

  fprintf(stderr,"\n");
}

int main( int argc, char *argv[ ] )
{
  int listen_sock;
  int connect_sock;
  int on = 1;
  struct sockaddr_in local_addr;
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof( client_addr );
#ifdef WIN32
  WSADATA wsaData;
 
  if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != NO_ERROR )
  {
     perror( "Unable to initialize winsock" );
     exit( 0 );
  }
#endif

  if ( ( listen_sock = socket( PF_INET, SOCK_STREAM, 0 ) ) == -1 )
  {
    perror( "Unable to create listening socket" );
    exit( 0 );
  }

  if ( setsockopt( listen_sock, 
           SOL_SOCKET, 
           SO_REUSEADDR, 
           &on, sizeof( on ) ) == -1 )
  {
    perror( "Setting socket option" );
    exit( 0 );
  }

  local_addr.sin_family = AF_INET;
  local_addr.sin_port = htons( HTTPS_PORT );
  //local_addr.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  local_addr.sin_addr.s_addr = htonl( INADDR_ANY );

  if ( bind( listen_sock, 
        ( struct sockaddr * ) &local_addr, 
        sizeof( local_addr ) ) == -1 )
  {
    perror( "Unable to bind to local address" );
    exit( 0 );
  }
  
  if ( listen( listen_sock, 5 ) == -1 )
  {
    perror( "Unable to set socket backlog" );
    exit( 0 );
  }
//fprintf(stderr,"listen socket is %d \n",listen_sock);
 while ( ( connect_sock = accept( listen_sock, 
                   ( struct sockaddr * ) &client_addr, 
                   &client_addr_len ) ) != -1 )
  {
    // TODO: ideally, this would spawn a new thread.
    
    process_https_request( connect_sock );
    
    
  }
 
  if ( connect_sock == -1 )
  {
    perror( "Unable to accept socket" );
  }

  return 0;
}
