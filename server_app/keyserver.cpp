#include <iostream> //標準入出力
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include <string> //string型
#include <string.h>
#include"des2.h"
#include<time.h>
#include<sys/time.h>
int main(){
int on=1;
struct timeval stTime,fiTime;

	//ソケットの生成
	int sockfd = socket(AF_INET, SOCK_STREAM, 0); //アドレスドメイン, ソケットタイプ, プロトコル
	if(sockfd < 0){ //エラー処理

		perror("Error socket:"); //標準出力
		exit(1); //異常終了
	}
	if ( setsockopt( sockfd, 
           SOL_SOCKET, 
           SO_REUSEADDR, 
           &on, sizeof( on ) ) == -1 )
  {
    perror( "Setting socket option" );
    exit( 0 );
  }
	//アドレスの生成
	struct sockaddr_in addr; //接続先の情報用の構造体(ipv4)
	memset(&addr, 0, sizeof(struct sockaddr_in)); //memsetで初期化
	addr.sin_family = AF_INET; //アドレスファミリ(ipv4)
	addr.sin_port = htons(50000); //ポート番号,htons()関数は16bitホストバイトオーダーをネットワークバイトオーダーに変換
	addr.sin_addr.s_addr = htonl(INADDR_ANY); //IPアドレス,inet_addr()関数はアドレスの翻訳

	//ソケット登録
	if(bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0){ //ソケット, アドレスポインタ, アドレスサイズ //エラー処理

		perror("Error bind:"); //標準出力
		exit(1); //異常終了
	}

	//鍵の準備
	FILE *mkf;
	mkf=fopen("./keyfile/masterkey","rb");
	SubParameters2 *master_key;
	master_key =(SubParameters2 *)malloc(sizeof(*master_key));
	fread(master_key,sizeof(*master_key),1,mkf);
	fclose(mkf);

	//受信待ち
	if(listen(sockfd,SOMAXCONN) < 0){ //ソケット, キューの最大長 //エラー処理
        perror("Error listen:"); //標準出力
		close(sockfd); //ソケットクローズ
		exit(1); //異常終了
	}

	//接続待ち
	struct sockaddr_in get_addr; //接続相手のソケットアドレス
	socklen_t len = sizeof(struct sockaddr_in); //接続相手のアドレスサイズ
	int connect;
	while((connect = accept(sockfd, (struct sockaddr *)&get_addr, &len) )!=-1)//接続待ちソケット, 接続相手のソケットアドレスポインタ, 接続相手のアドレスサイズ
	{
	//connect = accept(sockfd, (struct sockaddr *)&get_addr, &len) ;
	if(connect < 0){ //エラー処理

		perror("Error accept:"); //標準出力
		exit(1); //異常終了
	}

	


	//受信
	char str[12]; //受信用データ格納用
	recv(connect, str, 12, 0); //受信
	gettimeofday(&stTime,NULL);
	FILE *kf;
	kf=fopen("./keyfile/key0.dat","rb");
	 
	SubParameters *key;
	key = (SubParameters *)malloc(sizeof(*key));
	fread(key,sizeof(*key),1,kf);
	fclose(kf);
	unsigned char *plain_text;
	plain_text = (unsigned char *)malloc(sizeof(*key));
	memcpy(plain_text,&key->MAC_secret,20);
	memcpy(plain_text+20,&key->key,32);
	memcpy(plain_text+52,&key->IV,16);
	memcpy(plain_text+68,&key->suite,sizeof(key->suite));
	memcpy(plain_text+68+sizeof(key->suite),&key->seq_num,sizeof(long));
	gettimeofday(&fiTime,NULL);




	//std::cout << str << std::endl; //標準出力

	//送信
	unsigned char *send_buffer;
	send_buffer = (unsigned char *)malloc(sizeof(*key));
	des_encrypt(plain_text,sizeof(*key),send_buffer,master_key->IV,master_key->key);
	//send(connect, &str, 12, 0);
	 if(!send(connect, send_buffer, 80, 0)) //送信
	{
		perror("Error send:"); //標準出力
	} 
	
	free(key);
	free(plain_text);
	free(send_buffer);
 
	//std::cout << send_buffer << std::endl; //標準出力

	//ソケットクローズ
	close(connect);
	int sec,usec;
sec=fiTime.tv_sec-stTime.tv_sec;

FILE *ef;
ef =fopen("eva2.csv","a");
fprintf(ef,"%d.%5d\n",sec,usec);
fclose(ef);

	}
	close(sockfd);
	free(master_key);
	



	return 0;
}
