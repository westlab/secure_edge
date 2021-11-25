#include <iostream> //標準入出力
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include <string> //string型
#include<string.h>
#include "des.h"
#include "tls.h"
#include"keyclient.h"
#include<time.h>
#include<sys/time.h>
void key_get(SubParameters *key)
{
	struct timeval stTime,fiTime;
	//ソケットの生成
	int sockfd = socket(AF_INET, SOCK_STREAM, 0); //アドレスドメイン, ソケットタイプ, プロトコル
	if(sockfd < 0){ //エラー処理

		perror("Error socket:"); //標準出力
		exit(1); //異常終了
	}

	//アドレスの生成
	struct sockaddr_in addr; //接続先の情報用の構造体(ipv4)
	memset(&addr, 0, sizeof(struct sockaddr_in)); //memsetで初期化
	addr.sin_family = AF_INET; //アドレスファミリ(ipv4)
	addr.sin_port = htons(50000); //ポート番号,htons()関数は16bitホストバイトオーダーをネットワークバイトオーダーに変換
	addr.sin_addr.s_addr = inet_addr("10.0.1.2"); //IPアドレス,inet_addr()関数はアドレスの翻訳

	//ソケット接続要求
	connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)); //ソケット, アドレスポインタ, アドレスサイズ

	//鍵の準備
	FILE *mkf;
	mkf=fopen("masterkey","rb");
	SubParameters2 *master_key;
	master_key =(SubParameters2 *)malloc(sizeof(*master_key));
	fread(master_key,sizeof(*master_key),1,mkf);
	fclose(mkf);

	//データ送信
	gettimeofday(&stTime,NULL);
	char s_str[] = "Go!"; //送信データ格納用
	send(sockfd, s_str, 12, 0); //送信
	//std::cout << s_str << std::endl;

	//データ受信
	unsigned char r_str[80]; //受信データ格納用
	unsigned char *plain_text;
	plain_text =(unsigned char *)malloc(80);
	recv(sockfd, r_str, 80, 0); //受信
	
	des_decrypt(r_str,80,plain_text,master_key->IV,master_key->key);
	
	/* SubParameters *key;
	key =(SubParameters *)malloc(sizeof(*key)); */
	memcpy(&key->MAC_secret,plain_text,20);
	memcpy(&key->key,plain_text+20,32);
	memcpy(&key->IV,plain_text+52,16);
	memcpy(&key->suite,plain_text+68,sizeof(key->suite));
	memcpy(&key->seq_num,plain_text+68+sizeof(key->suite),sizeof(long));
	gettimeofday(&fiTime,NULL);
	int long sec,usec;
	sec=fiTime.tv_sec-stTime.tv_sec;
	usec=fiTime.tv_usec-stTime.tv_usec;

	FILE *ef;
	ef =fopen("eva1.csv","a");
	fprintf(ef,"%ld\n",usec);
	fclose(ef);
	
	//std::cout << plain_text << std::endl; //標準出力

	FILE *fp;
	fp =fopen("keydata","wb");
	fwrite(plain_text,sizeof(r_str),1,fp);
	fclose(fp);
	//ソケットクローズ
	close(sockfd);
	free(master_key);
	free(plain_text);

	
}
 # ifdef TEST_CLIENT
int main(){
	SubParameters *key;
	key =(SubParameters *)malloc(sizeof(*key));
	key_get(key);
	
	std::cout << key << std::endl;
	return 0;
}


 #endif