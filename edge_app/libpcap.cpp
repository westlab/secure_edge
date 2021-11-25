#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include "decry.h"
#include "keyclient.h"
#include<time.h>
#include<sys/time.h>
char *convert_mac_tostr(u_char *, char *, size_t);
char *convert_ip_tostr(u_char *, char *, size_t);

int t =0;

struct ipv4_header {
    u_char ip_ver_len;
    u_char service_type;
    uint16_t packet_len;
    uint16_t id;
    uint16_t fragment;
    u_char ttl;
    u_char protocol;
    uint16_t header_checksum;
    u_char src_ip[4];
    u_char dst_ip[4];
};

struct http_header{
    u_char header_type;
    u_char header_version_major;
    u_char header_version_minor;
    u_short header_length;

};

//pcap_loopのcallback関数で何がしたいかを書くということかな？
void pktfunc_starter(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
      

    struct ipv4_header *ip_hdr; 
    struct http_header *http;
    struct tcphdr *tcp;
    struct timeval stTime,fiTime;
    //Ethernet frame
    struct ether_header *eth_hdr = (struct ether_header *) packet;
    http= (struct http_header *) (packet +sizeof(ether_header)+sizeof(ipv4_header)+sizeof(struct tcphdr)+12UL);//12ULhanazekanagai
  
  
    if(http->header_version_major==3 || http->header_version_minor==1){

        if(http->header_type == 23){
            SubParameters *parameter;
            parameter = (SubParameters *) malloc (sizeof(SubParameters));
            gettimeofday(&stTime,NULL);
            key_get(parameter);
            if(header->len!=119&&header->len!=172){
            char *tlscont =(char *)(packet +sizeof(ether_header)+sizeof(ipv4_header)+sizeof(struct tcphdr)+12UL);
            /* FILE *fp;
            char filepath[256];
            sprintf(filepath,"1buffer.dat");
            fp =fopen(filepath,"wb");
            fwrite(tlscont,(header->len-66),1,fp);
            fclose(fp);
            t++; */
            unsigned char *encrypt,*decrypt;
            encrypt = (unsigned char *)malloc(header->len-66);
            decrypt = (unsigned char *)malloc(header->len-66);
            memcpy(encrypt,tlscont,header->len-66);
           /*  FILE *kf;
            kf=fopen("key.dat","rb"); */
            /* SubParameters *parameter;
            parameter = (SubParameters *) malloc (sizeof(SubParameters));
            
            key_get(parameter); */
            short send_buffer_size;
            send_buffer_size =decry (encrypt,decrypt,parameter);
            display(decrypt,send_buffer_size);
            gettimeofday(&fiTime,NULL);
            free (encrypt);
            free (decrypt);
            int long sec,usec;
	        sec=fiTime.tv_sec-stTime.tv_sec;
	        usec=fiTime.tv_usec-stTime.tv_usec;
    FILE *ef;
	ef =fopen("eva2.csv","a");
	fprintf(ef,"%ld\n",usec);
	fclose(ef);


         }
         free (parameter);
        }

    }

    
}


int main(int argc, char **argv){
    //デバイスに関する定義
    const char *dev = "enp2s0";
    //エラー出力格納用の定義
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 net, mask;
    
    //パケット送信用ハンドラの定義
    pcap_t *handler;
    //filterの構造体
    //struct bpf_program fp;
    //char filter_exp[] = "dst host 192.168.1.61";
    struct pcap_pkthdr header;
    const u_char *packet;

    //デバイスの確認
    if(dev == NULL){
        fprintf(stderr, "Device not found. Error: %s", errbuf);
        return 2;
    }
    //IPの取得ができているか否か
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Netmask not found for %s. Error: %s", dev, errbuf);
    }

    //handleを開けるパケット解析の開始点（上まではエラー処理というわけか）
    handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handler == NULL){
        fprintf(stderr, "Couldn't open device: %s: %s", dev, errbuf);
        return 2;
    }
    
    //パケット検出をループ
    pcap_loop(handler, 1000, pktfunc_starter, NULL);
    //ハンドラを閉じる
    pcap_close(handler);

    



    return 0;
}

//macアドレスを文字列にして返す関数
char *convert_mac_tostr(u_char *hwaddr, char *mac, size_t size){
    snprintf(mac, size, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return mac;
};


char *convert_ip_tostr(u_char *ipaddr, char *ip, size_t size){
    snprintf(ip, size, "%d.%d.%d.%d", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    return ip;
};

//pcap_next
//パケットを一つ読み込んで返す関数
//handleからパケットを読み込んでpkthdrからヘッダ情報を書き込む
//pcap_nextを繰り返すというやり方は非現実的なのでpcap_loopを使う
//pcap_loopで回すのが定石
//int pcap_loop(pcap_t *handle, int count, pcap_handler callback, u_char *user);
//handleの取得, 読み込むパケットの数（負の数を入れるとエラーが出るまで）, ,callbackに渡す第一引数

//pcap_handlerとは？
