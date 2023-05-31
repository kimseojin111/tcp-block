#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
// #include "libnet-headers.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h> // bool
#include <netinet/ip.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h> 
#include <sys/wait.h>

#define ETHSIZE 14

void usuage() {
    printf("syntax : tcp-block <interface> <pattern>");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

char* dev; 
char* pattern; 

bool parse(int argc, char* argv[]){
    if(argc!=3) {
        usuage();
        return false;
    }
    dev = argv[1];
    //printf("%s\n",host);
    pattern = argv[2];
    //printf("%s\n",pattern);
    return true;
}

void dump(unsigned char* buf, int size) {
	printf("-----------------------start dump-----------------------\n");
	int i;
	for (i = 0; i < size; i++) {
		//if (i != 0 && i % 16 == 0)
		//	printf("\n");
		printf("%c", buf[i]);
	}
	printf("\n------------------------------------------------------------------------------\n");

}

bool check_pattern(pcap_t* pcap){
    
}

int main(int argc, char* argv[]){
    if(!parse(argc, argv)) return -1; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
    while(true){
        //printf("\n----------packet capture------------\n"); 
        struct pcap_pkthdr* header; 
        const u_char* packet; 
        int res = pcap_next_ex(pcap,&header,&packet); 
        if(res==0) continue; 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        struct ether_header* ether = (struct ether_header*)packet; 
        /*
                printf("dhost : ");
        for(int i=0;i<ETH_ALEN;i++){
            printf("%02x",ether->ether_shost[i]);
        }
        */
        // printf("%d",ether->ether_type);
        // capture only ipv4 
        if(htons(ether->ether_type)!=0x0800) continue; 
        //printf("ip4\n");
        struct iphdr* ipv4_header = (struct iphdr*)(packet + ETHSIZE);
        // printf("%d",ipv4_header->protocol);
        //capture only tcp 
        if(ipv4_header->protocol != 0x06) continue; 
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + ETHSIZE + (ipv4_header->ihl)*4);  
        if(ntohs(tcp_header->th_dport)!=80) continue;
        //printf("Source Port: %d\n", ntohs(tcp_header->th_dport));
        //printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
        //printf("3");
        unsigned char* http_header = (unsigned char*)(packet + ETHSIZE + (ipv4_header->ihl*4) + (tcp_header->th_off*4));
        if(strstr((char*)http_header,pattern)!=NULL){
            printf("\nbad\n");
        }
        else continue; 
        //dump(http_header,256);
        u_char *dhost = ether->ether_dhost;  
        u_char *shost = ether->ether_shost; 
        printf("source host mac : ");
        for(int i=0;i<ETH_ALEN+1;i++) printf("%02x",shost[i]);
        printf("\nsource dest mac : ");
        for(int i=0;i<ETH_ALEN+1;i++) printf("%02x",dhost[i]);    
        printf("\n");    

        // send forward packet 
        uint16_t total_len = ntohs(ipv4_header->tot_len); 
        printf("total length : %d\n",total_len);
        printf("total ?? : %d\n",header->caplen);
        // check http_header length to get seq number 
        int http_len = total_len - (ipv4_header->ihl*4) - (tcp_header->th_off*4); 
        printf("http len : %d\n",http_len);
        printf("ack : %u\n", ntohl(tcp_header->th_ack));
        printf("seq : %u\n", ntohl(tcp_header->th_seq));



        char forward_packet[1000];
        for(int i=0;i<total_len;i++) forward_packet[i] = packet[i];
        struct ether_header *forward_ether = (struct ether_header*)forward_packet; 
        struct iphdr* forward_ip = (struct iphdr*)(forward_packet + ETHSIZE); 
        struct tcphdr* forward_tcp = (struct tcphdr*)(forward_packet + ETHSIZE + (forward_ip->ihl)*4); 
        //forward_tcp 

        













    }



}





























