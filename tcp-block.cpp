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
#include <iostream>

#define ETHSIZE 14

void usuage() {
    printf("syntax : tcp-block <interface> <pattern>");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

char redirect[] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";

unsigned short calculateChecksum(unsigned short *ptr, int nbytes) {
    unsigned long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;
    
    return answer;
}

uint16_t ip_checksum(iphdr* ipHeader)
{
    ipHeader->check = 0;
	uint16_t *ipHeader16 = (uint16_t *)ipHeader;
	uint32_t sum = 0;


	for (int i = 0; i < 10; i++)
	{
		sum += ntohs(ipHeader16[i]);
	}

	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return htons((uint16_t)~sum);
}

int j = 0;

uint16_t tcp_checksum(iphdr* forward_ip, tcphdr* forward_tcp, int size){ 
    forward_tcp->check = 0;
    struct pseudo_header {
        uint32_t source_address;
        uint32_t destination_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header;
    pseudo_header.source_address = forward_ip->saddr;
    pseudo_header.destination_address = forward_ip->daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(size);
    uint16_t *pseudot = (uint16_t *)&pseudo_header;
    uint32_t sum = 0;
	for (int i = 0; i < 6; i++)
	{
		sum += ntohs(pseudot[i]);
        printf("sum %d : %d\n",j++,sum);
	}
	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
        printf("sum %d : %d\n",j++,sum);
	}
	uint16_t *tcpp = (uint16_t *)forward_tcp;
	for (int i = 0; i < size / 2; i++)
	{
		sum += ntohs(tcpp[i]);
        printf("sum %d : %d\n",j++,sum);
		while (sum >> 16)
		{
			sum = (sum & 0xFFFF) + (sum >> 16);
            printf("sum %d : %d\n",j++,sum);
		}
	}
	if (size % 2 == 1)
	{
		sum += ntohs(tcpp[size / 2]);
        printf("sum %d : %d\n",j++,sum);
	}
    std::cout << "fuckkkkkkkkk" << ntohs((uint16_t)~sum) << std::endl;
    return ntohs((uint16_t)~sum);
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

uint16_t calculate_ip_checksum(const iphdr *header) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)header;

    for(int i=0; i<10; i++){
        sum += ntohs(ptr[i]);
    }

    // 16비트 이상의 체크섬을 반전시킴
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return htons((uint16_t)(~sum));
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
        //printf("protocol : %d\n",ipv4_header->protocol);
        //capture only tcp 
        if(ipv4_header->protocol != 0x06) continue; 
        //printf("?");
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + ETHSIZE + (ipv4_header->ihl)*4);  
        //if(ntohs(tcp_header->th_dport)!=80) continue;
        //printf("Source Port: %d\n", ntohs(tcp_header->th_dport));
        //printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
        //printf("3");
        
        unsigned char* http_header = (unsigned char*)(packet + ETHSIZE + (ipv4_header->ihl*4) + (tcp_header->th_off*4));
        //dump(http_header,256);
        if(strstr((char*)http_header,pattern)!=NULL){
            printf("\nbad\n");
        }
        else continue; 
        
        u_char *dhost = ether->ether_dhost;  
        u_char *shost = ether->ether_shost; 
        printf("source host mac : ");
        for(int i=0;i<ETH_ALEN+1;i++) printf("%02x",shost[i]);
        printf("\nsource dest mac : ");
        for(int i=0;i<ETH_ALEN+1;i++) printf("%02x",dhost[i]);    
        printf("\n");    

        // send forward packet 
        uint16_t total_len = header->caplen; 
        printf("total length : %d\n",total_len);
        printf("total ?? : %d\n",header->caplen);
        // check http_header length to get seq number 
        int http_len = total_len - ETHSIZE -  (ipv4_header->ihl*4) - (tcp_header->th_off*4); 
        printf("http len : %d\n",http_len);
        printf("ack : %u\n", ntohl(tcp_header->th_ack));
        printf("seq : %u\n", ntohl(tcp_header->th_seq));
        printf("flag : %d\n", tcp_header->th_flags);

        char forward_packet[1000];
        for(int i=0;i<total_len;i++) forward_packet[i] = packet[i];
        struct ether_header *forward_ether = (struct ether_header*)forward_packet; 
        struct iphdr* forward_ip = (struct iphdr*)(forward_packet + ETHSIZE); 
        struct tcphdr* forward_tcp = (struct tcphdr*)(forward_packet + ETHSIZE + (forward_ip->ihl)*4); 
        //forward_tcp 
        forward_tcp->doff = sizeof(tcphdr)/4;
        u_int32_t tmp = ntohl(forward_tcp->th_seq) + http_len; 
        forward_tcp->th_seq = htonl(tmp); 
        forward_ip->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr)); 
        forward_ip->check = ip_checksum(forward_ip); 
        printf("checksum : %x\n",forward_ip->check);
        forward_tcp->th_flags = TH_ACK + TH_RST; 
        forward_tcp->check = 0;
	    forward_tcp->check = tcp_checksum(forward_ip, forward_tcp, sizeof(tcphdr));
        printf("FuCKKKKKKKKKKKK %x\n",forward_tcp->check);
        if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(forward_packet), ETHSIZE + (ipv4_header->ihl*4) + (tcp_header->th_off*4)) != 0) {
            std::cout << "패킷 전송 실패: " << pcap_geterr(pcap) << std::endl;
            pcap_close(pcap);
            return 1;
        }

        char backward_packet[1000]; 
        for(int i=0;i<total_len;i++) backward_packet[i] = packet[i];
        struct ether_header *backward_ether = (struct ether_header*)backward_packet; 
        struct iphdr* backward_ip = (struct iphdr*)(backward_packet + ETHSIZE); 
        struct tcphdr* backward_tcp = (struct tcphdr*)(backward_packet + ETHSIZE + (backward_ip->ihl)*4); 
        for(int i=0; i<ETH_ALEN;i++) backward_ether->ether_dhost[i] = backward_ether->ether_shost[i]; 
        backward_ip->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr) + sizeof(redirect)); 
        backward_ip->ttl = 128; 
        backward_ip->daddr = ipv4_header->saddr; 
        backward_ip->saddr = ipv4_header->daddr; 
        backward_tcp->th_sport = tcp_header->th_dport; 
        backward_tcp->th_dport = tcp_header->th_sport; 
        backward_tcp->th_seq = forward_tcp->th_ack; 
        backward_tcp->th_ack = forward_tcp->th_seq; 
        backward_ip->check = ip_checksum(backward_ip); 
        backward_tcp->th_off = sizeof(tcphdr)/4; 
        backward_tcp->th_flags = TH_FIN + TH_ACK;
        int ll = sizeof(ether_header)+sizeof(iphdr)+sizeof(tcphdr);
        for(int i=0; i<sizeof(redirect); i++) backward_packet[i+ll] = redirect[i]; 

        backward_tcp->check = tcp_checksum(backward_ip,backward_tcp,sizeof(tcphdr)+sizeof(redirect)); 

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); 
        int on = 1;
	    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
		    std::cerr << "Failed to set socket options." << std::endl;
		    return -1;
	    }
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = backward_tcp->th_dport;
        dest_addr.sin_addr.s_addr = backward_ip->daddr;
        memset(dest_addr.sin_zero, '\0', sizeof(dest_addr.sin_zero));

        if (sendto(sockfd, backward_packet + ETHSIZE, sizeof(iphdr)+sizeof(tcphdr)+sizeof(redirect), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0){
		std::cerr << "Failed to send packet." << std::endl;
		return -1;
	    }
        close(sockfd);
    }
}





























