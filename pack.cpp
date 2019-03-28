#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "pack.h"

void pack(const unsigned char* data){
    struct eth_header *eth = (struct eth_header *)data;
    struct ip_header *ip = (struct ip_header *)(data+eth_size);
    uint8_t ipv4_len = (ip->ipv4_len & 0x0F)<<2;
    struct tcp_header *tcp = (struct tcp_header *)(data+eth_size+ipv4_len);
    uint8_t tcp_len = (tcp->hlen & 0xF0)>>2;
    char *http_data = (char *)(data+eth_size+ipv4_len+tcp_len);
    if(ntohs(eth->eth_type) == ipv4 && ip->pid == 6 && (ntohs(tcp->sport) == 80 || ntohs(tcp->dport) == 80)){
        printf("smac : ");
        for(int i=0; i<6; i++){
            printf("%02x:",eth->smac[i]);
        }
        printf("\b \n");
        printf("dmac : ");
        for(int i=0; i<6; i++){
            printf("%02x:",eth->dmac[i]);
        }
        printf("\b \n");
        printf("eth_type : %04x\n",ntohs(eth->eth_type));
        printf("sip : %s\n",inet_ntoa(*(struct in_addr *)&ip->sip));
        printf("dip : %s\n",inet_ntoa(*(struct in_addr *)&ip->dip));
        printf("ip_len : %d\n",ipv4_len);
        printf("pid : %d\n", ip->pid);
        printf("sport : %d\n",ntohs(tcp->sport));
        printf("dport : %d\n",ntohs(tcp->dport));
        printf("tcp_len : %d\n",tcp_len);
        printf("http_data_len : %d\n",strlen(http_data));
        if(strlen(http_data)>16){
            for (int i=0; i<16; i++) {
                printf("%c", http_data[i]);
            }
        }
        else {
            printf("%s",http_data);
        }
        printf("\n\n");
    }
}
