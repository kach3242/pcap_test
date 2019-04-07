#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "pack.h"

void pack(const unsigned char* data){
    struct eth_header *eth = (struct eth_header *)data;
    if(ntohs(eth->eth_type) == ipv4){
        struct ip_header *ip = (struct ip_header *)(data + sizeof(*eth));
        uint16_t ipv4_len = (ip->ipv4_len & 0x0F)<<2;
        if(ip->pid == 6){
            struct tcp_header *tcp = (struct tcp_header *)((uint8_t *)ip + ipv4_len);
            uint16_t tcp_len = (tcp->hlen & 0xF0)>>2;
            if((ntohs(tcp->sport) == 80 || ntohs(tcp->dport) == 80)){
                char *http_data = (char *)((uint8_t *)tcp + tcp_len);
                int p = 0;
                printf("smac : ");
                for(int i=0; i<6; i++){
                    if(p<6){
                        printf("%02x:",eth->smac[i]);
                        p++;
                        if(p==6){
                            i = -1;
                            printf("\b \n");
                            printf("dmac : ");
                        }
                    }
                    else{
                        printf("%02x:", eth->dmac[i]);
                    }
                }
                printf("\b \n");
                printf("eth_type : %04x\n", ntohs(eth->eth_type));
                printf("sip : %s\n", inet_ntoa(*(struct in_addr *)&ip->sip));
                printf("dip : %s\n", inet_ntoa(*(struct in_addr *)&ip->dip));
                printf("ip_len : %d\n",ipv4_len);
                printf("pid : %d\n", ip->pid);
                printf("sport : %d\n", ntohs(tcp->sport));
                printf("dport : %d\n", ntohs(tcp->dport));
                printf("tcp_len : %d\n", tcp_len);
                uint16_t http_data_len = ntohs(ip->packet_len) - ipv4_len + tcp_len;
                printf("http_data_len : %d\n", http_data_len);
                if(http_data_len > 16){
                    for (int i=0; i<16; i++) {
                        printf("%c", http_data[i]);
                    }
                }
                else if(http_data_len > 0) {
                    printf("%s", http_data);
                }
                printf("\n\n");
            }
        }
    }
}
