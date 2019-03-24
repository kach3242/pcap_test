#include <stdio.h>
#include <arpa/inet.h>
#include "pack.h"

void pack(const unsigned char* data){
    unsigned short ethertype[] = {*(data+12), *(data+13)};
    unsigned short* ethtype = (unsigned short*)ethertype;
    unsigned short iptype = *(data+23);
    *ethtype=ntohs(*ethtype);
    unsigned int iplen = (*(data+14) - 0x0040)*4;
    unsigned int Sport = *(data+iplen+14)*256 + *(data+iplen+15);
    unsigned int Dport = *(data+iplen+16)*256 + *(data+iplen+17);
    unsigned int tcplen = (*(data+46)/16)*4;
    if(*ethertype == 0x0800 && iptype == 6 && Dport == 80){
        printf("Smac : ");
        for(int i=6; i<12; i++){
            printf("%02x:", *(data+i));
            if(i==11){
                printf("\b \nDmac : ");
                
                i = -1;
            }
            if(i==5){
                printf("\b \n");
                break;
            }
        }
        printf("SIP  : ");
        for (int i=26; i<34; i++) {
            printf("%d.", *(data+i));
            if(i==29){
                printf("\b \nDIP  : ");
            }
            else if(i==33){
                printf("\b \n");
            }
        }
        printf("Sport  [%d]\n", Sport);
        printf("Dport  [%d]\n", Dport);
        printf("HTTP DATA : ");
        for (int i=0; i<16; i++){ 
            printf("%c", *(data+iplen+tcplen+14+i));
        }
        printf("\n\n");
    }
}

