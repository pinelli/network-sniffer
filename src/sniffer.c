#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <zconf.h>
#include <err.h>

void process(unsigned char* buffer);

int sock_raw;
FILE *logfile;

int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    logfile=fopen("log.txt","w");
    if(logfile==NULL) printf("Unable to create file.");
    printf("Starting...\n");
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }

    char ifname[] = "enp2s0";
    int rc = setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
    if (rc < 0)
        err(1, "Failed binding socket to ifname %s", ifname);

    int counter = 0;
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }

        //Now process the packet

        printf("+\n");
        process(buffer);
        counter++;

        if(counter >= 10){
            close(sock_raw);
            printf("Finished");
            return 0;
        }
    }

}

void process(unsigned char* buffer){
    struct iphdr *iph = (struct iphdr*)buffer;
    unsigned char octet[4]  = {0,0,0,0};

    for (int i=0; i<4; i++)
    {
        octet[i] = ( iph->saddr >> (i*8) ) & 0xFF;
    }

    printf("%d.%d.%d.%d\n",octet[3],octet[2],octet[1],octet[0]);
}
