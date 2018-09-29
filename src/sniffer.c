#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <zconf.h>
#include <err.h>
#include <syslog.h>
#include <bits/types/siginfo_t.h>
#include <signal.h>
#include <pthread.h>

void process(unsigned char* buffer);

int sock_raw;
FILE *logfile;


void termination_handler(int s){
    fprintf(logfile, "Daemon terminated!!!!!!!!!!!!\n");
    fflush(logfile);
    close(sock_raw);
//    shutdown(sock_raw, SHUT_RDWR);
}

void create_logger(){
    logfile=fopen("log.txt","w");

    if(logfile==NULL){
        syslog (LOG_NOTICE, "Unable to crate a file \n");
        exit(1);
    }
}

void* sniff(void *ifname){
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        fprintf(logfile, "Socket Error\n");
        fflush(logfile);
        return NULL;
    }

    int rc = setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
    if (rc < 0)
        err(1, "Failed binding socket to ifname %s", ifname);

    while(1)
    {
        saddr_size = sizeof saddr;

        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size < 0 )
            break;

        process(buffer);
    }
    fprintf(logfile, "Finished sniffing");
    fflush(logfile);

//    while(1){
//        fprintf(logfile, "sniffing on %s\n", (char*) ifname);
//        fflush(logfile);
//        sleep(3);
//    }
    return NULL;
}

int sniffer()
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    pthread_t thread1;
    int  thread_err;

    create_logger();

    signal(SIGTERM, termination_handler);
    signal(SIGINT, termination_handler);

    fprintf(logfile, "Starting...\n");
    fflush(logfile);

    char ifname[] = "enp2s0";


    thread_err = pthread_create( &thread1, NULL, sniff, (void*) ifname);

    if (thread_err != 0){
        fprintf(logfile, "\ncan't create thread :[%s]", strerror(thread_err));
        fflush(logfile);
    } else {
        fprintf(logfile, "\n Thread created successfully\n");
        fflush(logfile);
    }
    fprintf(logfile, "Wait for a thread\n");
    fflush(logfile);

    pthread_join(thread1, NULL);






//    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
//    if(sock_raw < 0)
//    {
//        fprintf(logfile, "Socket Error\n");
//        fflush(logfile);
//        return 1;
//    }
//
//    int rc = setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
//    if (rc < 0)
//        err(1, "Failed binding socket to ifname %s", ifname);
//
//    while(1)
//    {
//        saddr_size = sizeof saddr;
//        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
//        if(data_size < 0 )
//            break;
//
//        process(buffer);
//    }
    fprintf(logfile, "Exit");
    fflush(logfile);

}

void process(unsigned char* buffer){
    struct iphdr *iph = (struct iphdr*)buffer;
    unsigned char octet[4]  = {0,0,0,0};

    for (int i=0; i<4; i++)
    {
        octet[i] = ( iph->saddr >> (i*8) ) & 0xFF;
    }

    fprintf(logfile, "CONNECTION:%d.%d.%d.%d\n",octet[3],octet[2],octet[1],octet[0]);
    fflush(logfile);
}
