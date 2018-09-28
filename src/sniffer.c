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

void process(unsigned char* buffer);

int sock_raw;
FILE *logfile;

void sig_term_handler(int signum, siginfo_t *info, void *ptr)
{
    fprintf(logfile, "Daemon terminated\n");
    fflush(logfile);
    close(sock_raw);
}

void catch_sigterm()
{
    static struct sigaction _sigact;

    memset(&_sigact, 0, sizeof(_sigact));
    _sigact.sa_sigaction = sig_term_handler;
    _sigact.sa_flags = SA_SIGINFO;

    sigaction(SIGTERM, &_sigact, NULL);
}

int sniff()
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    logfile=fopen("log.txt","w");

    catch_sigterm();

    if(logfile==NULL){
        syslog (LOG_NOTICE, "Unable to crate a file \n");
        return 1;
    }

    fprintf(logfile, "Starting...\n");
    fflush(logfile);

    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        fprintf(logfile, "Socket Error\n");
        fflush(logfile);
        return 1;
    }

    char ifname[] = "enp2s0";
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
    fprintf(logfile, "Exit");
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
