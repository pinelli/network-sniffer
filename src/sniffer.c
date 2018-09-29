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

int hand_pipe[2]; //handler out, sniffer in
int snif_pipe[2]; //sniffer out, handler in

void termination_handler(int s){
    fprintf(logfile, "Daemon terminated!!!!!!!!!!!!\n");
    char ch = 'i';
    int res = write (hand_pipe[1], &ch,1);
    fflush(logfile);
//    close(sock_raw);
}

void create_logger(){
    logfile=fopen("log.txt","w");

    if(logfile==NULL){
        syslog (LOG_NOTICE, "Unable to crate a file \n");
        exit(1);
    }
}

int max_fd(int a, int b){
    return a >= b?a:b;
}


void* sniff(void *socket){
    int saddr_size , data_size;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *)malloc(65536);

    int sock_raw = *(int*)socket;

    fd_set readfds;

    saddr_size = sizeof saddr;

    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(sock_raw, &readfds);
        FD_SET(hand_pipe[0], &readfds);
        select(max_fd(sock_raw, hand_pipe[0]) + 1, &readfds, NULL, NULL, NULL);

        if(FD_ISSET(sock_raw, &readfds)){
            fprintf(logfile, "\n FD_ISSET\n");
            fflush(logfile);
            data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
            if(data_size < 0 ){
                fprintf(logfile, "\n < 0\n");
                fflush(logfile);
                break;
            }
            process(buffer);
        }
        else if(FD_ISSET(hand_pipe[0], &readfds)){
            fprintf(logfile, "\n GOT TERMINATION\n");
            fflush(logfile);
//            char val;
//            read (hand_pipe[0], &val, 1);
//            val = 'o'; //ok
//            write (snif_pipe[1], &val, 1);
            break;
        }
    }
    fprintf(logfile, "Finished sniffing");
    fflush(logfile);

    return NULL;
}

int create_socket(char *ifname){
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0) {
        fprintf(logfile, "Socket Error\n");
        fflush(logfile);
        return -1;
    }

    int rc = setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
    if (rc < 0){
        fprintf(logfile, "Failed binding socket to ifname %s\n", (char*)ifname);
        fflush(logfile);
        return -1;
    }
    return sock_raw;
}

void start_handler(){
    char ifname[] = "enp2s0";
    pthread_t sniffer;
    int  thread_err;
    int pipe_res;

    int socket = create_socket(ifname);

    pipe_res = pipe(hand_pipe);
    if (pipe_res < 0){
        fprintf(logfile, "Cannot create handler->sniffer pipe\n");
        fflush(logfile);
        return;
    }
    pipe_res = pipe(snif_pipe);
    if (pipe_res < 0){
        fprintf(logfile, "Cannot create sniffer->handler pipe\n");
        fflush(logfile);
        return;
    }

    thread_err = pthread_create(&sniffer, NULL, sniff, &socket);

    if (thread_err != 0){
        fprintf(logfile, "\ncan't create thread :[%s]", strerror(thread_err));
        fflush(logfile);
    } else {
        fprintf(logfile, "\n Thread created successfully\n");
        fflush(logfile);
    }
    fprintf(logfile, "End start handler\n");
    fflush(logfile);

}

int controller()
{
    create_logger();

    signal(SIGTERM, termination_handler);
    signal(SIGINT, termination_handler);

    fprintf(logfile, "Starting...\n");
    fflush(logfile);


    start_handler();
//    fprintf(logfile, "OK1\n");
//    fflush(logfile);
//
////    sleep(3);
    char val;
//    fprintf(logfile, "OK2\n");
//    fflush(logfile);
//
////
    int res = read(snif_pipe[0], &val, 1);
////
////    fprintf(logfile, "\n THE END, %d\n", res);
//    fprintf(logfile, "\n THE END!\n");
//    fflush(logfile);

    while(1){}

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
