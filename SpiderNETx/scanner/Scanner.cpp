#include "h/Scanner.h"
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
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <math.h>
#include <string>
#include <mutex>
#include <sstream>
#include <sys/types.h>
#include <sys/select.h>

void Scanner::make_scan_rage(std::string ip) {
    if(iprsp.ip_response(ip.c_str()) == true) {
        print_lock.lock();
        printf("[*] host oline: %s \n", ip.c_str());
        print_lock.unlock();
    }
}

uint32_t Scanner::ipToInt(const std::string& ip) {
    std::stringstream ss(ip);
    uint32_t a, b, c, d;
    char p;
    ss >> a >> p >> b >> p >> c >> p >> d;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::string Scanner::intToIpStr(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

void Scanner::show_ips(const std::string& ip_str, int CIDR) {
    
    std::vector<std::thread> spiders;
    uint32_t ip = ipToInt(ip_str);
    uint32_t mask = 0xFFFFFFFF << (32 - CIDR);
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;

    std::cout << "[*] Network: " << intToIpStr(network) << std::endl;
    std::cout << "[*] Broadcast: " << intToIpStr(broadcast) << std::endl;
    std::cout << "- - - - - - - - - - - - - - - - \n";

    for(uint32_t i = network + 1; i < broadcast; i++) {
        spiders.emplace_back(&Scanner::make_scan_rage, this, intToIpStr(i));
    }

    for(auto& t : spiders) {
        if(t.joinable()) t.join();
    }
}

bool Scanner::scan_port_aux(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return false;

    struct sockaddr_in host;
    host.sin_family = AF_INET;
    host.sin_port = htons(port);
    inet_pton(AF_INET, ip, &host.sin_addr);

    int connection = connect(sock, (struct sockaddr*)&host, sizeof(host));
    if(connection < 0) {
        close(sock);
        return false;
    }
    close(sock);
    return true;
}

void Scanner::scan_port(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        fprintf(stderr, "[-]Error creating socket\n ");
        return;
    }

    struct timeval tv;
    tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    struct sockaddr_in host;
    host.sin_family = AF_INET;
    host.sin_port = htons(port);
    inet_pton(AF_INET, ip, &host.sin_addr);

    int connection = connect(sock, (struct sockaddr*)&host, sizeof(host));
    if(connection == 0) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        int bytes = recv(sock, buffer, 1023, 0);

        if(port == 80 || port == 443 || port == 8080) {
            const char* req = "HEAD / HTTP/1.0\r\n\r\n";
            send(sock, req, strlen(req), 0);
        }

        std::string os = fingerprint.os_detector(ip);
        if(bytes > 0) {
            printf("[*] Connected \n");
            printf("[*] %s", buffer);
            printf("[*] Os: %s\n", os.c_str());
        } else {
            printf("[*] Connected \n");
            printf("[-] No banner service\n");
            printf("[*] Port: %i, proocess info: %s\n ", port, fingerprint.process_info(port).c_str());
        }
    }
    close(sock);
}

void Scanner::scan_all(const char *ip, std::vector<int> ports) {
    for(size_t i = 0; i < ports.size(); i++) {
        if(scan_port_aux(ip, ports[i]) == true) {
            std::string os = fingerprint.os_detector(ip);
            printf("\n==================================\n");
            printf("[*] Port: %i open \n", ports[i]);
            printf("[*] Process %s\n", fingerprint.process_info(ports[i]).c_str());
            printf("[*]Os: %s\n", os.c_str());
            printf("==================================\n");
        } else {
            printf("[*] Port %i, %s closed\n", ports[i], fingerprint.process_info(ports[i]).c_str());
        }
    }
}

void Scanner::scan_all(const char *ip) {
    printf("[*] Scanning . . . \n");
    for(int i = 0; i <= 65535; i++) {
        struct servent *service;
        service = getservbyport(htons(i), "tcp");
        if(scan_port_aux(ip, i) == true) {
            if(service != NULL) {
                printf("[*] Open port: %i, %s in host: %s \n", i, ip, service->s_name);
            } else {
                printf("[*] Open port: %i,[service undefine] in host: %s \n", i, ip);
            }
        }
    }
}

void Scanner::pingHost(const char *ip) {
    if(ping.ping(ip) == true) {
        printf("[*] Host valid\n");
        while(true) {
            printf("[*] Send ping\n");
        }
    } else {
        fprintf(stderr, "Invalid host\n");
    }
}