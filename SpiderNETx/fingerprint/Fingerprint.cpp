#include "h/Fingerprint.h"
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sstream>

Fingerprint::TargetIfo Fingerprint::fingerprinting(const char *ip) {
    TargetIfo info_target;
    info_target.ttl = 0;
    info_target.ip = ip;
    info_target.status = "OFILINE";

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return info_target;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &target.sin_addr);

    char package[64];
    memset(package, 0, sizeof(package));
    struct icmphdr *icmp = (struct icmphdr*)package;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(1234);
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = iprsp.checksum(package, sizeof(package));

    sendto(sock, package, sizeof(package), 0, (struct sockaddr*)&target, sizeof(target));

    char buffer_respost[256];
    struct sockaddr_in sender;
    socklen_t len = sizeof(sender);

    while (true) {
        int bytes = recvfrom(sock, buffer_respost, sizeof(buffer_respost), 0, (struct sockaddr*)&sender, &len);
        if (bytes <= 0) {
            close(sock);
            info_target.status = "OFILINE";
            return info_target;
        }

        struct iphdr *ip_header = (struct iphdr *)buffer_respost;
        int header_len = ip_header->ihl * 4;
        struct icmphdr *reply = (struct icmphdr *)(buffer_respost + header_len);
        int capture_ttl = ip_header->ttl;

        if (reply->type == ICMP_ECHOREPLY && reply->un.echo.id == htons(1234)) {
            char d[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender.sin_addr, d, INET_ADDRSTRLEN);
            if (std::string(ip) == std::string(d)) {
                close(sock);
                info_target.status = "OLINE";
                info_target.ttl = capture_ttl;
                return info_target;
            } else {
                continue;
            }
        }
    }
    close(sock);
    return info_target;
}

std::string Fingerprint::os_detector(const char *ip) {
    if (iprsp.ip_response(ip) == false) return "refused_connection";
    TargetIfo target_info = fingerprinting(ip);
    if (target_info.ttl == 0) return "No os detected";
    else if (target_info.ttl <= 64) return "Linux";
    else if (target_info.ttl <= 126) return "Windows";
    else if (target_info.ttl <= 255) return "Router";
    else return "unknown ";
}

uint32_t Fingerprint::ipToInt(const std::string& ip) {
    std::stringstream ss(ip);
    uint32_t a, b, c, d;
    char p;
    ss >> a >> p >> b >> p >> c >> p >> d;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::string Fingerprint::intToIpStr(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

std::string Fingerprint::process_info(int port) {
    struct servent *service;
    service = getservbyport(htons(port), "tcp");
    if (service) return std::string(service->s_name);
    return "unknown";
}

std::string Fingerprint::dns_resolver(char *buffer) {
    struct hostent *hostInfo = gethostbyname(buffer);
    if (!hostInfo) return "Host not found";
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, hostInfo->h_addr, ip, INET_ADDRSTRLEN);
    if (iprsp.ip_response(ip) == false) return "Connection refused";
    return std::string(ip);
}