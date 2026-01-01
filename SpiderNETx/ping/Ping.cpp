#include "h/Ping.h"
#include <cstring>
#include <cstdio>

unsigned short Ping::checksum(void *b, int len) {    
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

bool Ping::ping(const char *ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock < 0) return false;

    struct timeval tv {};
    tv.tv_sec = 0;
    tv.tv_usec = 200000;

    setsockopt(
        sock,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &tv,
        sizeof(tv)
    );

    struct sockaddr_in target {};
    target.sin_family = AF_INET;
    
    if (inet_pton(AF_INET, ip, &target.sin_addr) != 1) {
        close(sock);
        return false;
    }

    char packet[sizeof(struct icmphdr)]{};
    struct icmphdr *icmp = (struct icmphdr*)packet;

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = checksum(packet, sizeof(packet));

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&target, sizeof(target)) < 0) {
        close(sock);
        return false;
    }

    char buffer[1024];
    struct sockaddr_in sender{};
    socklen_t len = sizeof(sender);
    
    int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender, &len);
    if (bytes <= 0) {
        close(sock);
        return false;
    }

    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    int ip_len = ip_hdr->ihl * 4;

    if (bytes < ip_len + (int)sizeof(struct icmphdr)) {
        close(sock);
        return false;
    }

    struct icmphdr *reply = (struct icmphdr*)(buffer + ip_len);
    
    bool ok = (reply->type == ICMP_ECHOREPLY &&
               reply->un.echo.id == icmp->un.echo.id &&
               sender.sin_addr.s_addr == target.sin_addr.s_addr);

    close(sock);
    return ok;
}