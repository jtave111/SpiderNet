#include "h/ipResponse.h"
#include <cstdio>

unsigned short IpResponse::checksum(void *b, int len) {    
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

bool IpResponse::ip_response(const char *ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    if (sock < 0) return false;

    // Timeout 
    struct timeval tv;
    tv.tv_sec = 0; 
    tv.tv_usec = 200000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Target
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &target.sin_addr);

    // Pacote ICMP  
    char package[64];
    memset(package, 0, sizeof(package));

    struct icmphdr *icmp = (struct icmphdr*)package;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(1234);
    icmp->un.echo.sequence = htons(1);

    // Calcula checksum                         
    icmp->checksum = checksum(package, sizeof(package)); 

    // Envia o pacote
    sendto(sock, package, sizeof(package), 0, (struct sockaddr*)&target, sizeof(target));

    // Resposta do timeout
    char buffer_respost[1024];
    struct sockaddr_in sender;
    socklen_t len = sizeof(sender);

    while(true) {
        int bytes = recvfrom(sock, buffer_respost, sizeof(buffer_respost), 0, (struct sockaddr*)&sender, &len);
    
        if(bytes <= 0) {
            close(sock);
            return false;   
        }

        // Cálculo para ICMP
        struct iphdr *ip_header = (struct iphdr *)buffer_respost;
        int header_len = ip_header->ihl * 4;
        struct icmphdr *reply = (struct icmphdr *)(buffer_respost + header_len);

        // Filtro
        if(reply->type == ICMP_ECHOREPLY && reply->un.echo.id == htons(1234)) {
            char d[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender.sin_addr, d, INET_ADDRSTRLEN);

            if (std::string(ip) == std::string(d)) {
                close(sock);
                return true;
            } else {
                continue; 
            }
        }
    }
}