#ifndef IPRESPONSE_H
#define IPRESPONSE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string>
#include <cstring>
#include <unistd.h>

class IpResponse {
public:

    unsigned short checksum(void *b, int len); 
    bool ip_response(const char *ip);       
    
    
};

#endif