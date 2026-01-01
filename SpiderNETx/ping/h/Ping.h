#ifndef PING_H
#define PING_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
class Ping {
public:
    unsigned short checksum(void *b, int len); 
    bool ping(const char *ip);                 
};

#endif