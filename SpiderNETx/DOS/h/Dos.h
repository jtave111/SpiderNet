#ifndef DOS_H
#define DOS_H

#include <iostream>
#include <vector>
#include <thread>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/types.h>

#include "ping/h/ipResponse.h"

class Dos {
private:
    IpResponse iprsp;

public:
    void tcp_flood(const char *ip, int port);
    
    void ping_flood(const char *ip, int size);
    
    void dOS(int th, const char *ip, int type);
};

#endif