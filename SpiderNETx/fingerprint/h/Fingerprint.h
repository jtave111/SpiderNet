#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <string>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "ping/h/Ping.h"
#include "ping/h/ipResponse.h"
class Fingerprint {
private:
    Ping ping;
    IpResponse iprsp;

public:
    struct TargetIfo {
        std::string status;
        int ttl;
        std::string ip;
        double rtt_ms;
    };

    TargetIfo fingerprinting(const char *ip);
    std::string os_detector(const char *ip);
    uint32_t ipToInt(const std::string& ip);
    std::string intToIpStr(uint32_t ip);
    std::string process_info(int port);
    std::string dns_resolver(char *buffer);
};

#endif