#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <iostream>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include "ping/h/Ping.h"
#include "ping/h/ipResponse.h"
#include "fingerprint/h/Fingerprint.h"

class Scanner {
private:
    Ping ping;
    IpResponse iprsp;
    Fingerprint fingerprint;
    std::mutex print_lock;

    uint32_t ipToInt(const std::string& ip);
    std::string intToIpStr(uint32_t ip);
    bool scan_port_aux(const char* ip, int port);
    
    void make_scan_rage(std::string ip);

public:
    Scanner() = default;

    void show_ips(const std::string& ip_str, int CIDR);

    void scan_port(const char* ip, int port);

    void scan_all(const char* ip, std::vector<int> ports);

    void scan_all(const char* ip);


    void pingHost(const char* ip);
};

#endif