#include "h/EchoServer.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

void EchoServer::startEchoTcpServer(char * ip, int port){

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0) return;


    int opt = 1;

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));


    struct sockaddr_in server {};

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);

    
    if(bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0){

        fprintf(stderr, "[x] Blind error");
        close(sock);
        return;

    }


    int ls =  listen(sock, 100);  

    if(ls < 0) {
        
        return;
    }


    struct sockaddr_in client {};
    socklen_t client_len = sizeof(client);

    while (true)
    {        

        int socket_agent = accept(sock, (struct sockaddr *)&client, &client_len);


        if(socket_agent > 0){

            while (true){
                    
                char  buffer [255];
                memset(buffer, 0, sizeof(buffer));


                int bytes_client = recv(socket_agent, buffer, sizeof(buffer) -1, 0);

                if(bytes_client > 0){
                    
                    buffer[bytes_client] = '\0';

                    send(socket_agent, buffer, bytes_client, 0);


                }else if(bytes_client == 0){
                    
                    printf("[*] Client disconected\n");

                    break;

                }else{

                    fprintf(stderr, "[X]Error recv . . \n");
                    
                    break;
                }

                
            }
            close(socket_agent);
            
        }else{

            printf("[x] Accept Error . . \n");
            continue;

        }

    }
    
    close(sock);


}


