#include "h/EchoServer.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
void EchoServer::startEchoTcpServer(char * ip, int port){

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0) return;


    int opt = 1;

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));


    struct sockaddr_in server {};

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);
    socklen_t server_len = sizeof(server);
    
    bind(sock, (struct sockaddr *)&server, sizeof(server));

    int ls =  listen(sock, 100);  

    if(ls < 0) {
        
        return;
    }


    struct sockaddr_in client {};
    socklen_t client_len = sizeof(client);

    while (true)
    {        

        int socket_agent = accept(sock, (struct sockaddr *)&client, &client_len);

    }
    

    //Create step 6(eco talking) - 7(finished),


}


