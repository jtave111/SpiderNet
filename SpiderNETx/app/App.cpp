#include "h/App.h"
#include <iostream>
#include <vector>
#include <sstream>
#include <cstdio>
#include <unistd.h>

void App::spider_name() {
    printf(
        " ____        _     _           _   _ _____ _____ \n"
        "/ ___| _ __ (_) __| | ___ _ __| \\ | | ____|_   _|\n"
        "\\___ \\| '_ \\| |/ _` |/ _ \\ '__|  \\| |  _|   | |  \n"
        " ___) | |_) | | (_| |  __/ |  | |\\  | |___  | |  \n"
        "|____/| .__/|_|\\__,_|\\___|_|  |_| \\_|_____| |_|  \n"
        "      |_|                                         \n"
    );
}

void App::man() {
    spider_name();
    printf("\nSpiderNET -- version 0.001\n\n");
    
    //Server
    printf("Servers");
    printf("Usage -sRV: for server\n");
    printf("  -sRV 'ip' -p 'port' -TCP");

    //Scanners 
    printf("Scanners \n");
    printf("Usage: -s: for scanner\n");
    printf(" -sO 'ip' -p 'port'\n");
    printf(" -sL 'ip' -p 'list_ports' ex: --> ./SpiderNet -sL 192.1.1.1 -p 21,22,80,443\n");
    printf(" -sA 'ip': scan all ports in host\n");
    printf(" -sR 'ip/CIDR' --> ./SpiderNet -sR 192.1.1.1/24\n\n");
    
    //Dos
    printf("DOS\n");
    printf(" -For Dos usage -d\n");
    printf(" -d 'ip' -T  --Dos tcp flood\n");
    printf(" -d 'ip' -P  --Dos ping flood\n");
}

bool App::is_root() {
    return geteuid() == 0;
}

void App::run(int argc, char* argv[]) {

    if(!is_root()){
        fprintf(stderr, "[x] Sudo  requirements");
    }

    if (argc <= 1) {
        fprintf(stderr, "Fatal error \n");
        fprintf(stderr, "Use './SpiderNet -H' for more details\n");
        return;
    }

    std::string arg1 = argv[1];

    if (arg1 == "-H" || arg1 == "-h") {
        man();
        return;
    }

   

    // Scanner ---- 
    if (arg1 == "-sA" && argc >= 3) {
        scanner.scan_all(argv[2]);
    }

    else if (arg1 == "-sO" && argc >= 5 && std::string(argv[3]) == "-p") {
        scanner.scan_port(argv[2], std::stoi(argv[4]));
    }

    else if (arg1 == "-sL" && argc >= 5 && std::string(argv[3]) == "-p") {
        
        std::stringstream ss(argv[4]);
        std::string segment;
        std::vector<int> portList;

        while (std::getline(ss, segment, ',')) {
            try {
                portList.push_back(std::stoi(segment));
            } catch (...) {}
        }
        printf("Ports collected\n");
        scanner.scan_all(argv[2], portList);
    }
    else if (arg1 == "-sR" && argc >= 3) {
        
        std::string range = argv[2];
        std::stringstream ss(range);
        std::string ip_base;
        int CIDR = 0;
        if (std::getline(ss, ip_base, '/')) {
            ss >> CIDR;
        }
        if (CIDR > 0 && CIDR <= 32) {
            scanner.show_ips(ip_base, CIDR);
        }
    }
   


    //DOs --- 
    if (arg1 == "-d" && argc >= 4) {
        if (!is_root()) {
            fprintf(stderr, "Fatal ERROR. sudo requirement\n");
            return;
        }
        int th = 100;
        printf("Number of threads: -standard: 100 \n");
        scanf("%i", &th);
        printf("Use ctrl + c for stop\n");

        int type = (std::string(argv[3]) == "-T") ? 1 : 2;
        dos_tool.dOS(th, argv[2], type);
    }




    //Server 
    //printf("  -sRV 'ip' -p 'port' -TCP");

    if(arg1 == "-sRV"){
        std::string flag_port = argv[2];
        std::string flag_proto = argv[4];
        
        if(flag_port == "-p" && flag_proto == "-TCP" ){

            int port = std::stoi(argv[3]);

            printf("[*] Echo TCP server start \n");

            echo_server.startEchoTcpServer(port);


        }

    }
}