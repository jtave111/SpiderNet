#ifndef APP_H
#define APP_H

#include <string>
#include "scanner/h/Scanner.h"
#include "DOS/h/Dos.h"
#include "server/tcp/h/EchoServer.h"

class App {
private:
    Scanner scanner;
    Dos dos_tool;
    EchoServer echo_server;

    void spider_name();
    void man();
    bool is_root();

public:
    App() = default;
    void run(int argc, char* argv[]);
};

#endif