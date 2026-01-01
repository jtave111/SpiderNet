#ifndef APP_H
#define APP_H

#include <string>
#include "scanner/h/Scanner.h"
#include "DOS/h/Dos.h"

class App {
private:
    Scanner scanner;
    Dos dos_tool;

    void spider_name();
    void man();
    bool is_root();

public:
    App() = default;
    void run(int argc, char* argv[]);
};

#endif