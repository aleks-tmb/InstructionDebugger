#include <cstdlib>
#include <iostream>
#include <memory>
#include <unistd.h>
#include <utility>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <boost/asio.hpp>

#include "debugger.h"
#include "server_debugger.h"
#include "utils.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <program to debug> <port>" << std::endl;
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(argv[1], argv[1], nullptr);
    } else if (pid > 0) {
      debugger::Debugger debugger(pid, argv[1]);
      debugger.run();

      try {
        boost::asio::io_context io_context;
        debugger::ServerDebugger s(io_context, std::atoi(argv[2]), debugger);
        io_context.run();
      } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return -1;
      }
    } else {
        std::cerr << "Fork failed!" << std::endl;
        return -1;
    }

    return 0;
}