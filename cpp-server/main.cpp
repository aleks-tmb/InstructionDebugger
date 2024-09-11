#include "debugger.h"
#include "utils.h"
#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

class CLIDebugger : public debugger::Debugger {
public:
    CLIDebugger(pid_t pid, const std::string& program) : Debugger(pid, program) {}

protected:
    void respond(const std::string& message) override {
        std::cout << message << std::endl;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <program to debug>" << std::endl;
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(argv[1], argv[1], nullptr);
    } else if (pid > 0) {
        debugger::Debugger debugger(pid, argv[1]);
        debugger.run();
    } else {
        std::cerr << "Fork failed!" << std::endl;
        return -1;
    }

    return 0;
}
