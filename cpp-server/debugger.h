#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <capstone/capstone.h>
#include <cstdint>
#include <string>
#include <sys/types.h>

namespace debugger {

class Debugger {
public:
    Debugger(pid_t pid, const std::string& program);
    ~Debugger();

    void run();
    std::string handle_command(const std::string& command);

    std::string set_breakpoint(const std::string& name);
    std::string set_breakpoint(uintptr_t address);
    std::string print_executing_instruction();

    // Methods to control execution
    void continue_execution();
    void step_instruction();
    void step_over();



protected:
    std::string respond(const std::string& message) {
        return message;
    }

private:
    pid_t m_pid;
    std::string m_program;
    csh m_capstone_handle;

    void wait_for_signal();
};

} // namespace debugger

#endif // DEBUGGER_H
