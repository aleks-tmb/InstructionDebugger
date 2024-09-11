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

    // Main method to run the debugger
    void run();

    std::string set_breakpoint(const std::string& name);
    std::string set_breakpoint(uintptr_t address);
    std::string print_executing_instruction();

    // Methods to control execution
    void continue_execution();
    void step_instruction();
    void step_over();



protected:
    virtual void respond(const std::string& message) = 0;

private:
    pid_t m_pid;
    std::string m_program;
    csh m_capstone_handle;

    // Helper methods
    void wait_for_signal();
};

} // namespace debugger

#endif // DEBUGGER_H
