#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <cstdint>
#include <string>
#include <sys/types.h>

namespace debugger {

class Debugger {
public:
    Debugger(pid_t pid, const std::string& program);

    // Main method to run the debugger
    void run();

    // Overloaded methods to set breakpoints
    void set_breakpoint(const std::string& name);
    void set_breakpoint(uintptr_t address);

    // Methods to control execution
    void continue_execution();
    void step_instruction();
    void print_executing_instruction();

protected:
    virtual void respond(const std::string& message) = 0;

private:
    pid_t m_pid;
    std::string m_program;

    // Helper methods
    void wait_for_signal();
};

} // namespace debugger

#endif // DEBUGGER_H
