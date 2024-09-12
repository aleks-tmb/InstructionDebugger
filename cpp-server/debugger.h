#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <capstone/capstone.h>
#include <cstdint>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace debugger {

class Debugger {
public:
    Debugger(pid_t pid, const std::string& program);
    ~Debugger();
    void run();
    // Handle input command and give response
    std::string handle_command(const std::string& command);
    // Set a breakpoint at entry to function
    std::string set_breakpoint(const std::string& name);
    // Set a breakpoint at address
    std::string set_breakpoint(uintptr_t address);
    // Disassemble an instruction
    std::string print_executing_instruction();
    // Continue the process
    void continue_execution();
    // Execute one instruction
    void step_instruction();
    // Jump after a call
    void step_over();
    // Exit current function and jump to a caller
    void step_out();
    // Print registers value
    std::string show_registers_state() const;

  private:
    pid_t m_pid;
    std::string m_program;
    csh m_capstone_handle;
    // Set of users breakpoints: address -> original instruction
    std::unordered_map<uintptr_t, long> m_breakpoints;
    // Temporary breakpoint for step over/out
    uintptr_t temp_breakpoint = 0;

    // Handle child proccess signal
    void wait_for_signal();
    // Change RIP register value
    void decrement_rip() const;
    // Return RIP register value
    uintptr_t get_rip() const;
    // Read instuction at RIP register
    std::vector<uint8_t> read_instruction_at_rip(uintptr_t rip) const;
    // Logging
    void log(std::string_view message) const {}
};

} // namespace debugger

#endif // DEBUGGER_H
