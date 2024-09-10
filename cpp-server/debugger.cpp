#include <cstring>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <functional>

#include "debugger.h"
#include "utils.h"

namespace debugger {

Debugger::Debugger(pid_t pid, const std::string& program) 
    : m_pid(pid), m_program(program) {
    // Initialize Capstone disassembler
    cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone_handle);
}

Debugger::~Debugger() {
    cs_close(&m_capstone_handle);
}

void Debugger::run() {
    int status;
    waitpid(m_pid, &status, 0);
    std::cerr << "Debugger started, child process stopped at exec" << std::endl;
}

std::string Debugger::handle_command(const std::string& command) {
    static std::string prev_command;
    // Use previous command if the current one is empty
    std::string_view cmd = command.empty() ? prev_command : command;
    prev_command = cmd;

    if (cmd == "b") {
        return set_breakpoint("main");
    } else if (cmd == "c") {
        continue_execution();
        return print_executing_instruction();
    } else if (cmd == "s") {
        step_instruction();
        return print_executing_instruction();
    } else {
        return "Unknown command!";
    }
}

void Debugger::continue_execution() {
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void Debugger::wait_for_signal() {
    int status;
    waitpid(m_pid, &status, 0);
    if (WIFSTOPPED(status)) {
        std::cerr <<  "signal received: " + std::to_string(WSTOPSIG(status)) << std::endl;
    }
}

std::string Debugger::set_breakpoint(unsigned long address) {
    long data = ptrace(PTRACE_PEEKTEXT, m_pid, (void*)address, nullptr);
    if (data == -1) {
        return "Failed to read memory at address " + toHex(address);
    }

    std::cout << toHex(data) << std::endl;

    long breakpointInst = (data & ~0xFF) | 0xCC;  // Inject INT 3 (0xCC)
    if (ptrace(PTRACE_POKETEXT, m_pid, (void*)address, (void*)breakpointInst) == -1) {
        return "Failed to write breakpoint at address " + toHex(address);
    } else {
        return "Breakpoint set at address " + toHex(address);
    }
}

std::string Debugger::set_breakpoint(const std::string& name) {
    std::string path = debugger::getAbsolutePath(m_program);
    uintptr_t base_addr = getBaseAddress(m_pid, path);
    if (base_addr == 0) {
        return "Failed to get base address";
    }

    uintptr_t function_offset = getFunctionOffset(path.c_str(), name.c_str());
    if (function_offset == 0) {
        return "Failed to get function offset for " + name;
    }

    // Hack to determine PIC code
    if (function_offset > base_addr) {
        base_addr = 0;
    }
    uintptr_t address = function_offset + base_addr;
    return set_breakpoint(address);
}

void Debugger::step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

std::string Debugger::print_executing_instruction() {
    // Get the current instruction pointer (RIP)
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);

    // Read the instruction at the current RIP
    uintptr_t rip = regs.rip;
    uint8_t data[16];  // Buffer to store instruction bytes
    for (size_t i = 0; i < sizeof(data); i += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKTEXT, m_pid, (void*)(rip + i), nullptr);
        memcpy(&data[i], &word, sizeof(word));
    }

    cs_insn* insn;
    std::ostringstream oss;
    // Disassemble only one instruction
    size_t count = cs_disasm(m_capstone_handle, data, sizeof(data), rip, 1, &insn);
    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << rip << ": ";
    if (count > 0) {
        // Print the address and the disassembled instruction
        oss << insn[0].mnemonic << " " << insn[0].op_str;
        cs_free(insn, count);
    } else {
        oss << "-";
    }
    return oss.str();
}
} // namespace debugger
