#include <capstone/capstone.h>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <iostream>

#include "debugger.h"
#include "utils.h"

namespace debugger {

Debugger::Debugger(pid_t pid, const std::string& program)
    : m_pid(pid), m_program(program) {}

void Debugger::run() {
    int status;
    waitpid(m_pid, &status, 0);
    respond("Debugger started, child process stopped at exec.");

    while (true) {
        respond("Debugger: waiting for user input...");
        std::string command;
        std::cin >> command;

        if (command == "c") {
            continue_execution();
        } else if (command == "b") {
            set_breakpoint("main");
        } else if (command == "s") {
            step_instruction();
            print_executing_instruction();
        } else if (command == "e") {
            break;
        }
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
        respond("Debugger: stopped, signal " + std::to_string(WSTOPSIG(status)));
    }
}

void Debugger::set_breakpoint(unsigned long address) {
    long data = ptrace(PTRACE_PEEKTEXT, m_pid, (void*)address, nullptr);
    if (data == -1) {
        respond("Failed to read memory at address " + toHex(address));
        return;
    }

    std::cout << toHex(data) << std::endl;

    long breakpointInst = (data & ~0xFF) | 0xCC;  // Inject INT 3 (0xCC)
    if (ptrace(PTRACE_POKETEXT, m_pid, (void*)address, (void*)breakpointInst) == -1) {
        respond("Failed to write breakpoint at address " + toHex(address));
    } else {
        respond("Debugger: Breakpoint set at address " + toHex(address));
    }
}

void Debugger::set_breakpoint(const std::string& name) {
    uintptr_t base_addr = getBaseAddress(m_pid, m_program);
    if (base_addr == 0) {
        respond("Failed to get base address");
        return;
    }
    respond("Base address: " + toHex(base_addr));

    uintptr_t function_offset = getFunctionOffset(m_program.c_str(), name.c_str());
    if (function_offset == 0) {
        respond("Failed to get function offset for " + name);
        return;
    }
    respond("Function offset for " + name + ": " + toHex(function_offset));

    uintptr_t address = function_offset + base_addr;
    set_breakpoint(address);
}

void Debugger::step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void Debugger::print_executing_instruction() {
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

    // Initialize Capstone disassembler
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        respond("Failed to initialize Capstone");
        return;
    }

    // Disassemble only one instruction
    count = cs_disasm(handle, data, sizeof(data), rip, 1, &insn);
    if (count > 0) {
        // Print only the first disassembled instruction
        respond("Executing instruction: " + std::string(insn[0].mnemonic) + " " + std::string(insn[0].op_str));
        cs_free(insn, count);
    } else {
        respond("Failed to disassemble instruction");
    }

    cs_close(&handle);
}

} // namespace debugger
