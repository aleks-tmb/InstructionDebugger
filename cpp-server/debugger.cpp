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

    if (cmd.rfind("break ", 0) == 0) {
      std::string arg = std::string(cmd.substr(6));

      // Check if the argument is an address or a function name
      if (arg.find("0x") == 0) {
        // Argument is an address
        uintptr_t address;
        std::stringstream ss(arg);
        ss >> std::hex >> address;
        return set_breakpoint(address);
      } else {
        // Argument is a function name
        return set_breakpoint(arg);
      }
    } else if (cmd == "c" || cmd == "continue") {
      continue_execution();
      return print_executing_instruction();
    } else if (cmd == "s" || cmd == "step") {
      step_instruction();
      return print_executing_instruction();
    } else if (cmd == "step over") {
      step_over();
      return print_executing_instruction();
    } else if (cmd == "step out") {
      step_out();
      return print_executing_instruction();
    } else if (cmd == "state") {
      return show_registers_state();
    } else {
      return "Unknown command!";
    }
}

void Debugger::decrement_rip() {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs) == -1) {
    std::cerr << "Failed to get registers" << std::endl;
    return;
  }
  regs.rip--;
  // Set the updated registers
  if (ptrace(PTRACE_SETREGS, m_pid, nullptr, &regs) == -1) {
    std::cerr << "Failed to set registers" << std::endl;
    return;
  }
}

void Debugger::continue_execution() {
  step_instruction();
  ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
  wait_for_signal();
}

void Debugger::wait_for_signal() {
    int status;
    waitpid(m_pid, &status, 0);

    if (WIFSTOPPED(status)) {
      int signal = WSTOPSIG(status);
      // Handle breakpoint signal
      if (signal == SIGTRAP) {
        uintptr_t orig_address = get_rip() - 1;
        auto it = m_breakpoints.find(orig_address);
        if (it != m_breakpoints.end()) {
          long original = it->second;
          ptrace(PTRACE_POKETEXT, m_pid, (void *)orig_address,
                 (void *)original);
          decrement_rip();
          std::cout << "Restore original instruction at" << toHex(orig_address)
                    << std::endl;
          if (temp_breakpoint == orig_address) {
            m_breakpoints.erase(temp_breakpoint);
            temp_breakpoint = 0;
            std::cout << "Remove temp breakpoint" << std::endl;
          }
          return;
        }
      }
      std::cout << "Signal received: " + std::to_string(signal) << std::endl;
    }
}

std::string Debugger::set_breakpoint(unsigned long address) {
  long orig_inst = ptrace(PTRACE_PEEKTEXT, m_pid, (void *)address, nullptr);
  if (orig_inst == -1) {
    std::cerr << "Failed to read memory at address " + toHex(address);
    std::cerr << ". Error: " << strerror(errno) << std::endl;
    return "Failed to set breakpoint";
  }

  m_breakpoints[address] = orig_inst;
  long breakpointInst = (orig_inst & ~0xFF) | 0xCC; // Inject INT 3 (0xCC)
  if (ptrace(PTRACE_POKETEXT, m_pid, (void *)address, (void *)breakpointInst) ==
      -1) {
    std::cerr << "Failed to write breakpoint at address " + toHex(address);
    return "Failed to set breakpoint";
    }

    std::cout << "Breakpoint set at address " + toHex(address) << std::endl;
    return "Breakpoint set at address " + toHex(address);
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

// Execute current instruction and restore breakpoint if it was set on the
// instruction
void Debugger::step_instruction() {
  uintptr_t addr = get_rip();
  ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
  wait_for_signal();

  auto it = m_breakpoints.find(addr);
  if (it != m_breakpoints.end()) {
    set_breakpoint(addr);
  }
}

std::vector<uint8_t> Debugger::read_instruction_at_rip(uintptr_t rip) const {
    size_t size = 16; // Read 16 bytes for rip
    std::vector<uint8_t> data(size);
    
    for (size_t offset = 0; offset < size;)  {
        size_t chunk_size = std::min(size - offset, sizeof(long));

        long word = ptrace(PTRACE_PEEKTEXT, m_pid, (void*)(rip + offset), nullptr);
        std::memcpy(data.data() + offset, &word, chunk_size);
        
        offset += chunk_size;
    }    
    return data;
}

uintptr_t Debugger::get_rip() const {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
    return regs.rip;   
}

std::string Debugger::print_executing_instruction() {
    uintptr_t rip = get_rip();
    std::vector<uint8_t> data = read_instruction_at_rip(rip);
    // Disassemble only one instruction
    cs_insn* insn;
    size_t count = cs_disasm(m_capstone_handle, data.data(), data.size(), rip, 1, &insn);

    std::ostringstream oss;
    oss << toHex(rip) << ": ";
    if (count > 0) {
        // Print the address and the disassembled instruction
        oss << insn[0].mnemonic << " " << insn[0].op_str;
        cs_free(insn, count);
    } else {
        oss << "-";
    }
    return oss.str();
}

void Debugger::step_over() {
    uintptr_t rip = get_rip();
    std::vector<uint8_t> data = read_instruction_at_rip(rip);
    // Disassemble only one instruction
    cs_insn* insn;
    size_t count = cs_disasm(m_capstone_handle, data.data(), data.size(), rip, 1, &insn);

    if (count > 0 && insn[0].id == X86_INS_CALL) {
        // If it's a function call, set a breakpoint after the call
        uintptr_t after_call = rip + insn[0].size;
        temp_breakpoint = after_call;
        set_breakpoint(after_call);
        continue_execution();
    } else {
        step_instruction();  
    }   
}

void Debugger::step_out() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
    uintptr_t return_address = ptrace(PTRACE_PEEKTEXT, m_pid, regs.rsp, nullptr);
    std::cout << "Return address: " << toHex(return_address) << std::endl;
    if (return_address == (uintptr_t)-1 || return_address == 0) {
        std::cout << "Failed to read return address from stack" << std::endl;
        return;
    }
    temp_breakpoint = return_address;
    set_breakpoint(return_address);
    continue_execution(); 
}

std::string Debugger::show_registers_state() const {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs) == -1) {
    return "Failed to get register state.";
  }

  std::ostringstream oss;
  oss << "RIP: " << toHex(regs.rip) << std::endl
      << "RAX: " << toHex(regs.rax) << std::endl
      << "RBX: " << toHex(regs.rbx) << std::endl
      << "RCX: " << toHex(regs.rcx) << std::endl
      << "RDX: " << toHex(regs.rdx) << std::endl
      << "RSI: " << toHex(regs.rsi) << std::endl
      << "RDI: " << toHex(regs.rdi) << std::endl
      << "RSP: " << toHex(regs.rsp) << std::endl
      << "RBP: " << toHex(regs.rbp) << std::endl
      << "R8:  " << toHex(regs.r8) << std::endl
      << "R9:  " << toHex(regs.r9) << std::endl
      << "R10: " << toHex(regs.r10) << std::endl
      << "R11: " << toHex(regs.r11) << std::endl
      << "R12: " << toHex(regs.r12) << std::endl
      << "R13: " << toHex(regs.r13) << std::endl
      << "R14: " << toHex(regs.r14) << std::endl
      << "R15: " << toHex(regs.r15) << std::endl;

  return oss.str();
}

} // namespace debugger
