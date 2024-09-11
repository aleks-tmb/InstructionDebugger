#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../debugger.h"

// [gtest_prog]
//
// section .data
//     msg1 db "Hello from function 1!", 0xA    ; Message for function 1
//     len1 equ $ - msg1                        ; Length of message 1
//     msg2 db "Hello from function 2!", 0xA    ; Message for function 2
//     len2 equ $ - msg2                        ; Length of message 2

// section .text
//     global _start

// _start:
//     call function1            ; Call the first function
//     mov rax, 60               ; sys_exit system call number
//     xor rdi, rdi              ; Return 0
//     syscall

// function1:
//     mov rax, 1                ; sys_write system call number
//     mov rdi, 1                ; File descriptor (stdout)
//     mov rsi, msg1             ; Pointer to message 1
//     mov rdx, len1             ; Length of message 1
//     syscall
//     call function2
//     ret

// function2:
//     mov rax, 1                ; sys_write system call number
//     mov rdi, 1                ; File descriptor (stdout)
//     mov rsi, msg2             ; Pointer to message 2
//     mov rdx, len2             ; Length of message 2
//     syscall
//     ret

class DebuggerTest : public ::testing::Test {
protected:
  pid_t pid;
  const std::string program_name = std::string(TEST_DIR) + "/gtest_prog";

  void start_debugger_process() {
    pid = fork();
    if (pid == 0) {
      // Child process: trace itself and exec the program
      ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
      execl(program_name.c_str(), program_name.c_str(), nullptr);
    }
  }

  bool check_inst(std::string_view inst, std::string_view addr,
                  std::string_view op) {
    return inst.find(addr) != std::string::npos &&
           inst.find(op) != std::string::npos;
  }
};

TEST_F(DebuggerTest, StepOver) {
  start_debugger_process();
  debugger::Debugger dbg(pid, program_name);
  dbg.run();

  std::string respond = dbg.set_breakpoint("_start");
  EXPECT_TRUE(respond.find("Breakpoint set at address 0x0000000000401000") !=
              std::string::npos);

  dbg.continue_execution(); // call function1
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "401000", "call"));

  dbg.step_over(); // mov rax, 60
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "401005", "mov"));

  dbg.step_over(); // xor rdi, rdi
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "40100a", "xor"));

  dbg.step_over(); // syscall
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "40100d", "syscall"));
}

TEST_F(DebuggerTest, StepOut) {
  start_debugger_process();
  debugger::Debugger dbg(pid, program_name);
  dbg.run();

  std::string respond = dbg.set_breakpoint("_start");
  EXPECT_TRUE(respond.find("Breakpoint set at address 0x0000000000401000") !=
              std::string::npos);

  dbg.continue_execution(); // call function1
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "401000", "call"));

  dbg.step_instruction(); // mov rax, 1
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "40100f", "mov"));

  dbg.step_instruction(); // mov rdi, 1
  dbg.step_instruction(); // mov rsi, msg1
  dbg.step_instruction(); // mov rdx, len1
  dbg.step_instruction(); // syscall
  dbg.step_instruction(); // call function2
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "40102a", "call"));

  dbg.step_instruction(); // mov rax, 1
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "401030", "mov"));

  dbg.step_out(); // ret (function1)
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "40102f", "ret"));

  dbg.step_out(); // mov rax, 60 (_start)
  respond = dbg.print_executing_instruction();
  EXPECT_TRUE(check_inst(respond, "401005", "mov"));
}
