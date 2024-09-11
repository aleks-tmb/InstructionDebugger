; nasm -f elf64 gtest_prog.s -o gtest_prog.o
; ld gtest_prog.o -o gtest_prog
;
section .data
    msg1 db "Hello from function 1!", 0xA    ; Message for function 1
    len1 equ $ - msg1                        ; Length of message 1

    msg2 db "Hello from function 2!", 0xA    ; Message for function 2
    len2 equ $ - msg2                        ; Length of message 2

section .text
    global _start

_start:
    call function1            ; Call the first function
    mov rax, 60               ; sys_exit system call number
    xor rdi, rdi              ; Return 0
    syscall

function1:
    mov rax, 1                ; sys_write system call number
    mov rdi, 1                ; File descriptor (stdout)
    mov rsi, msg1             ; Pointer to message 1
    mov rdx, len1             ; Length of message 1
    syscall
    call function2
    ret

function2:
    mov rax, 1                ; sys_write system call number
    mov rdi, 1                ; File descriptor (stdout)
    mov rsi, msg2             ; Pointer to message 2
    mov rdx, len2             ; Length of message 2
    syscall
    ret
