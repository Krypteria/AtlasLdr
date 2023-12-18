section .text

    global SysInvoke
    global SysPrepare

    SysPrepare:
        xor r11, r11
        xor r12, r12
        mov r11d, ecx ; STDCALL convention
        mov r12, rdx  ; STDCALL convention
        ret

    SysInvoke:
        mov r10, rcx
        mov eax, r11d ; lower 32 bits of r11
        jmp QWORD r12 ; jump to syscall in ntdll
        ret