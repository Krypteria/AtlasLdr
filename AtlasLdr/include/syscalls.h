#ifndef Atlas_Syscalls_H
#define Atlas_Syscalls_H

#include <utils.h>

#define Sys_Ntdll 0xae5d2a33

#define Sys_LdrLoadDll 0x307a4bc5
#define Sys_NtWriteVirtualMemory 0x5d869814

#define Sys_ZwOpenProcess 0xf686cdc7
#define Sys_ZwAllocateVirtualMemory 0x38c08e31
#define Sys_ZwProtectVirtualMemory 0xd8355abb
#define Sys_ZwQuerySystemInformation 0x8056f0f3
#define Sys_ZwFreeVirtualMemory 0x68564aa2
#define Sys_ZwCreateThreadEx 0xb3f31797

struct SYSCALL_INFO{
    DWORD ssn;
    PVOID stubAddr;
};

struct ATLAS_SYSCALLS {
    SYSCALL_INFO NtOpenProcess;
    SYSCALL_INFO NtAllocateVirtualMemory;
    SYSCALL_INFO NtProtectVirtualMemory;
    SYSCALL_INFO NtQuerySystemInformation;
    SYSCALL_INFO NtFreeVirtualMemory;
    SYSCALL_INFO NtCreateThreadEx;
};


std::vector<std::tuple<char*, DWORD>> C_RetrieveSyscalls(DLL_DATA dll_data);
DWORD C_RetrieveSSN(DWORD targetFuncHash, DLL_DATA dll_data);
PVOID C_RetrieveSyscallAddr(SIZE_T stubAddr);

#endif