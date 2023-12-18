#ifndef Atlas_Syscalls_H
#define Atlas_Syscalls_H

#include <utils.h>

#define Sys_Ntdll 0xae5d2a33

#define Sys_LdrLoadDll 0x308243a5
#define Sys_NtWriteVirtualMemory 0xfc5bb054

#define Sys_ZwAllocateVirtualMemory 0xd02815f1
#define Sys_ZwProtectVirtualMemory 0x721e52fb
#define Sys_ZwQuerySystemInformation 0xa5ea60f3
#define Sys_ZwFreeVirtualMemory 0xb3e59262
#define Sys_ZwCreateThreadEx 0x4d09f817

struct SYSCALL_INFO{
    DWORD ssn;
    PVOID stubAddr;
};

struct ATLAS_SYSCALLS {
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