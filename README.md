Atlas is a fileless reflective x64 loader that has the following features:

## Features

- Retrieve of DLL and PE from a remote server
- Manual Mapping on a remote process
- Position independent code
- Use of indirect Syscalls
  - ZwAllocateVirtualMemory
  - ZwProtectVirtualMemory
  - ZwQuerySystemInformation
  - ZwFreeVirtualMemory
  - ZwCreateThreadEx
- Single stub for all Syscalls
  - Dynamic SSN retrieve
  - Dynamic Syscall address resolution
- Atlas also uses
  - LdrLoadDll
  - NtWriteVirtualMemory
- Custom implementations of
  - GetProcAddress
  - GetModuleHandle
- API hashing
- Cleanup on error
- Variable EntryPoint

## Usage

![atlasldr](https://github.com/Krypteria/AtlasLdR/assets/55555187/b7fecd90-10b3-4081-80f3-d21e62524cff)

## Compilation

Atlas needs to be compiled using **x86_64-w64-mingw32-g++**, once you have it on your system, just execute make (or mingw32-make.exe) on the project folder

![atlas compilation](https://github.com/Krypteria/AtlasLdR/assets/55555187/be7d48a4-56c6-4d55-bf3a-8eca87d09511)

