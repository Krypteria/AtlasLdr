Atlas is a reflective x64 loader that has the following features:

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

![atlasldr](https://github.com/Krypteria/AtlasLdr/assets/55555187/8737996e-2da8-4025-b128-0e65d1080af0)

## Compilation

Atlas needs to be compiled using **x86_64-w64-mingw32-g++**, once you have it on your system, just execute make (or mingw32-make.exe) on the project folder

![atlascompilation](https://github.com/Krypteria/AtlasLdr/assets/55555187/db6b328f-a916-4ccc-bd14-1d4bead19d8a)

## Disclaimer
There are improvements that could be made such as modifying the way syscalls are executed with a consistent and error-proof assembly code. In the future this could be implemented.
