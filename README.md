Atlas is a reflective x64 loader that has the following features:

## Features

- Retrieve of DLL and PE from a remote server
- Manual Mapping on a remote process
- Erase of the DOS Header and NTHeader Magic bytes
- Position independent code
- Use of indirect Syscalls
  - ZwOpenProcess
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
- Optional cleanup on finish
- Variable EntryPoint

## Usage

Atlas requires the following parameters to work properly:

```
Usage: atlas_x64.exe [Process name / PID] [Cleanup] [Server] [Port] [AtlasPatcher DLL] [DLL/PE to inject] <Entrypoint>
```

| Parameter        | Description                                                                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Name / PID       | The name or PID of the target process                                                                                                          |
| Cleanup          | Indicate whether you want to remove the injected DLLs from the target process upon completion (Cleanup supports 1 or 0 as values)              |
| Server           | The IP address of the remote server where you have the DLLs                                                                                    |
| Port             | The port used by your server                                                                                                                   |
| AtlasPatcher DLL | The name of the AtlasPatcher DLL (by default atlas_patcher.dll) hosted on your server (you can find the DLL under /AtlasLdr/bin once compiled) |
| DLL/PE to inject | The name of the DLL or PE you want to inject, hosted on your server                                                                            |
| Entrypoint       | An optional argument; the name of the exported function you want to use as entrypoint when the DLL is injected                                 |

![AtlasLdr](https://github.com/Krypteria/AtlasLdr/assets/55555187/4cefd0b6-0ee9-4663-ace6-250baa6671a6)

## The Atlas approach

The conventional approach to a loader usually involves having an injector responsible for injecting a DLL containing the loader into the remote process we are targeting. Once injected, execution is passed to the loader, which is responsible for mapping the malicious DLL. In contrast, Atlas takes a slightly different approach by performing the entire mapping process within its own context, except for the Import Address Table (IAT) patching, which is deferred. 

Once the malicious DLL has been mapped into the Atlas context, it is copied into memory previously reserved in the remote process. At this point, the malicious DLL is mapped into the remote process, but the IAT has not been patched. To fix this, AtlasLdr injects a DLL (atlas_patcher.dll) into the malicious process with minimal dependencies, which takes care of patching the IAT of the malicious DLL and then transfers the execution context to it.

This approach helps reduce the size and complexity of the loader DLL to be injected into the remote process and minimises the chances of the injector being detected, as we can load the DLL with the loader itself.

## Compilation

Atlas needs to be compiled using **x86_64-w64-mingw32-g++**, once you have it on your system, just execute make (or mingw32-make.exe) on the project folder

![AtlasCompilation](https://github.com/Krypteria/AtlasLdr/assets/55555187/d1010231-aa0e-4385-b203-88788131c661)
