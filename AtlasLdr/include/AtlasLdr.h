#ifndef Atlas_Ldr_H
#define Atlas_Ldr_H

#include <winhttpapi.h>
#include <win32.h>

struct ATLAS_PARAMS {
    char* process_name;
    int   process_pid;
    char* server;
    char* port;
    char* atlasPatcher;
    char* atlasPatcher_entrypoint;
    char* dll;
    char* dll_entryPoint;
    BOOL cleanupOnFinish;
};

struct ATLASPATCHER_PARAMS {
    DWORD_PTR pDllAddr;
    DWORD_PTR pDllEntryPoint;
    DWORD_PTR pImportDirectoryRVA;
    SIZE_T importDirectorySize;
};


VOID AtlasInject(ATLAS_PARAMS atlas_params);
VOID AtlasLdr(DLL_DATA dll_data, ATLAS_UTILS* atlas_utils, ARTIFACT_DATA& artifact_data, HANDLE hRemote, char* entryPoint, BOOL patchIAT);
#endif