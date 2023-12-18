#ifndef Atlas_Ldr_H
#define Atlas_Ldr_H

#include <win32.h>

void AtlasInject(PVOID pDllAddr, wchar_t* target, char* entryPoint);
PVOID AtlasLdr(PVOID pDllAddr, HANDLE hRemote, char* entryPoint, ATLAS_UTILS* atlas_utils, TARGET_DATA* target_data);

#endif