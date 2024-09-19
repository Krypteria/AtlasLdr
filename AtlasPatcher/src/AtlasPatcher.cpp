#include <AtlasPatcher.h>


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
    switch(fdwReason){ 
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE; 
}

extern "C" Exported VOID AtlasPatcher(PVOID lpParameter){
    DLL_DATA dll_data;
    ATLASPATCHER_PARAMS* atlasPatcher_params;
    atlasPatcher_params = (ATLASPATCHER_PARAMS*)lpParameter;

    PatchIAT(atlasPatcher_params->pDllAddr, (DWORD_PTR)atlasPatcher_params->pImportDirectoryRVA, atlasPatcher_params->importDirectorySize);

    AtlasJump fnAtlasExecution = (AtlasJump)atlasPatcher_params->pDllEntryPoint;
    fnAtlasExecution(atlasPatcher_params->pDllAddr, DLL_PROCESS_ATTACH, NULL);
}

VOID PatchIAT(PVOID pDllAddr, DWORD_PTR pImportDirectoryRVA, SIZE_T importDirectorySize){
    if(importDirectorySize){
        DLL_DATA ntdll_data;

        PVOID pNtpDllAddress = CP_GetModuleHandle(Sys_Ntdll);
        RetrieveDLL_DATA(pNtpDllAddress, &ntdll_data);

        fnLdrLoadDll pLdrLoadDll = (fnLdrLoadDll)CP_GetProcAddress(ntdll_data, Sys_LdrLoadDll, NULL, NULL);

        if(pLdrLoadDll == NULL){
            exit(EXIT_FAILURE);
        }

        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pDllAddr + pImportDirectoryRVA);

        HANDLE hDll;
        DLL_DATA iat_entry_dll_data;
        SIZE_T procAddr;

        while(pImportDescriptor->Name){
            char * dllName = (char*)((DWORD_PTR)pDllAddr + pImportDescriptor->Name);
            if(!CP_LoadLibrary(dllName, &hDll, pLdrLoadDll)){
                exit(EXIT_FAILURE);
            }
            
            RetrieveDLL_DATA((PVOID)hDll, &iat_entry_dll_data);

            PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)pDllAddr + pImportDescriptor->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)pDllAddr + pImportDescriptor->OriginalFirstThunk);

            while(pOriginalFirstThunk->u1.AddressOfData){
                if(IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)){
                    procAddr = CP_GetProcAddress(iat_entry_dll_data, NULL, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal), pLdrLoadDll);
                    if(procAddr != -1){
                        pIAT->u1.Function = procAddr;
                    }
                    else{
                        exit(EXIT_FAILURE);
                    }
                }
                else{
                    PIMAGE_IMPORT_BY_NAME pFunction = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pDllAddr + pOriginalFirstThunk->u1.AddressOfData);
                    procAddr = CP_GetProcAddress(iat_entry_dll_data, CP_HashString(ConvertCharToWideChar(pFunction->Name)), NULL, pLdrLoadDll);

                    if(procAddr != -1){
                        pIAT->u1.Function = procAddr;
                    }
                    else{
                        exit(EXIT_FAILURE);
                    }
                }
                pOriginalFirstThunk++;
                pIAT++;
            }

            pImportDescriptor++;    
        }
    }
}

// Aux functions

BOOL CP_LoadLibrary(char* dllName, PHANDLE pHDll, fnLdrLoadDll pLdrLoadDll){
    UNICODE_STRING usDllName;
    if(!ConvertCharToUnicode(dllName, &usDllName)){
        return FALSE;
    } 

    NTSTATUS status = pLdrLoadDll(NULL, 0, &usDllName, pHDll);
    if(!NT_SUCCESS(status)){
        return FALSE;
    }

    return TRUE;
}

std::pair<DLL_DATA, DWORD> CP_PrepareForwardedProc(SIZE_T funcAddr, fnLdrLoadDll pLdrLoadDll){
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

    pModule = CP_GetModuleHandle(CP_HashString(ConvertCharToWideChar(forwardedDLL)));

    if(pModule == NULL){
        if(!CP_LoadLibrary(forwardedDLL, &hDll, pLdrLoadDll)){
            exit(EXIT_FAILURE);
        }

        pModule = (PVOID) hDll;
    }
    
    
    DLL_DATA dll_forward_data;
    RetrieveDLL_DATA(pModule, &dll_forward_data); 

    return std::make_pair(dll_forward_data, CP_HashString(ConvertCharToWideChar(forwardedFunction)));
}

SIZE_T CP_GetProcAddress(DLL_DATA dll_data, DWORD targetFuncHash, WORD ordinal, fnLdrLoadDll pLdrLoadDll){ 
    IMAGE_DATA_DIRECTORY pExportedDir = dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dll_data.baseAddr + pExportedDir.VirtualAddress);

    PDWORD pFuncNames = (PDWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfNames);
    PDWORD pFuncAddrs = (PDWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfNameOrdinals);

    for(size_t i = 0; i < pExportTable->NumberOfNames; i++){
        char *funcName = (char*)((DWORD_PTR)dll_data.baseAddr + pFuncNames[i]);
        WORD funcOrdinal = (WORD)(pExportTable->Base + (DWORD_PTR)dll_data.baseAddr + pOrdinals[i]);

        if(ordinal != NULL){
            if(funcOrdinal == ordinal){
                size_t funcAddr = (size_t)((DWORD_PTR)dll_data.baseAddr + pFuncAddrs[pOrdinals[i]]);
                if(funcAddr >= (DWORD_PTR) pExportTable && funcAddr < ((SIZE_T)pExportTable + pExportedDir.Size)){
                    std::pair<DLL_DATA, DWORD> forwardedFunc = CP_PrepareForwardedProc(funcAddr, pLdrLoadDll);
                    funcAddr = CP_GetProcAddress(forwardedFunc.first, forwardedFunc.second, NULL, pLdrLoadDll);
                }

                return funcAddr;  
            }
        }
        else{
            wchar_t* wfuncName = ConvertCharToWideChar(funcName);
            if(wfuncName != NULL && CP_HashString(wfuncName) == targetFuncHash){
                size_t funcAddr = (size_t)((DWORD_PTR)dll_data.baseAddr + pFuncAddrs[pOrdinals[i]]);

                if(funcAddr >= (DWORD_PTR) pExportTable && funcAddr < ((SIZE_T)pExportTable + pExportedDir.Size)){
                    std::pair<DLL_DATA, DWORD> forwardedFunc = CP_PrepareForwardedProc(funcAddr, pLdrLoadDll);
                    funcAddr = CP_GetProcAddress(forwardedFunc.first, forwardedFunc.second, NULL, pLdrLoadDll);
                }
                
                return funcAddr; 
            }
        }
    }

    return -1;
}


PVOID CP_GetModuleHandle(DWORD dll){
    wchar_t* wBaseDll;

    C_PPEB_LDR_DATA pLdrData = (C_PPEB_LDR_DATA)((PPEB)PPEB_PTR)->Ldr;
    C_PLDR_DATA_TABLE_ENTRY pLdrEntry = (C_PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink;

    while(pLdrEntry->DllBase != NULL){
        wBaseDll = new wchar_t[pLdrEntry->BaseDllName.Length + 1];

        wcsncpy(wBaseDll, pLdrEntry->BaseDllName.Buffer, pLdrEntry->BaseDllName.Length + 1);
        if(CP_HashString(wBaseDll) == dll){
            delete [] wBaseDll;
            return pLdrEntry->DllBase;
        }

        pLdrEntry = (C_PLDR_DATA_TABLE_ENTRY)pLdrEntry->InLoadOrderLinks.Flink;
    }

    delete [] wBaseDll;
    return NULL;
}

VOID RetrieveDLL_DATA(PVOID pDllAddr, DLL_DATA* dll_data){
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;

    pDosHeader = (PIMAGE_DOS_HEADER)pDllAddr;

    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
        exit(EXIT_FAILURE);
    }

    pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDllAddr + pDosHeader->e_lfanew);
    if(pNtHeader->Signature != IMAGE_NT_SIGNATURE){
        exit(EXIT_FAILURE);
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


//Str manipulation

DWORD CP_HashString(wchar_t* string){
    DWORD hash = 33;
    wchar_t character;

    while ((character = *string++)){
        if(character >= L'A' && character <= L'Z'){
            character += (int)(L'a' - L'A');
        }
        
        hash = character + (hash << 6) + (hash << 16) - hash;
    }

    return hash;
}

SIZE_T StrLength(char * str){
    SIZE_T index = 0;
    while(str[index] != '\0'){
        index++;
    }

    return index;
}

BOOL ConvertCharToUnicode(const char* ansiString, PUNICODE_STRING pUnicodeString){
    SIZE_T ansiLength = strlen(ansiString);

    pUnicodeString->Buffer = new WCHAR[ansiLength + 1];
    if (pUnicodeString->Buffer == nullptr) {
        return FALSE;
    }

    pUnicodeString->MaximumLength = static_cast<USHORT>((ansiLength + 1) * sizeof(WCHAR));
    pUnicodeString->Length = static_cast<USHORT>(ansiLength * sizeof(WCHAR));

    MultiByteToWideChar(CP_ACP, 0, ansiString, -1, pUnicodeString->Buffer, static_cast<int>(ansiLength + 1));

    pUnicodeString->Buffer[ansiLength] = L'\0';

    return TRUE;
}

wchar_t* ConvertCharToWideChar(const char* ansiString){
    SIZE_T wAnsiStringLenght = strlen(ansiString) + 1;

    wchar_t* wAnsiString = new wchar_t[wAnsiStringLenght];
    SIZE_T result = mbstowcs(wAnsiString, ansiString, wAnsiStringLenght);
    if(result == (SIZE_T) - 1){
        delete [] wAnsiString;
        return NULL;
    }

    return wAnsiString;
}