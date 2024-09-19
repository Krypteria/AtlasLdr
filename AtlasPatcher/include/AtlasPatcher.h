#ifndef Atlas_Patcher_H
#define Atlas_Patcher_H

#include <windows.h>
#include <winternl.h>
#include <tuple>

#define Exported __declspec(dllexport)

#define ok "[+]"
#define info "[*]"
#define err "[!]"

#define PPEB_PTR __readgsqword(0x60)

#define Sys_Ntdll 0xae5d2a33
#define Sys_LdrLoadDll 0x307a4bc5


typedef VOID (*AtlasJump)(PVOID hinstDLL, DWORD fdwReason, PVOID lpvReserved);

struct DLL_DATA {
    PVOID baseAddr;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_FILE_HEADER fileHeader;
    PIMAGE_OPTIONAL_HEADER optHeader;
    DWORD_PTR preferedAddr;
    SIZE_T imageSize;
    SIZE_T entryPoint;
};

struct ATLASPATCHER_PARAMS {
    PVOID pDllAddr;
    PVOID pDllEntryPoint;
    PVOID pImportDirectoryRVA;
    SIZE_T importDirectorySize;
};

typedef NTSTATUS(NTAPI* fnLdrLoadDll)(
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    HANDLE* ModuleHandle
);

typedef struct C_PEB_LDR_DATA{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} C_PEB_LDR_DATA, *C_PPEB_LDR_DATA;

typedef struct C_LDR_DATA_TABLE_ENTRY{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID entry_point;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    _ACTIVATION_CONTEXT * entry_pointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} C_LDR_DATA_TABLE_ENTRY, *C_PLDR_DATA_TABLE_ENTRY;


VOID PatchIAT(PVOID pDllAddr, DWORD_PTR pImportDirectoryRVA, SIZE_T importDirectorySize);

BOOL CP_LoadLibrary(char* dllName, PHANDLE pHDll, fnLdrLoadDll pLdrLoadDll);
std::pair<DLL_DATA, DWORD> CP_PrepareForwardedProc(SIZE_T funcAddr, fnLdrLoadDll pLdrLoadDll);
SIZE_T CP_GetProcAddress(DLL_DATA dll_data, DWORD targetFuncHash, WORD ordinal, fnLdrLoadDll pLdrLoadDll);
PVOID CP_GetModuleHandle(DWORD dll);
DWORD CP_HashString(wchar_t* string);

VOID RetrieveDLL_DATA(PVOID pDllAddr, DLL_DATA* dll_data);

BOOL ConvertCharToUnicode(const char* ansiString, PUNICODE_STRING pUnicodeString);
wchar_t* ConvertCharToWideChar(const char* ansiString);
SIZE_T StrLength(char * str);

#endif