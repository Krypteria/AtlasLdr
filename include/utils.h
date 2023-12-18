
#ifndef Atlas_Utils_H
#define Atlas_Utils_H

#include <windows.h>

#include <winternl.h>
#include <stdio.h>
#include <vector>
#include <tuple>
#include <algorithm>

#define ok "[+]"
#define info "[*]"
#define err "[!]"

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

struct TARGET_DATA{
    HANDLE hRemote;
    PVOID pTargetAddr;
    SIZE_T imageSize;
};

DWORD C_HashString(wchar_t* string);
BOOL ConvertCharToUnicode(const char* ansiString, PUNICODE_STRING pUnicodeString);
wchar_t* ConvertCharToWideChar(const char* ansiString);

#endif