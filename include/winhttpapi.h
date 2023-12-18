#ifndef Atlas_WinHTTP_H
#define Atlas_WinHTTP_H

#include <windows.h>
#include <stdio.h>
#include <winhttp.h>
#include <vector>

#define ok "[+]"
#define info "[*]"
#define err "[!]"

char* ObtainRock(LPCWSTR server, DWORD port, LPCWSTR dll);
void ErrorCallback(const char* msg, DWORD status, const std::vector<HANDLE> openHandles);

#endif