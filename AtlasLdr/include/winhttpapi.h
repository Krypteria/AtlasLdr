#ifndef Atlas_WinHTTP_H
#define Atlas_WinHTTP_H

#include <utils.h>
#include <winhttp.h>

#define ok "[+]"
#define info "[*]"
#define err "[!]"

char* ObtainRock(char* server, DWORD port, char* dll);
VOID ErrorCallbackHTTP(const char* msg, DWORD status, const std::vector<HANDLE> openHandles);

#endif