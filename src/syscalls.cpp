#include <syscalls.h>

DWORD C_RetrieveSSN(DWORD targetFuncHash, DLL_DATA dll_data){
    std::vector<std::tuple<char*, DWORD>> syscalls = C_RetrieveSyscalls(dll_data);

    DWORD ssn = 0;
    for (const auto& tuple : syscalls) {
        if(C_HashString(ConvertCharToWideChar(std::get<0>(tuple))) == targetFuncHash){
            break;
        }
        else{
            ssn += 1;
        }
    }

    return ssn;
}

PVOID C_RetrieveSyscallAddr(SIZE_T stubAddr){
    PBYTE pStubAddr = (PBYTE)stubAddr;
    const byte syscall[] = {0x0F, 0x05};

    for(size_t i = 0; i < 23; i++){
        if(*(pStubAddr + 1) == syscall[0] && *(pStubAddr + 2) == syscall[1]){
            return (PVOID)(pStubAddr + 1);
        }

        pStubAddr++;
    }
    
    return NULL;
}

std::vector<std::tuple<char*, DWORD>> C_RetrieveSyscalls(DLL_DATA dll_data){
    std::vector<std::tuple<char*, DWORD>> syscalls; 

    PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dll_data.baseAddr + dll_data.optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pFuncNames = (PDWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfNames);
    PDWORD pFuncAddrs = (PDWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)((DWORD_PTR)dll_data.baseAddr + pExportTable->AddressOfNameOrdinals);

    for(size_t i = 0; i < pExportTable->NumberOfNames; i++){
        char *funcName = (char*)((DWORD_PTR)dll_data.baseAddr + pFuncNames[i]);

        if(strncmp(funcName, "Zw", 2) == 0){
            size_t funcAddr = (size_t)((DWORD_PTR)dll_data.baseAddr + pFuncAddrs[pOrdinals[i]]);
            syscalls.push_back(std::make_tuple(funcName, funcAddr));
        }
    }

    //lambda to sort by DWORD
    auto compareByAddr = [](const auto& firstAddr, const auto& secondAddr) {
        return std::get<1>(firstAddr) < std::get<1>(secondAddr);
    };

    std::sort(syscalls.begin(), syscalls.end(), compareByAddr);

    return syscalls;
}