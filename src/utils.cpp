#include <utils.h>

DWORD C_HashString(wchar_t* string){
    DWORD hash = 33;
    wchar_t character;

    while ((character = *string++)){
        hash = character + (hash << 6) + (hash << 16) - hash;
    }

    return hash;
}

BOOL ConvertCharToUnicode(const char* ansiString, PUNICODE_STRING pUnicodeString){
    size_t ansiLength = strlen(ansiString);

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
    size_t wAnsiStringLenght = strlen(ansiString) + 1;

    wchar_t* wAnsiString = new wchar_t[wAnsiStringLenght];
    size_t result = mbstowcs(wAnsiString, ansiString, wAnsiStringLenght);
    if(result == (size_t) - 1){
        delete [] wAnsiString;
        return NULL;
    }

    return wAnsiString;
}