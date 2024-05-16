#include <Windows.h>

#include "prototype.h"

int getFileAlignment(protoCreateFileMappingA _CreateFileMappingA, protoMapViewOfFile _MapViewOfFile, protoUnmapViewOfFile _UnmapViewOfFile,
                     protoCloseHandle _CloseHandle, HANDLE file) {
    HANDLE fileMapping = _CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID baseAddress = _MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER dosHeader = baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = baseAddress + dosHeader->e_lfanew;

    int fileAlignment = ntHeaders->OptionalHeader.FileAlignment;

    _UnmapViewOfFile(baseAddress);
    _CloseHandle(fileMapping);

    return fileAlignment;
}

ULONG_PTR RVA2RA(LPVOID baseAddress, int RVA) {
    PIMAGE_DOS_HEADER dosHeader = baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = baseAddress + dosHeader->e_lfanew;
    LPVOID sectionHeader = ntHeaders + sizeof(IMAGE_NT_HEADERS);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER currentSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)sectionHeader + i * sizeof(IMAGE_SECTION_HEADER));

        int VA = currentSection->VirtualAddress;
        int VS = currentSection->Misc.VirtualSize;
        if (VA <= RVA && RVA <= VA + VS) {
            return (ULONG_PTR)baseAddress + RVA - VA + currentSection->PointerToRawData;
        }
    }

    return -1;
}

// BOOL isRegKeyExists(protoRegOpenKeyExA _RegOpenKeyExA, protoRegCloseKey _RegCloseKey, HKEY hKey, LPCSTR lpSubKey) {
//     HKEY hkResult = NULL;
//     LPCSTR lpData[1024] = {0};
//     DWORD cbData = MAX_PATH;

//     if (_RegOpenKeyExA(hKey, lpSubKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS) {
//         _RegCloseKey(hkResult);
//         return TRUE;
//     }

//     return FALSE;
// }

// BOOL isFileExists(protoGetFileAttributesA _GetFileAttributesA, LPCSTR szPath) {
//     DWORD dwAttrib = _GetFileAttributesA(szPath);
//     return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
// }

// BOOL isDirectoryExists(protoGetFileAttributesA _GetFileAttributesA, LPCSTR szPath) {
//     DWORD dwAttrib = _GetFileAttributesA(szPath);
//     return (dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
// }