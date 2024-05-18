#pragma once

#include <Windows.h>

typedef HMODULE(WINAPI *protoLoadLibraryA)(LPCSTR lpLibFileName);
typedef DWORD(WINAPI *protoGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef FARPROC(WINAPI *protoGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef int(WINAPI *protoMessageBoxA)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);
typedef HANDLE(WINAPI *protoCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                         DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
// typedef LPVOID(WINAPI *protoHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
// typedef HANDLE(WINAPI *protoGetProcessHeap)();
// typedef BOOL(WINAPI *protoReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
//                                     LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
// typedef BOOL(WINAPI *protoWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
//                                      LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef BOOL(WINAPI *protoCloseHandle)(HANDLE hObject);
// typedef BOOL(WINAPI *protoHeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
typedef HANDLE(WINAPI *protoCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh,
                                                DWORD dwMaximumSizeLow, LPCSTR lpName);
typedef LPVOID(WINAPI *protoMapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
                                           SIZE_T dwNumberOfBytesToMap);
typedef BOOL(WINAPI *protoUnmapViewOfFile)(LPCVOID lpBaseAddress);
// typedef HMODULE(WINAPI *protoGetModuleHandleA)(LPCSTR lpModuleName);
typedef DWORD(WINAPI *protoGetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
// typedef BOOL(WINAPI *protoCopyFileA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
typedef void(WINAPI *protoRtlCopyMemory)(void *Destination, const VOID *Source, size_t Length);
typedef HANDLE(WINAPI *protoFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *protoFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *protoFindClose)(HANDLE hFindFile);

// typedef LSTATUS(WINAPI *protoRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
// typedef LSTATUS(WINAPI *protoRegCloseKey)(HKEY hKey);
// typedef DWORD(WINAPI *protoGetFileAttributesA)(LPCSTR lpFileName);

typedef BOOLEAN(WINAPI *protoGetPwrCapabilities)(PSYSTEM_POWER_CAPABILITIES lpspc);