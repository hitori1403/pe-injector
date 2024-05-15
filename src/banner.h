#include "pebLookup.h"
#include "prototype.h"

void banner(protoLoadLibraryA _LoadLibraryA, protoGetProcAddress _GetProcAddress) {
    HMODULE User32Dll = _LoadLibraryA("User32.dll");
#pragma GCC diagnostic ignored "-Wcast-function-type"
    protoMessageBoxA _MessageBoxA = (protoMessageBoxA)_GetProcAddress(User32Dll, "MessageBoxA");
#pragma GCC diagnostic pop
    _MessageBoxA(0, "Bocchi The Rock!", "Kessoku Band", MB_OK);
}