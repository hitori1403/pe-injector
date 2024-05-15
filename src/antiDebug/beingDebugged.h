#include "../pebLookup.h"

BOOL isDebuggerPresentPEB() {
#if defined(_WIN64)
#pragma GCC diagnostic ignored "-Warray-bounds"
    PPEB peb = (PPEB)__readgsqword(0x60);
#pragma GCC diagnostic pop
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif

    return peb->BeingDebugged == TRUE;
}
