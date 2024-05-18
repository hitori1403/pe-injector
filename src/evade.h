#include <Windows.h>

#include "antiDebug/beingDebugged.h"
#include "antiVM/generic.h"
#include "prototype.h"

BOOL isSuspicious(protoLoadLibraryA _LoadLibraryA, protoGetProcAddress _GetProcAddress) {
    if (isDebuggerPresentPEB()) {
        return TRUE;
    }

    if (cpuidIsHypvervisor()) {
        return TRUE;
    }
    
    if (powerCapabilities(_LoadLibraryA, _GetProcAddress)) {
        return TRUE;
    }

    return FALSE;
}