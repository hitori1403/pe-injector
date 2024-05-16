#include <Windows.h>

#include "antiDebug/beingDebugged.h"
#include "antiVM/generic.h"
#include "prototype.h"

BOOL isSuspicious() {
    if (isDebuggerPresentPEB()) {
        return TRUE;
    }
    if (cpuidIsHypvervisor()) {
        return TRUE;
    }
    return FALSE;
}