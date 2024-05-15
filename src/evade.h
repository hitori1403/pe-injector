#include <Windows.h>

#include "antiDebug/beingDebugged.h"
#include "antiVM/VBox.h"
#include "antiVM/VMWare.h"
#include "prototype.h"

BOOL isFuckedUp(protoLoadLibraryA _LoadLibraryA, protoGetProcAddress _GetProcAddress) {
    if (isDebuggerPresentPEB()) {
        return TRUE;
    }
    return FALSE;
}