#include <Windows.h>

#include "../prototype.h"
#include "../utils.h"

static inline void __cpuidex(int info[4], int ax, int cx) {
    __asm__("cpuid" : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3]) : "a"(ax), "c"(cx));
}
static inline void __cpuid(int info[4], int ax) { return __cpuidex(info, ax, 0); }

BOOL cpuidIsHypvervisor() {
    int cpuInfo[4] = {-1};

    __cpuid(cpuInfo, 0x40000000);

    char vendor[20] = {0};

    *(unsigned int *)(&vendor[0]) = cpuInfo[1];
    *(unsigned int *)(&vendor[4]) = cpuInfo[2];
    *(unsigned int *)(&vendor[8]) = cpuInfo[3];

    if (!strcmp(vendor, "VMwareVMware")) {
        return TRUE;
    }

    if (!strcmp(vendor, "VBoxVBoxVBox")) {
        return TRUE;
    }

    // if (!strcmp(vendor, "Microsoft Hv")) {
    //     return TRUE;
    // }

    return FALSE;
}

/*
Check what power states are enabled.
Most VMs don't support S1-S4 power states whereas most hardware does, and thermal control is usually not found either.
This has been tested on VirtualBox and Hyper-V, as well as a physical desktop and laptop.
*/
BOOL powerCapabilities(protoLoadLibraryA _LoadLibraryA, protoGetProcAddress _GetProcAddress) {
    HMODULE PowrProfDll = _LoadLibraryA("PowrProf.dll");
    protoGetPwrCapabilities _GetPwrCapabilities = (protoGetPwrCapabilities)_GetProcAddress(PowrProfDll, "GetPwrCapabilities");

    SYSTEM_POWER_CAPABILITIES powerCaps;

    if (_GetPwrCapabilities(&powerCaps) == TRUE) {
        if ((powerCaps.SystemS1 | powerCaps.SystemS2 | powerCaps.SystemS3 | powerCaps.SystemS4) == FALSE) {
            return powerCaps.ThermalControl == FALSE;
        }
    }

    return FALSE;
}