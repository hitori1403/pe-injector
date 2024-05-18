#include <Windows.h>

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