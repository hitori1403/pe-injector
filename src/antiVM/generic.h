#include <Windows.h>

static inline void __cpuidex(int info[4], int ax, int cx) {
    __asm__("cpuid" : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3]) : "a"(ax), "c"(cx));
}
static inline void __cpuid(int info[4], int ax) { return __cpuidex(info, ax, 0); }

BOOL cpuidIsHypvervisor() {
    int CPUInfo[4] = {-1};

    __cpuid(CPUInfo, 1);

    if ((CPUInfo[2] >> 31) & 1) {
        return TRUE;
    }

    return FALSE;
}