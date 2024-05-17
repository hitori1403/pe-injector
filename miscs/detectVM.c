#include <stdio.h>

static inline void __cpuidex(int info[4], int ax, int cx) {
    __asm__("cpuid" : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3]) : "a"(ax), "c"(cx));
}
static inline void __cpuid(int info[4], int ax) { return __cpuidex(info, ax, 0); }

unsigned char vendor[20];

int main() {
    int cpuInfo[4] = {-1};

    __cpuid(cpuInfo, 1);

    *(unsigned int *)(&vendor[0]) = cpuInfo[1];
    *(unsigned int *)(&vendor[4]) = cpuInfo[2];
    *(unsigned int *)(&vendor[8]) = cpuInfo[3];

    puts(vendor);
}
