#define BYTEn(x, n) ((x >> 8 * n) & 0xff)

void cipher(char *block, unsigned int size, unsigned long long key) {
    __asm__(
        "call next;"
        "next: pop %rax;"
        "sub $0x5, %rax;"
        "add %rax, %rcx;");
    for (unsigned int i = 0; i < size; ++i) {
        block[i] ^= BYTEn(key, i & 7);
    }
}