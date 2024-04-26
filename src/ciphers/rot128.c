void rot128Cipher(char *block, unsigned int size, unsigned long long key) {
    __asm__(
        "call next;"
        "next: pop %rax;"
        "sub $0x5, %rax;"
        "add %rax, %rcx;");
    for (unsigned int i = 0; i < size; ++i) {
        block[i] = (block[i] + 128) & 0xff;
    }
}