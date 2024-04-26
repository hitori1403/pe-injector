#define BYTEn(x, n) ((x >> 8 * n) & 0xff)

void xorCipher(char *block, unsigned int size, unsigned long long key) {
    for (unsigned int i = 0; i < size; ++i) {
        block[i] ^= BYTEn(key, i & 7);
    }
}

void rot128Cipher(char *block, unsigned int size, unsigned long long key) {
    for (unsigned int i = 0; i < size; ++i) {
        block[i] = (block[i] + 128) & 0xff;
    }
}