#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    FILE *fp = fopen(argv[1], "rb");

    fseek(fp, 0, SEEK_END);
    int fsize = ftell(fp);
    rewind(fp);

    char *buf = malloc(fsize + 1);

    fread(buf, 1, fsize, fp);
    fclose(fp);

    buf[fsize] = 0;

    for (int i = 0; i < fsize; ++i) {
        printf("\\x%02x", buf[i] & 0xff);
    }
}
