#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "aes.h"
#include <x86intrin.h>  //linux
// #include <intrin.h>  //windows
#include "util.h"
#include "ae.h"
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

// linux
#define ALIGN(n) __attribute__((aligned(n)))
void createFolder(char *foldername)
{
    struct stat st = {0};
    if (stat(foldername, &st) == -1)
    {
        mkdir(foldername, 0777);
        printf("create done.");
    }
    return;
}

int main(int argc, char **argv)
{
    createFolder("result"); //linux
    unsigned int ui;
    ALIGN(16) u8 key[] = {0x76, 0x10, 0xff, 0x13, 0xd7, 0xbd, 0x68, 0x4b,
                0xcb, 0x87, 0x51, 0x90, 0xb5, 0x4d, 0x7c, 0x4f,
                0x60, 0x75, 0x4f, 0x1a, 0x2d, 0xfd, 0x3a, 0xd7,
                0x10, 0xa4, 0x8b, 0x9f, 0x1d, 0x9b, 0x63, 0x02,
                0xe7, 0xc4, 0x37, 0x14, 0xc6, 0x1c, 0xa6, 0xd6,
                0xe6, 0x42, 0xaa, 0xd6, 0x1f, 0xe4, 0x00, 0x29};
    ALIGN(16) u8 pt[4096] = {0};
    ALIGN(16) u8 ct[4096] = {0};
    ALIGN(16) u8 associated[] = {0xfe, 0x81, 0xb7, 0x13, 0xc3, 0x53, 0x03, 0x6e,
                       0x9f, 0xfc, 0x77, 0x8e, 0x69, 0x61, 0x03, 0x35};
    ae_ctx *ctx = ae_allocate(NULL);
    ALIGN(16) u8 tag[16];
    u8 tweak[16];
    unsigned long long clock1, clock2;
    ae_init(ctx, key, 48, 0, 0);
    for (int i = 0; i < 16; i++)
        tweak[i] = 0;
    double cpb[101];
    int pt_len = 32;
    FILE *fp = NULL;
#ifdef USE_AESNI_1
    fp = fopen("./result/EME2_reg.txt", "w");
#endif
#ifdef USE_AESNI_2
    fp = fopen("./result/EME2_mem.txt", "w");
#endif
    while (pt_len <= 4096)
    {
        for (int z = 0; z < 101; z++)
        {
            clock1 = __rdtscp(&ui);
            for (int j = 0; j < 1e4; j++)
            {
                ae_encrypt(ctx, tweak, pt, pt_len, NULL, 0, ct, tag, 1);
            }
            clock2 = __rdtscp(&ui);
            cpb[z] = (clock2 - clock1) / (1e4 * pt_len);
        }
        qsort(cpb, 101, sizeof(double), compare);
        printf("length = %d bytes , cpb = %.3f cycles/byte\n", pt_len, cpb[50]);
        fprintf(fp, "%d %.3f\n", pt_len, cpb[50]);
        pt_len += 32;
    }
    fclose(fp);
    ae_free(ctx);
    return 0;
}
