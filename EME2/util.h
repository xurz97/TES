#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <wmmintrin.h>
#include <smmintrin.h>

void print_m128i_with_string(char *string, __m128i data);
int compare(const void *a, const void *b);
void output(unsigned char *arr, int num);

// output m128i
void print_m128i_with_string(char *string, __m128i data)
{
    unsigned char *pointer = (unsigned char *)&data;
    int i;
    printf("%-40s[0x", string);
    for (i = 0; i < 16; i++)
        printf("%02x", pointer[i]);
    printf("]\n");
}

// output u8 arr
void output(unsigned char *arr, int num)
{
    for (int i = 0; i < num; i++)
    {
        printf("%02x", arr[i]);
        if (i % 16 == 15)
            printf("\n");
    }
}

// compare function used in qsort
int compare(const void *a, const void *b)
{
    double ret = *(double *)a - *(double *)b;
    if (ret > 0)
    {
        return 1;
    }
    else if (ret < 0)
    {
        return -1;
    }
    else
        return 0;
}

#endif