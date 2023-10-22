#include "ae.h"
#include "aes.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

void XTS_encrypt_1(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx);
void XTS_encrypt_2(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx);
void XTS_encrypt_4(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx);
void XTS_encrypt_6(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx);
void XTS_encrypt_8(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx);

struct _ae_ctx
{
    uint8_t K1[16 * 15];
    uint8_t K2[16 * 15];
};

int ae_init(ae_ctx *ctx, const void *key, int key_len, int nonce_len, int tag_len)
{
    AES_set_encrypt_key(key, 0, (AES_KEY *)ctx->K1);
    AES_set_encrypt_key((unsigned char *)key + 16, 0, (AES_KEY *)ctx->K2);
    return 0;
}

int ae_encrypt(ae_ctx *ctx, const void *nonce, const void *pt, int pt_len, const void *ad, int ad_len, void *ct, void *tag, int final)
{
#ifdef USE_AESNI_1
    XTS_encrypt_1(pt, pt_len, nonce, ct, ctx);
#endif
#ifdef USE_AESNI_2
    XTS_encrypt_2(pt, pt_len, nonce, ct, ctx);
#endif
#ifdef USE_AESNI_4
    XTS_encrypt_4(pt, pt_len, nonce, ct, ctx);
#endif
#ifdef USE_AESNI_6
    XTS_encrypt_6(pt, pt_len, nonce, ct, ctx);
#endif
#ifdef USE_AESNI_8
    XTS_encrypt_8(pt, pt_len, nonce, ct, ctx);
#endif
    return pt_len;
}

static inline __m128i xts_crank_lfsr(__m128i inp) // from freebsd aes-ni_wrap.c
{
    const __m128i alphamask = _mm_set_epi32(1, 1, 1, 0x87);
    __m128i xtweak, ret;
    xtweak = _mm_shuffle_epi32(inp, 0x93);
    xtweak = _mm_srai_epi32(xtweak, 31);
    xtweak = _mm_and_si128(xtweak, alphamask);
    ret = _mm_slli_epi32(inp, 1);
    ret = _mm_xor_si128(ret, xtweak);
    return ret;
}

void XTS_encrypt_1(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx)
{
    __m128i tmp, T = _mm_load_si128((const __m128i *)nonce);
    __m128i *KEY = (__m128i *)ctx->K2;
    T = _mm_xor_si128(T, KEY[0]);
    for (int i = 1; i < 10; i++)
        T = _mm_aesenc_si128(T, KEY[i]);
    T = _mm_aesenclast_si128(T, KEY[10]);
    KEY = (__m128i *)ctx->K1;
    for (int i = 0; i < (pt_len >> 4); i++)
    {
        tmp = _mm_load_si128(&((__m128i *)pt)[i]);
        tmp = _mm_xor_si128(tmp, T);
        tmp = _mm_xor_si128(tmp, KEY[0]);
        for (int j = 1; j < 10; j++)
            tmp = _mm_aesenc_si128(tmp, KEY[j]);
        tmp = _mm_aesenclast_si128(tmp, KEY[10]);
        tmp = _mm_xor_si128(tmp, T);
        T = xts_crank_lfsr(T);
        _mm_store_si128(&((__m128i *)ct)[i], tmp);
    }
}

void XTS_encrypt_2(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx)
{
    __m128i T;
    T = _mm_load_si128((const __m128i *)nonce);
    __m128i *KEY = (__m128i *)ctx->K2;
    T = _mm_xor_si128(T, KEY[0]);
    for (int i = 1; i < 10; i++)
        T = _mm_aesenc_si128(T, KEY[i]);
    T = _mm_aesenclast_si128(T, KEY[10]);
    KEY = (__m128i *)ctx->K1;
    int i, j;
    __m128i tmp[2], t[2];
    t[0] = T;
    t[1] = xts_crank_lfsr(t[0]);
    for (i = 0; i < pt_len / 32; i++)
    {
        tmp[0] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 2 + 0]), t[0]);
        tmp[1] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 2 + 1]), t[1]);

        tmp[0] = _mm_xor_si128(tmp[0], KEY[0]);
        tmp[1] = _mm_xor_si128(tmp[1], KEY[0]);

        for (j = 1; j < 10; j++)
        {
            tmp[0] = _mm_aesenc_si128(tmp[0], KEY[j]);
            tmp[1] = _mm_aesenc_si128(tmp[1], KEY[j]);
        }
        tmp[0] = _mm_aesenclast_si128(tmp[0], KEY[10]);
        tmp[1] = _mm_aesenclast_si128(tmp[1], KEY[10]);
        tmp[0] = _mm_xor_si128(tmp[0], t[0]);
        tmp[1] = _mm_xor_si128(tmp[1], t[1]);
        _mm_store_si128(&((__m128i *)ct)[i * 2 + 0], tmp[0]);
        _mm_store_si128(&((__m128i *)ct)[i * 2 + 1], tmp[1]);
        t[0] = xts_crank_lfsr(t[1]);
        t[1] = xts_crank_lfsr(t[0]);
    }
    for (i = i * 2; i < pt_len / 16; i++)
    {
        tmp[0] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i]), t[0]);
        tmp[0] = _mm_xor_si128(tmp[0], KEY[0]);
        for (j = 1; j < 10; j++)
            tmp[0] = _mm_aesenc_si128(tmp[0], KEY[j]);
        tmp[0] = _mm_aesenclast_si128(tmp[0], KEY[10]);
        tmp[0] = _mm_xor_si128(tmp[0], t[0]);
        _mm_store_si128(&((__m128i *)ct)[i], tmp[0]);
        t[0] = xts_crank_lfsr(t[0]);
    }
}

void XTS_encrypt_4(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx)
{
    __m128i T;
    T = _mm_load_si128((const __m128i *)nonce);
    __m128i *KEY = (__m128i *)ctx->K2;
    T = _mm_xor_si128(T, KEY[0]);
    for (int i = 1; i < 10; i++)
        T = _mm_aesenc_si128(T, KEY[i]);
    T = _mm_aesenclast_si128(T, KEY[10]);
    KEY = (__m128i *)ctx->K1;
    int i, j;
    __m128i tmp[4], t[4];
    t[0] = T;
    t[1] = xts_crank_lfsr(t[0]);
    t[2] = xts_crank_lfsr(t[1]);
    t[3] = xts_crank_lfsr(t[2]);
    for (i = 0; i < pt_len / 64; i++)
    {
        tmp[0] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 4 + 0]), t[0]);
        tmp[1] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 4 + 1]), t[1]);
        tmp[2] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 4 + 2]), t[2]);
        tmp[3] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 4 + 3]), t[3]);

        tmp[0] = _mm_xor_si128(tmp[0], KEY[0]);
        tmp[1] = _mm_xor_si128(tmp[1], KEY[0]);
        tmp[2] = _mm_xor_si128(tmp[2], KEY[0]);
        tmp[3] = _mm_xor_si128(tmp[3], KEY[0]);

        for (j = 1; j < 10; j++)
        {
            tmp[0] = _mm_aesenc_si128(tmp[0], KEY[j]);
            tmp[1] = _mm_aesenc_si128(tmp[1], KEY[j]);
            tmp[2] = _mm_aesenc_si128(tmp[2], KEY[j]);
            tmp[3] = _mm_aesenc_si128(tmp[3], KEY[j]);
        }
        tmp[0] = _mm_aesenclast_si128(tmp[0], KEY[10]);
        tmp[1] = _mm_aesenclast_si128(tmp[1], KEY[10]);
        tmp[2] = _mm_aesenclast_si128(tmp[2], KEY[10]);
        tmp[3] = _mm_aesenclast_si128(tmp[3], KEY[10]);
        tmp[0] = _mm_xor_si128(tmp[0], t[0]);
        tmp[1] = _mm_xor_si128(tmp[1], t[1]);
        tmp[2] = _mm_xor_si128(tmp[2], t[2]);
        tmp[3] = _mm_xor_si128(tmp[3], t[3]);
        _mm_store_si128(&((__m128i *)ct)[i * 4 + 0], tmp[0]);
        _mm_store_si128(&((__m128i *)ct)[i * 4 + 1], tmp[1]);
        _mm_store_si128(&((__m128i *)ct)[i * 4 + 2], tmp[2]);
        _mm_store_si128(&((__m128i *)ct)[i * 4 + 3], tmp[3]);
        t[0] = xts_crank_lfsr(t[3]);
        t[1] = xts_crank_lfsr(t[0]);
        t[2] = xts_crank_lfsr(t[1]);
        t[3] = xts_crank_lfsr(t[2]);
    }
    for (i = i * 4; i < pt_len / 16; i++)
    {
        tmp[0] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i]), t[0]);
        tmp[0] = _mm_xor_si128(tmp[0], KEY[0]);
        for (j = 1; j < 10; j++)
            tmp[0] = _mm_aesenc_si128(tmp[0], KEY[j]);
        tmp[0] = _mm_aesenclast_si128(tmp[0], KEY[10]);
        tmp[0] = _mm_xor_si128(tmp[0], t[0]);
        _mm_store_si128(&((__m128i *)ct)[i], tmp[0]);
        t[0] = xts_crank_lfsr(t[0]);
    }
}

void XTS_encrypt_6(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx)
{
    __m128i T;
    T = _mm_load_si128((const __m128i *)nonce);
    __m128i *KEY = (__m128i *)ctx->K2;
    T = _mm_xor_si128(T, KEY[0]);
    for (int i = 1; i < 10; i++)
        T = _mm_aesenc_si128(T, KEY[i]);
    T = _mm_aesenclast_si128(T, KEY[10]);
    KEY = (__m128i *)ctx->K1;
    int i, j;
    __m128i tmp[6], t[6];
    t[0] = T;
    t[1] = xts_crank_lfsr(t[0]);
    t[2] = xts_crank_lfsr(t[1]);
    t[3] = xts_crank_lfsr(t[2]);
    t[4] = xts_crank_lfsr(t[3]);
    t[5] = xts_crank_lfsr(t[4]);
    for (i = 0; i < pt_len / 96; i++)
    {
        tmp[0] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 6 + 0]), t[0]);
        tmp[1] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 6 + 1]), t[1]);
        tmp[2] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 6 + 2]), t[2]);
        tmp[3] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 6 + 3]), t[3]);
        tmp[4] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 6 + 4]), t[4]);
        tmp[5] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 6 + 5]), t[5]);

        tmp[0] = _mm_xor_si128(tmp[0], KEY[0]);
        tmp[1] = _mm_xor_si128(tmp[1], KEY[0]);
        tmp[2] = _mm_xor_si128(tmp[2], KEY[0]);
        tmp[3] = _mm_xor_si128(tmp[3], KEY[0]);
        tmp[4] = _mm_xor_si128(tmp[4], KEY[0]);
        tmp[5] = _mm_xor_si128(tmp[5], KEY[0]);

        for (j = 1; j < 10; j++)
        {
            tmp[0] = _mm_aesenc_si128(tmp[0], KEY[j]);
            tmp[1] = _mm_aesenc_si128(tmp[1], KEY[j]);
            tmp[2] = _mm_aesenc_si128(tmp[2], KEY[j]);
            tmp[3] = _mm_aesenc_si128(tmp[3], KEY[j]);
            tmp[4] = _mm_aesenc_si128(tmp[4], KEY[j]);
            tmp[5] = _mm_aesenc_si128(tmp[5], KEY[j]);
        }
        tmp[0] = _mm_aesenclast_si128(tmp[0], KEY[10]);
        tmp[1] = _mm_aesenclast_si128(tmp[1], KEY[10]);
        tmp[2] = _mm_aesenclast_si128(tmp[2], KEY[10]);
        tmp[3] = _mm_aesenclast_si128(tmp[3], KEY[10]);
        tmp[4] = _mm_aesenclast_si128(tmp[4], KEY[10]);
        tmp[5] = _mm_aesenclast_si128(tmp[5], KEY[10]);

        tmp[0] = _mm_xor_si128(tmp[0], t[0]);
        tmp[1] = _mm_xor_si128(tmp[1], t[1]);
        tmp[2] = _mm_xor_si128(tmp[2], t[2]);
        tmp[3] = _mm_xor_si128(tmp[3], t[3]);
        tmp[4] = _mm_xor_si128(tmp[4], t[4]);
        tmp[5] = _mm_xor_si128(tmp[5], t[5]);

        _mm_store_si128(&((__m128i *)ct)[i * 6 + 0], tmp[0]);
        _mm_store_si128(&((__m128i *)ct)[i * 6 + 1], tmp[1]);
        _mm_store_si128(&((__m128i *)ct)[i * 6 + 2], tmp[2]);
        _mm_store_si128(&((__m128i *)ct)[i * 6 + 3], tmp[3]);
        _mm_store_si128(&((__m128i *)ct)[i * 6 + 4], tmp[4]);
        _mm_store_si128(&((__m128i *)ct)[i * 6 + 5], tmp[5]);

        t[0] = xts_crank_lfsr(t[5]);
        t[1] = xts_crank_lfsr(t[0]);
        t[2] = xts_crank_lfsr(t[1]);
        t[3] = xts_crank_lfsr(t[2]);
        t[4] = xts_crank_lfsr(t[3]);
        t[5] = xts_crank_lfsr(t[4]);
    }
    for (i = i * 6; i < pt_len / 16; i++)
    {
        tmp[0] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i]), t[0]);
        tmp[0] = _mm_xor_si128(tmp[0], KEY[0]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[1]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[2]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[3]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[4]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[5]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[6]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[7]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[8]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[9]);
        tmp[0] = _mm_aesenclast_si128(tmp[0], KEY[10]);
        tmp[0] = _mm_xor_si128(tmp[0], t[0]);
        _mm_store_si128(&((__m128i *)ct)[i], tmp[0]);
        t[0] = xts_crank_lfsr(t[0]);
    }
}
void XTS_encrypt_8(const unsigned char *pt, int pt_len, const unsigned char *nonce, unsigned char *ct, ae_ctx *ctx)
{
    __m128i T;
    T = _mm_load_si128((const __m128i *)nonce);
    __m128i *KEY = (__m128i *)ctx->K2;
    T = _mm_xor_si128(T, KEY[0]);
    for (int i = 1; i < 10; i++)
        T = _mm_aesenc_si128(T, KEY[i]);
    T = _mm_aesenclast_si128(T, KEY[10]);
    KEY = (__m128i *)ctx->K1;
    int i, j;
    __m128i tmp[8], t[8];
    t[0] = T;
    t[1] = xts_crank_lfsr(t[0]);
    t[2] = xts_crank_lfsr(t[1]);
    t[3] = xts_crank_lfsr(t[2]);
    t[4] = xts_crank_lfsr(t[3]);
    t[5] = xts_crank_lfsr(t[4]);
    t[6] = xts_crank_lfsr(t[5]);
    t[7] = xts_crank_lfsr(t[6]);
    for (i = 0; i < pt_len / 128; i++)
    {
        tmp[0] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 8 + 0]), t[0]);
        tmp[1] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 8 + 1]), t[1]);
        tmp[2] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 8 + 2]), t[2]);
        tmp[3] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 8 + 3]), t[3]);
        tmp[4] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 8 + 4]), t[4]);
        tmp[5] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 8 + 5]), t[5]);
        tmp[6] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 8 + 6]), t[6]);
        tmp[7] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i * 8 + 7]), t[7]);

        tmp[0] = _mm_xor_si128(tmp[0], KEY[0]);
        tmp[1] = _mm_xor_si128(tmp[1], KEY[0]);
        tmp[2] = _mm_xor_si128(tmp[2], KEY[0]);
        tmp[3] = _mm_xor_si128(tmp[3], KEY[0]);
        tmp[4] = _mm_xor_si128(tmp[4], KEY[0]);
        tmp[5] = _mm_xor_si128(tmp[5], KEY[0]);
        tmp[6] = _mm_xor_si128(tmp[6], KEY[0]);
        tmp[7] = _mm_xor_si128(tmp[7], KEY[0]);

        for (j = 1; j < 10; j++)
        {
            tmp[0] = _mm_aesenc_si128(tmp[0], KEY[j]);
            tmp[1] = _mm_aesenc_si128(tmp[1], KEY[j]);
            tmp[2] = _mm_aesenc_si128(tmp[2], KEY[j]);
            tmp[3] = _mm_aesenc_si128(tmp[3], KEY[j]);
            tmp[4] = _mm_aesenc_si128(tmp[4], KEY[j]);
            tmp[5] = _mm_aesenc_si128(tmp[5], KEY[j]);
            tmp[6] = _mm_aesenc_si128(tmp[6], KEY[j]);
            tmp[7] = _mm_aesenc_si128(tmp[7], KEY[j]);
        }
        tmp[0] = _mm_aesenclast_si128(tmp[0], KEY[10]);
        tmp[1] = _mm_aesenclast_si128(tmp[1], KEY[10]);
        tmp[2] = _mm_aesenclast_si128(tmp[2], KEY[10]);
        tmp[3] = _mm_aesenclast_si128(tmp[3], KEY[10]);
        tmp[4] = _mm_aesenclast_si128(tmp[4], KEY[10]);
        tmp[5] = _mm_aesenclast_si128(tmp[5], KEY[10]);
        tmp[6] = _mm_aesenclast_si128(tmp[6], KEY[10]);
        tmp[7] = _mm_aesenclast_si128(tmp[7], KEY[10]);

        tmp[0] = _mm_xor_si128(tmp[0], t[0]);
        tmp[1] = _mm_xor_si128(tmp[1], t[1]);
        tmp[2] = _mm_xor_si128(tmp[2], t[2]);
        tmp[3] = _mm_xor_si128(tmp[3], t[3]);
        tmp[4] = _mm_xor_si128(tmp[4], t[4]);
        tmp[5] = _mm_xor_si128(tmp[5], t[5]);
        tmp[6] = _mm_xor_si128(tmp[6], t[6]);
        tmp[7] = _mm_xor_si128(tmp[7], t[7]);

        _mm_store_si128(&((__m128i *)ct)[i * 8 + 0], tmp[0]);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 1], tmp[1]);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 2], tmp[2]);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 3], tmp[3]);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 4], tmp[4]);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 5], tmp[5]);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 6], tmp[6]);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 7], tmp[7]);

        t[0] = xts_crank_lfsr(t[7]);
        t[1] = xts_crank_lfsr(t[0]);
        t[2] = xts_crank_lfsr(t[1]);
        t[3] = xts_crank_lfsr(t[2]);
        t[4] = xts_crank_lfsr(t[3]);
        t[5] = xts_crank_lfsr(t[4]);
        t[6] = xts_crank_lfsr(t[5]);
        t[7] = xts_crank_lfsr(t[6]);
    }
    for (i = i * 8; i < pt_len / 16; i++)
    {
        tmp[0] = _mm_xor_si128(_mm_load_si128(&((__m128i *)pt)[i]), t[0]);
        tmp[0] = _mm_xor_si128(tmp[0], KEY[0]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[1]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[2]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[3]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[4]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[5]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[6]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[7]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[8]);
        tmp[0] = _mm_aesenc_si128(tmp[0], KEY[9]);
        tmp[0] = _mm_aesenclast_si128(tmp[0], KEY[10]);
        tmp[0] = _mm_xor_si128(tmp[0], t[0]);
        _mm_store_si128(&((__m128i *)ct)[i], tmp[0]);
        t[0] = xts_crank_lfsr(t[0]);
    }
}

#define USE_MM_MALLOC ((__SSE2__ || _M_IX86_FP >= 2) && !(_M_X64 || __x86_64__))
#define USE_POSIX_MEMALIGN (__ALTIVEC__ && __GLIBC__ && !__PPC64__)

ae_ctx *ae_allocate(void *misc)
{
    void *p;
    (void)misc; /* misc unused in this implementation */
#if USE_MM_MALLOC
    p = _mm_malloc(sizeof(ae_ctx), 16);
#elif USE_POSIX_MEMALIGN
    if (posix_memalign(&p, 16, sizeof(ae_ctx)) != 0)
        p = NULL;
#else
    p = malloc(sizeof(ae_ctx));
#endif
    return (ae_ctx *)p;
}

void ae_free(ae_ctx *ctx)
{
#if USE_MM_MALLOC
    _mm_free(ctx);
#else
    free(ctx);
#endif
}