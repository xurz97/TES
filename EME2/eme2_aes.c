#include "ae.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include <stdio.h>

// PPPi and CCCi store in the register
void EME2_encrypt_1(const unsigned char *pt,
                    int pt_len,
                    const unsigned char *ad,
                    int ad_len,
                    unsigned char *ct,
                    ae_ctx *ctx);

// PPPi and CCCi store in the memory
void EME2_encrypt_2(const unsigned char *pt,
                    int pt_len,
                    const unsigned char *ad,
                    int ad_len,
                    unsigned char *ct,
                    ae_ctx *ctx);

struct _ae_ctx
{
    u8 Kaes[16];
    u8 Kad[16];
    u8 Kecb[16];
    u8 k[16 * 15];
};

int ae_init(ae_ctx *ctx,
            const void *key,
            int key_len,
            int nonce_len,
            int tag_len)
{
    const u8 *k1 = key;
    for (int i = 0; i < 16; i++)
    {
        ctx->Kad[i] = k1[i];
        ctx->Kecb[i] = k1[i + 16];
        ctx->Kaes[i] = k1[i + 32];
    }
    AES_set_encrypt_key(ctx->Kaes, 0, (AES_KEY *)ctx->k);
    return 0;
}

int ae_encrypt(ae_ctx *ctx,
               const void *nonce,
               const void *pt,
               int pt_len,
               const void *ad,
               int ad_len,
               void *ct,
               void *tag,
               int final)
{
#ifdef USE_AESNI_1
    EME2_encrypt_1(pt, pt_len, ad, ad_len, ct, ctx);
#endif
#ifdef USE_AESNI_2
    EME2_encrypt_2(pt, pt_len, ad, ad_len, ct, ctx);
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

void EME2_encrypt_1(const unsigned char *pt,
                    int pt_len,
                    const unsigned char *ad,
                    int ad_len,
                    unsigned char *ct,
                    ae_ctx *ctx)
{
    __m128i T_star = _mm_setzero_si128(), temp;
    // H
    __m128i *KEY = (__m128i *)ctx->k;
    __m128i Kad = _mm_loadu_si128(ctx->Kad);
    int i, j;
    if (ad_len == 0)
    {
        T_star = _mm_xor_si128(Kad, KEY[0]);
        for (i = 1; i < 10; i++)
            T_star = _mm_aesenc_si128(T_star, KEY[i]);
        T_star = _mm_aesenclast_si128(T_star, KEY[10]);
    }
    else
    {
        for (i = 0; i < ad_len / 16; i++)
        {
            Kad = xts_crank_lfsr(Kad);
            temp = KEY[0] ^ _mm_xor_si128(Kad, _mm_loadu_si128(&((__m128i *)ad)[i]));
            for (j = 1; j < 10; j++)
                temp = _mm_aesenc_si128(temp, KEY[j]);
            temp = _mm_aesenclast_si128(temp, KEY[10]);
            temp ^= Kad;
            T_star ^= temp;
        }
    }
    __m128i PPP[256], CCC[256];
    // First ECB pass
    __m128i L = _mm_loadu_si128(ctx->Kecb);
    for (i = 0; i < pt_len / 16; i++)
    {
        temp = L ^ _mm_loadu_si128(&((__m128i *)pt)[i]);
        PPP[i] = temp ^ KEY[0];
        for (j = 1; j < 10; j++)
            PPP[i] = _mm_aesenc_si128(PPP[i], KEY[j]);
        PPP[i] = _mm_aesenclast_si128(PPP[i], KEY[10]);
        L = xts_crank_lfsr(L);
    }
    // Intermediate mixing
    __m128i MP = T_star, MC, MC1, M, M1;
    for (int i = 0; i < pt_len / 16; i++)
        MP ^= PPP[i];
    MC = MP ^ KEY[0];
    for (j = 1; j < 10; j++)
        MC = _mm_aesenc_si128(MC, KEY[j]);
    MC = _mm_aesenclast_si128(MC, KEY[10]);
    MC1 = MC;
    M = M1 = MP ^ MC;
    for (i = 1; i < pt_len / 16; i++)
    {
        if (i % 128)
        {
            M = xts_crank_lfsr(M);
            CCC[i] = PPP[i] ^ M;
        }
        else
        {
            MP = PPP[i] ^ M1;
            MC = MP ^ KEY[0];
            for (j = 1; j < 10; j++)
                MC = _mm_aesenc_si128(MC, KEY[j]);
            MC = _mm_aesenclast_si128(MC, KEY[10]);
            M = MP ^ MC;
            CCC[i] = MC ^ M1;
        }
    }
    CCC[0] = MC1 ^ T_star;
    for (i = 1; i < pt_len / 16; i++)
    {
        CCC[0] ^= CCC[i];
    }

    // Second ECB Pass
    L = _mm_loadu_si128(ctx->Kecb);
    for (int i = 0; i < pt_len / 16; i++)
    {
        CCC[i] = CCC[i] ^ KEY[0];
        for (j = 1; j < 10; j++)
            CCC[i] = _mm_aesenc_si128(CCC[i], KEY[j]);
        CCC[i] = _mm_aesenclast_si128(CCC[i], KEY[10]);
        CCC[i] ^= L;
        _mm_store_si128(&((__m128i *)ct)[i], CCC[i]);
        L = xts_crank_lfsr(L);
    }
}

void EME2_encrypt_2(const unsigned char *pt,
                    int pt_len,
                    const unsigned char *ad,
                    int ad_len,
                    unsigned char *ct,
                    ae_ctx *ctx)
{
    u8 PPP[16 * 512], CCC[16 * 512];
    __m128i T_star = _mm_setzero_si128(), temp;
    __m128i *KEY = (__m128i *)ctx->k;
    __m128i Kad = _mm_loadu_si128(ctx->Kad);
    int i, j;
    if (ad_len == 0)
    {
        T_star = _mm_xor_si128(Kad, KEY[0]);
        for (i = 1; i < 10; i++)
            T_star = _mm_aesenc_si128(T_star, KEY[i]);
        T_star = _mm_aesenclast_si128(T_star, KEY[10]);
    }
    else
    {
        for (i = 0; i < ad_len / 16; i++)
        {
            Kad = xts_crank_lfsr(Kad);
            temp = KEY[0] ^ _mm_xor_si128(Kad, _mm_loadu_si128(&((__m128i *)ad)[i]));
            for (j = 1; j < 10; j++)
                temp = _mm_aesenc_si128(temp, KEY[j]);
            temp = _mm_aesenclast_si128(temp, KEY[10]);
            temp ^= Kad;
            T_star ^= temp;
        }
    }
    __m128i PPP1, CCC1;
    // First ECB pass
    __m128i L = _mm_loadu_si128(ctx->Kecb);
    __m128i MP = T_star, MC, MC1, M, M1;
    for (i = 0; i < pt_len / 16; i++)
    {
        temp = L ^ _mm_loadu_si128(&((__m128i *)pt)[i]);
        PPP1 = temp ^ KEY[0];
        for (j = 1; j < 10; j++)
            PPP1 = _mm_aesenc_si128(PPP1, KEY[j]);
        PPP1 = _mm_aesenclast_si128(PPP1, KEY[10]);
        MP ^= PPP1;
        _mm_store_si128(&((__m128i *)PPP)[i], PPP1);
        L = xts_crank_lfsr(L);
    }
    // Intermediate mixing
    MC = MP ^ KEY[0];
    for (j = 1; j < 10; j++)
        MC = _mm_aesenc_si128(MC, KEY[j]);
    MC = _mm_aesenclast_si128(MC, KEY[10]);
    MC1 = MC;
    M = M1 = MP ^ MC;
    __m128i CCC0 = MC1 ^ T_star;
    for (i = 1; i < pt_len / 16; i++)
    {
        if (i % 128)
        {
            PPP1 = _mm_loadu_si128(&((__m128i *)PPP)[i]);
            M = xts_crank_lfsr(M);
            CCC1 = PPP1 ^ M;
            CCC0 = CCC0 ^ CCC1;
            _mm_store_si128(&((__m128i *)CCC)[i], CCC1);
        }
        else
        {
            PPP1 = _mm_loadu_si128(&((__m128i *)PPP)[i]);
            MP = PPP1 ^ M1;
            MC = MP ^ KEY[0];
            for (j = 1; j < 10; j++)
                MC = _mm_aesenc_si128(MC, KEY[j]);
            MC = _mm_aesenclast_si128(MC, KEY[10]);
            M = MP ^ MC;
            CCC1 = MC ^ M1;
            CCC0 = CCC0 ^ CCC1;
            _mm_store_si128(&((__m128i *)CCC)[i], CCC1);
        }
    }
    _mm_store_si128(&((__m128i *)CCC)[0], CCC0);
    // Second ECB Pass
    L = _mm_loadu_si128(ctx->Kecb);
    for (int i = 0; i < pt_len / 16; i++)
    {
        CCC1 = _mm_loadu_si128(&((__m128i *)CCC)[i]);
        CCC1 = CCC1 ^ KEY[0];
        for (j = 1; j < 10; j++)
            CCC1 = _mm_aesenc_si128(CCC1, KEY[j]);
        CCC1 = _mm_aesenclast_si128(CCC1, KEY[10]);
        CCC1 ^= L;
        _mm_store_si128(&((__m128i *)ct)[i], CCC1);
        L = xts_crank_lfsr(L);
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