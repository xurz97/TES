#include "ae.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include <stdio.h>

static __m128i reduce(__m128i prod_high, __m128i prod_low) // from PyCryptodome
{
    const uint64_t c2 = (uint64_t)0xc2 << 56;
    __m128i t1, t2, t3, t4, t7;
    t1 = prod_high; /* U3:U2 */
    t7 = prod_low;  /* U1:U0 */
    t3 = _mm_loadl_epi64((__m128i *)&c2);
    t2 = _mm_clmulepi64_si128(t3, t7, 0x00);             /* A */
    t4 = _mm_shuffle_epi32(t7, _MM_SHUFFLE(1, 0, 3, 2)); /* U0:U1 */
    t4 = _mm_xor_si128(t4, t2);                          /* B */
    t2 = _mm_clmulepi64_si128(t3, t4, 0x00);             /* C */
    t4 = _mm_shuffle_epi32(t4, _MM_SHUFFLE(1, 0, 3, 2)); /* B0:B1 */
    t4 = _mm_xor_si128(t4, t2);                          /* D */
    t1 = _mm_xor_si128(t1, t4);                          /* T */
    return t1;
}

static void reduce2(__m128i H1, __m128i H2,
                    __m128i X1, __m128i X2, __m128i *res)
{
    const uint64_t c2 = (uint64_t)0xc2 << 56;
    __m128i POLY = _mm_loadl_epi64((__m128i *)&c2);
    __m128i H1_X1_lo, H1_X1_hi,
        H2_X2_lo, H2_X2_hi,
        lo, hi;
    __m128i tmp0, tmp1, tmp2, tmp3;
    __m128i tmp4, tmp5, tmp6, tmp7;
    __m128i tmp8, tmp9;
    H1_X1_lo = _mm_clmulepi64_si128(H1, X1, 0x00);
    H2_X2_lo = _mm_clmulepi64_si128(H2, X2, 0x00);
    lo = _mm_xor_si128(H1_X1_lo, H2_X2_lo);
    H1_X1_hi = _mm_clmulepi64_si128(H1, X1, 0x11);
    H2_X2_hi = _mm_clmulepi64_si128(H2, X2, 0x11);
    hi = _mm_xor_si128(H1_X1_hi, H2_X2_hi);
    tmp0 = _mm_shuffle_epi32(H1, 78);
    tmp4 = _mm_shuffle_epi32(X1, 78);
    tmp0 = _mm_xor_si128(tmp0, H1);
    tmp4 = _mm_xor_si128(tmp4, X1);
    tmp1 = _mm_shuffle_epi32(H2, 78);
    tmp5 = _mm_shuffle_epi32(X2, 78);
    tmp1 = _mm_xor_si128(tmp1, H2);
    tmp5 = _mm_xor_si128(tmp5, X2);
    tmp0 = _mm_clmulepi64_si128(tmp0, tmp4, 0x00);
    tmp1 = _mm_clmulepi64_si128(tmp1, tmp5, 0x00);
    tmp0 = _mm_xor_si128(tmp0, lo);
    tmp0 = _mm_xor_si128(tmp0, hi);
    tmp0 = _mm_xor_si128(tmp1, tmp0);
    tmp4 = _mm_slli_si128(tmp0, 8);
    tmp0 = _mm_srli_si128(tmp0, 8);
    lo = _mm_xor_si128(tmp4, lo);
    hi = _mm_xor_si128(tmp0, hi);
    tmp1 = lo;
    tmp4 = hi;
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78);
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78);
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    *res = _mm_xor_si128(tmp1, tmp4);
    return;
}

// reduce4 from Intel GCM Whitepaper
static void reduce4(__m128i H1, __m128i H2, __m128i H3, __m128i H4,
                    __m128i X1, __m128i X2, __m128i X3, __m128i X4, __m128i *res)
{
    const uint64_t c2 = (uint64_t)0xc2 << 56;
    __m128i POLY = _mm_loadl_epi64((__m128i *)&c2);
    __m128i H1_X1_lo, H1_X1_hi,
        H2_X2_lo, H2_X2_hi,
        H3_X3_lo, H3_X3_hi,
        H4_X4_lo, H4_X4_hi,
        lo, hi;
    __m128i tmp0, tmp1, tmp2, tmp3;
    __m128i tmp4, tmp5, tmp6, tmp7;
    __m128i tmp8, tmp9;
    H1_X1_lo = _mm_clmulepi64_si128(H1, X1, 0x00);
    H2_X2_lo = _mm_clmulepi64_si128(H2, X2, 0x00);
    H3_X3_lo = _mm_clmulepi64_si128(H3, X3, 0x00);
    H4_X4_lo = _mm_clmulepi64_si128(H4, X4, 0x00);
    lo = _mm_xor_si128(H1_X1_lo, H2_X2_lo);
    lo = _mm_xor_si128(lo, H3_X3_lo);
    lo = _mm_xor_si128(lo, H4_X4_lo);
    H1_X1_hi = _mm_clmulepi64_si128(H1, X1, 0x11);
    H2_X2_hi = _mm_clmulepi64_si128(H2, X2, 0x11);
    H3_X3_hi = _mm_clmulepi64_si128(H3, X3, 0x11);
    H4_X4_hi = _mm_clmulepi64_si128(H4, X4, 0x11);
    hi = _mm_xor_si128(H1_X1_hi, H2_X2_hi);
    hi = _mm_xor_si128(hi, H3_X3_hi);
    hi = _mm_xor_si128(hi, H4_X4_hi);
    tmp0 = _mm_shuffle_epi32(H1, 78);
    tmp4 = _mm_shuffle_epi32(X1, 78);
    tmp0 = _mm_xor_si128(tmp0, H1);
    tmp4 = _mm_xor_si128(tmp4, X1);
    tmp1 = _mm_shuffle_epi32(H2, 78);
    tmp5 = _mm_shuffle_epi32(X2, 78);
    tmp1 = _mm_xor_si128(tmp1, H2);
    tmp5 = _mm_xor_si128(tmp5, X2);
    tmp2 = _mm_shuffle_epi32(H3, 78);
    tmp6 = _mm_shuffle_epi32(X3, 78);
    tmp2 = _mm_xor_si128(tmp2, H3);
    tmp6 = _mm_xor_si128(tmp6, X3);
    tmp3 = _mm_shuffle_epi32(H4, 78);
    tmp7 = _mm_shuffle_epi32(X4, 78);
    tmp3 = _mm_xor_si128(tmp3, H4);
    tmp7 = _mm_xor_si128(tmp7, X4);
    tmp0 = _mm_clmulepi64_si128(tmp0, tmp4, 0x00);
    tmp1 = _mm_clmulepi64_si128(tmp1, tmp5, 0x00);
    tmp2 = _mm_clmulepi64_si128(tmp2, tmp6, 0x00);
    tmp3 = _mm_clmulepi64_si128(tmp3, tmp7, 0x00);
    tmp0 = _mm_xor_si128(tmp0, lo);
    tmp0 = _mm_xor_si128(tmp0, hi);
    tmp0 = _mm_xor_si128(tmp1, tmp0);
    tmp0 = _mm_xor_si128(tmp2, tmp0);
    tmp0 = _mm_xor_si128(tmp3, tmp0);
    tmp4 = _mm_slli_si128(tmp0, 8);
    tmp0 = _mm_srli_si128(tmp0, 8);
    lo = _mm_xor_si128(tmp4, lo);
    hi = _mm_xor_si128(tmp0, hi);
    tmp1 = lo;
    tmp4 = hi;
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78); // 78 = 01001110b
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78); // 78 = 01001110b
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    *res = _mm_xor_si128(tmp1, tmp4);
    return;
}

// multiply used in reduce8
static void multiply(__m128i H1, __m128i H2, __m128i H3, __m128i H4,
                     __m128i X1, __m128i X2, __m128i X3, __m128i X4,
                     __m128i *hi, __m128i *lo)
{
    __m128i H1_X1_lo, H1_X1_hi,
        H2_X2_lo, H2_X2_hi,
        H3_X3_lo, H3_X3_hi,
        H4_X4_lo, H4_X4_hi;
    __m128i tmp0, tmp1, tmp2, tmp3;
    __m128i tmp4, tmp5, tmp6, tmp7;
    __m128i tmp8, tmp9;
    H1_X1_lo = _mm_clmulepi64_si128(H1, X1, 0x00);
    H2_X2_lo = _mm_clmulepi64_si128(H2, X2, 0x00);
    H3_X3_lo = _mm_clmulepi64_si128(H3, X3, 0x00);
    H4_X4_lo = _mm_clmulepi64_si128(H4, X4, 0x00);
    *lo = _mm_xor_si128(H1_X1_lo, H2_X2_lo);
    *lo = _mm_xor_si128(*lo, H3_X3_lo);
    *lo = _mm_xor_si128(*lo, H4_X4_lo);
    H1_X1_hi = _mm_clmulepi64_si128(H1, X1, 0x11);
    H2_X2_hi = _mm_clmulepi64_si128(H2, X2, 0x11);
    H3_X3_hi = _mm_clmulepi64_si128(H3, X3, 0x11);
    H4_X4_hi = _mm_clmulepi64_si128(H4, X4, 0x11);
    *hi = _mm_xor_si128(H1_X1_hi, H2_X2_hi);
    *hi = _mm_xor_si128(*hi, H3_X3_hi);
    *hi = _mm_xor_si128(*hi, H4_X4_hi);
    tmp0 = _mm_shuffle_epi32(H1, 78);
    tmp4 = _mm_shuffle_epi32(X1, 78);
    tmp0 = _mm_xor_si128(tmp0, H1);
    tmp4 = _mm_xor_si128(tmp4, X1);
    tmp1 = _mm_shuffle_epi32(H2, 78);
    tmp5 = _mm_shuffle_epi32(X2, 78);
    tmp1 = _mm_xor_si128(tmp1, H2);
    tmp5 = _mm_xor_si128(tmp5, X2);
    tmp2 = _mm_shuffle_epi32(H3, 78);
    tmp6 = _mm_shuffle_epi32(X3, 78);
    tmp2 = _mm_xor_si128(tmp2, H3);
    tmp6 = _mm_xor_si128(tmp6, X3);
    tmp3 = _mm_shuffle_epi32(H4, 78);
    tmp7 = _mm_shuffle_epi32(X4, 78);
    tmp3 = _mm_xor_si128(tmp3, H4);
    tmp7 = _mm_xor_si128(tmp7, X4);
    tmp0 = _mm_clmulepi64_si128(tmp0, tmp4, 0x00);
    tmp1 = _mm_clmulepi64_si128(tmp1, tmp5, 0x00);
    tmp2 = _mm_clmulepi64_si128(tmp2, tmp6, 0x00);
    tmp3 = _mm_clmulepi64_si128(tmp3, tmp7, 0x00);
    tmp0 = _mm_xor_si128(tmp0, *lo);
    tmp0 = _mm_xor_si128(tmp0, *hi);
    tmp0 = _mm_xor_si128(tmp1, tmp0);
    tmp0 = _mm_xor_si128(tmp2, tmp0);
    tmp0 = _mm_xor_si128(tmp3, tmp0);
    tmp4 = _mm_slli_si128(tmp0, 8);
    tmp0 = _mm_srli_si128(tmp0, 8);
    *lo = _mm_xor_si128(tmp4, *lo);
    *hi = _mm_xor_si128(tmp0, *hi);
}

static void reduce8(__m128i H1, __m128i H2, __m128i H3, __m128i H4, __m128i H5, __m128i H6, __m128i H7, __m128i H8,
                    __m128i X1, __m128i X2, __m128i X3, __m128i X4, __m128i X5, __m128i X6, __m128i X7, __m128i X8, __m128i *res)
{

    const uint64_t c2 = (uint64_t)0xc2 << 56;
    __m128i POLY = _mm_loadl_epi64((__m128i *)&c2);
    __m128i lo1, hi1, lo, hi;
    __m128i tmp1, tmp2, tmp3, tmp4;
    multiply(H1, H2, H3, H4, X1, X2, X3, X4, &hi1, &lo1);
    multiply(H5, H6, H7, H8, X5, X6, X7, X8, &hi, &lo);
    tmp1 = _mm_xor_si128(lo, lo1);
    tmp4 = _mm_xor_si128(hi, hi1);
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78);
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78);
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    *res = _mm_xor_si128(tmp1, tmp4);
    return;
}

// multiply by 2, from PyCryptodome
static __m128i multx(__m128i a)
{
    int msb;
    int64_t r;
    uint64_t p0, p1;
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    msb = _mm_movemask_epi8(a) >> 15;          /* Bit 0 is a[127] */
    r = (msb ^ 1) - 1;                         /* MSB is copied into all 64 positions */
    p0 = (uint64_t)r & 0x0000000000000001U;    /* Zero or XOR mask (low) */
    p1 = (uint64_t)r & ((uint64_t)0xc2 << 56); /* Zero or XOR mask (high) */
    t0 = _mm_loadl_epi64((__m128i *)&p0);
    t1 = _mm_loadl_epi64((__m128i *)&p1);
    t2 = _mm_unpacklo_epi64(t0, t1); /* Zero or XOR mask */
    /* Shift value a left by 1 bit */
    t3 = _mm_slli_si128(a, 8);   /* Shift a left by 64 bits (lower 64 bits are zero) */
    t4 = _mm_srli_epi64(t3, 63); /* Bit 64 is now a[63], all other bits are 0 */
    t5 = _mm_slli_epi64(a, 1);   /* Shift left by 1 bit, but bit 64 is zero, not a[63] */
    t6 = _mm_or_si128(t4, t5);   /* Actual result of shift left by 1 bit */
    /* XOR conditional mask */
    t7 = _mm_xor_si128(t2, t6);
    return t7;
}

static inline void gfmul(__m128i a, __m128i b, __m128i *res)
{
    const uint64_t c2 = (uint64_t)0xc2 << 56;
    __m128i POLY = _mm_loadl_epi64((__m128i *)&c2);
    __m128i tmp1, tmp2, tmp3, tmp4;
    tmp1 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp2 = _mm_clmulepi64_si128(a, b, 0x11);
    tmp3 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp3 = _mm_xor_si128(tmp4, tmp3);
    tmp4 = _mm_slli_si128(tmp3, 8);
    tmp3 = _mm_srli_si128(tmp3, 8);
    tmp1 = _mm_xor_si128(tmp4, tmp1);
    tmp4 = _mm_xor_si128(tmp3, tmp2);
    /* Montgomery reduction */
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78); // 78 = 01001110b
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78); // 78 = 01001110b
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    *res = _mm_xor_si128(tmp1, tmp4);
}

// from Intel GCM Whitepaper
static void gfmul1(__m128i a, __m128i b, __m128i *res)
{
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);
    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);
    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);
    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);
    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    tmp6 = _mm_xor_si128(tmp6, tmp3);
    *res = tmp6;
}

#define ALIGN(n) __attribute__((aligned(n)))
void XCB_encrypt_1(const unsigned char *pt,
                   int pt_len,
                   const unsigned char *ad,
                   int ad_len,
                   unsigned char *ct,
                   ae_ctx *ctx);
void XCB_encrypt_2(const unsigned char *pt,
                   int pt_len,
                   const unsigned char *ad,
                   int ad_len,
                   unsigned char *ct,
                   ae_ctx *ctx);
void XCB_encrypt_4(const unsigned char *pt,
                   int pt_len,
                   const unsigned char *ad,
                   int ad_len,
                   unsigned char *ct,
                   ae_ctx *ctx);
void XCB_encrypt_8(const unsigned char *pt,
                   int pt_len,
                   const unsigned char *ad,
                   int ad_len,
                   unsigned char *ct,
                   ae_ctx *ctx);

struct _ae_ctx
{
    ALIGN(16)
    u8 K[16 * 15];
    ALIGN(16)
    u8 Ke[16 * 15];
    ALIGN(16)
    u8 Kd[16 * 15];
    ALIGN(16)
    u8 Kc[16 * 15];
    __m128i H;
};

int ae_init(ae_ctx *ctx,
            const void *key,
            int key_len,
            int nonce_len,
            int tag_len)
{
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    u8 zero[16], H1[16], Ke1[16], Kc1[16], Kd1[16];
    for (int i = 0; i < 16; i++)
    {
        zero[i] = 0;
    }
    AES_set_encrypt_key(key, 0, (AES_KEY *)ctx->K);
    AES_encrypt(zero, H1, (const AES_KEY *)ctx->K);
    ctx->H = _mm_loadu_si128(H1);
    ctx->H = _mm_shuffle_epi8(ctx->H, BSWAP_MASK);
    zero[15] = 1;
    AES_encrypt(zero, Ke1, ctx->K);
    AES_set_encrypt_key(Ke1, 0, (AES_KEY *)ctx->Ke);
    zero[15] = 3;
    AES_encrypt(zero, Kd1, ctx->K);
    AES_set_encrypt_key(Kd1, 0, (AES_KEY *)ctx->Kc);
    AES_NI_set_decrypt_key((__m128i *)ctx->Kd, (__m128i *)ctx->Kc);
    zero[15] = 5;
    AES_encrypt(zero, Kc1, ctx->K);
    AES_set_encrypt_key(Kc1, 0, (AES_KEY *)ctx->Kc);
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
    XCB_encrypt_1(pt, pt_len, ad, ad_len, ct, ctx);
#endif
#ifdef USE_AESNI_2
    XCB_encrypt_2(pt, pt_len, ad, ad_len, ct, ctx);
#endif
#ifdef USE_AESNI_4
    XCB_encrypt_4(pt, pt_len, ad, ad_len, ct, ctx);
#endif
#ifdef USE_AESNI_8
    XCB_encrypt_8(pt, pt_len, ad, ad_len, ct, ctx);
#endif
    return pt_len;
}

void XCB_encrypt_1(const unsigned char *pt,
                   int pt_len,
                   const unsigned char *ad,
                   int ad_len,
                   unsigned char *ct,
                   ae_ctx *ctx)
{
    __m128i C, D = _mm_setzero_si128(), tmp, ciphertext, F = _mm_setzero_si128();
    __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
    __m128i ctr = _mm_setzero_si128();
    __m128i len = _mm_setzero_si128();
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    int i, j;
    __m128i BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5,
                                       6, 7);
    C = _mm_loadu_si128(&((__m128i *)pt)[pt_len / 16 - 1]);
    __m128i *KEY = (__m128i *)ctx->Ke;
    C = _mm_xor_si128(C, KEY[0]);
    for (j = 1; j < 10; j++)
        C = _mm_aesenc_si128(C, KEY[j]);
    C = _mm_aesenclast_si128(C, KEY[10]);
    // hash1
    ctx->H = multx(ctx->H);
    for (i = 0; i < ad_len / 16; i++)
    {
        tmp = _mm_loadu_si128(&((__m128i *)ad)[i]);
        tmp = _mm_shuffle_epi8(tmp, BSWAP_MASK);
        D = D ^ tmp;
        gfmul(D, ctx->H, &D);
    }
    for (i = 0; i < pt_len / 16 - 1; i++)
    {
        tmp = _mm_loadu_si128(&((__m128i *)pt)[i]);
        tmp = _mm_shuffle_epi8(tmp, BSWAP_MASK);
        D = D ^ tmp;
        gfmul(D, ctx->H, &D);
    }
    gfmul(D, ctx->H, &D);
    tmp = _mm_insert_epi64(tmp, pt_len * 8, 0);
    tmp = _mm_insert_epi64(tmp, ad_len * 8 + 128, 1);
    D = D ^ tmp;
    gfmul(D, ctx->H, &D);
    D = _mm_shuffle_epi8(D, BSWAP_MASK);
    D = D ^ C;
    // ctr
    ctr = _mm_shuffle_epi8(D, BSWAP_EPI64);
    KEY = (__m128i *)ctx->Kc;
    for (i = 0; i < ad_len / 16; i++)
    {
        tmp = _mm_loadu_si128(&((__m128i *)ad)[i]);
        tmp = _mm_shuffle_epi8(tmp, BSWAP_MASK);
        F = F ^ tmp;
        gfmul(F, ctx->H, &F);
    }
    gfmul(F, ctx->H, &F);
    for (i = 0; i < pt_len / 16 - 1; i++)
    {
        tmp = _mm_shuffle_epi8(ctr, BSWAP_EPI64);
        ctr = _mm_add_epi64(ctr, ONE);
        tmp = _mm_xor_si128(tmp, KEY[0]);
        for (j = 1; j < 10; j++)
            tmp = _mm_aesenc_si128(tmp, KEY[j]);
        tmp = _mm_aesenclast_si128(tmp, KEY[10]);
        ciphertext = _mm_loadu_si128(&((__m128i *)pt)[i]);
        ciphertext = ciphertext ^ tmp;
        _mm_storeu_si128(&((__m128i *)ct)[i], ciphertext);
        tmp = _mm_shuffle_epi8(ciphertext, BSWAP_MASK);
        F = F ^ tmp;
        gfmul(F, ctx->H, &F);
    }
    // hash2
    tmp = _mm_insert_epi64(tmp, pt_len * 8 - 128, 0);
    tmp = _mm_insert_epi64(tmp, ad_len * 8 + 128, 1);
    F = F ^ tmp;
    gfmul(F, ctx->H, &F);
    tmp = _mm_insert_epi64(tmp, pt_len * 8, 0);
    F = F ^ tmp;
    gfmul(F, ctx->H, &F);
    F = _mm_shuffle_epi8(F, BSWAP_MASK);
    F = F ^ D;
    KEY = (__m128i *)ctx->Kd;
    F = _mm_xor_si128(F, KEY[0]);
    for (j = 1; j < 10; j++)
        F = _mm_aesdec_si128(F, KEY[j]);
    F = _mm_aesdeclast_si128(F, KEY[10]);
    _mm_storeu_si128(&((__m128i *)ct)[pt_len / 16 - 1], F);
}

void XCB_encrypt_2(const unsigned char *pt,
                   int pt_len,
                   const unsigned char *ad,
                   int ad_len,
                   unsigned char *ct,
                   ae_ctx *ctx)
{
    __m128i C, D = _mm_setzero_si128(), tmp1, tmp2, ciphertext, F = _mm_setzero_si128();
    __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
    __m128i TWO = _mm_set_epi32(0, 2, 0, 0);
    __m128i ctr1 = _mm_setzero_si128(), ctr2;
    __m128i len = _mm_setzero_si128();
    __m128i H1, H2;
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    int i;
    __m128i BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5,
                                       6, 7);
    H1 = ctx->H;
    gfmul1(H1, H1, &H2);
    H1 = multx(H1);
    H2 = multx(H2);
    C = _mm_loadu_si128(&((__m128i *)pt)[pt_len / 16 - 1]);
    __m128i *KEY = (__m128i *)ctx->Ke;
    C = _mm_xor_si128(C, KEY[0]);
    for (int j = 1; j < 10; j++)
        C = _mm_aesenc_si128(C, KEY[j]);
    C = _mm_aesenclast_si128(C, KEY[10]);
    // hash1
    for (i = 0; i < ad_len / 32; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i + 1]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(D, tmp1);
        reduce2(H1, H2, tmp2, tmp1, &D);
    }
    for (i = 2 * i; i < ad_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[i]), BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H1, &D);
    }
    for (i = 0; i < (pt_len - 16) / 32; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[4 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[4 * i + 1]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(D, tmp1);
        reduce2(H1, H2, tmp2, tmp1, &D);
    }
    for (i = 2 * i; i < pt_len / 16 - 1; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[i]), BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H1, &D);
    }
    gfmul(D, H1, &D);
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8, 0);
    tmp1 = _mm_insert_epi64(tmp1, ad_len * 8 + 128, 1);
    D = _mm_xor_si128(D, tmp1);
    gfmul(D, H1, &D);
    D = _mm_shuffle_epi8(D, BSWAP_MASK);
    D = _mm_xor_si128(D, C);
    // ctr
    KEY = (__m128i *)ctx->Kc;
    for (i = 0; i < ad_len / 32; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i + 1]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(F, tmp1);
        reduce2(H1, H2, tmp2, tmp1, &F);
    }
    for (i = 2 * i; i < ad_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[i]), BSWAP_MASK);
        F = _mm_xor_si128(F, tmp1);
        gfmul(F, H1, &F);
    }
    gfmul(F, H1, &F);
    ctr1 = _mm_shuffle_epi8(D, BSWAP_EPI64);
    ctr2 = _mm_add_epi64(ctr1, ONE);
    for (i = 0; i < (pt_len - 16) / 32; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
        tmp2 = _mm_shuffle_epi8(ctr2, BSWAP_EPI64);
        ctr1 = _mm_add_epi64(ctr1, TWO);
        ctr2 = _mm_add_epi64(ctr2, TWO);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        tmp2 = _mm_xor_si128(tmp2, KEY[0]);
        for (int j = 1; j < 10 - 1; j += 2)
        {
            tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
            tmp2 = _mm_aesenc_si128(tmp2, KEY[j]);

            tmp1 = _mm_aesenc_si128(tmp1, KEY[j + 1]);
            tmp2 = _mm_aesenc_si128(tmp2, KEY[j + 1]);
        }
        tmp1 = _mm_aesenc_si128(tmp1, KEY[10 - 1]);
        tmp2 = _mm_aesenc_si128(tmp2, KEY[10 - 1]);
        tmp1 = _mm_aesenclast_si128(tmp1, KEY[10]);
        tmp2 = _mm_aesenclast_si128(tmp2, KEY[10]);
        tmp1 = _mm_xor_si128(tmp1, _mm_load_si128(&((__m128i *)pt)[i * 2 + 0]));
        tmp2 = _mm_xor_si128(tmp2, _mm_load_si128(&((__m128i *)pt)[i * 2 + 1]));
        _mm_store_si128(&((__m128i *)ct)[i * 2 + 0], tmp1);
        _mm_store_si128(&((__m128i *)ct)[i * 2 + 1], tmp2);
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(tmp2, BSWAP_MASK);
        tmp1 = _mm_xor_si128(F, tmp1);
        reduce2(H1, H2, tmp2, tmp1, &F);
    }
    for (i = i * 2; i < pt_len / 16 - 1; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
        ctr1 = _mm_add_epi64(ctr1, ONE);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[1]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[2]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[3]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[4]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[5]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[6]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[7]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[8]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[9]);
        tmp1 = _mm_aesenclast_si128(tmp1, KEY[10]);
        tmp1 = _mm_xor_si128(tmp1, _mm_load_si128(&((__m128i *)pt)[i]));
        _mm_store_si128(&((__m128i *)ct)[i], tmp1);
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        F = _mm_xor_si128(F, tmp1);
        gfmul(F, H1, &F);
    }
    // hash2
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8 - 128, 0);
    tmp1 = _mm_insert_epi64(tmp1, ad_len * 8 + 128, 1);
    F = _mm_xor_si128(F, tmp1);
    gfmul(F, H1, &F);
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8, 0);
    F = _mm_xor_si128(F, tmp1);
    gfmul(F, H1, &F);
    F = _mm_shuffle_epi8(F, BSWAP_MASK);
    F = _mm_xor_si128(F, D);
    KEY = (__m128i *)ctx->Kd;
    F = _mm_xor_si128(F, KEY[0]);
    for (int j = 1; j < 10; j++)
        F = _mm_aesdec_si128(F, KEY[j]);
    F = _mm_aesdeclast_si128(F, KEY[10]);
    _mm_storeu_si128(&((__m128i *)ct)[pt_len / 16 - 1], F);
}

void XCB_encrypt_4(const unsigned char *pt,
                   int pt_len,
                   const unsigned char *ad,
                   int ad_len,
                   unsigned char *ct,
                   ae_ctx *ctx)
{
    __m128i C, D = _mm_setzero_si128(), tmp1, tmp2, tmp3, tmp4, ciphertext, F = _mm_setzero_si128();
    __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
    __m128i FOUR = _mm_set_epi32(0, 4, 0, 0);
    __m128i ctr1 = _mm_setzero_si128(), ctr2, ctr3, ctr4;
    __m128i len = _mm_setzero_si128();
    __m128i H1, H2, H3, H4;
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    int i;
    __m128i BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5,
                                       6, 7);
    H1 = ctx->H;
    gfmul1(H1, H1, &H2);
    gfmul1(H1, H2, &H3);
    gfmul1(H1, H3, &H4);
    H1 = multx(H1);
    H2 = multx(H2);
    H3 = multx(H3);
    H4 = multx(H4);
    C = _mm_loadu_si128(&((__m128i *)pt)[pt_len / 16 - 1]);
    __m128i *KEY = (__m128i *)ctx->Ke;
    C = _mm_xor_si128(C, KEY[0]);
    for (int j = 1; j < 10; j++)
        C = _mm_aesenc_si128(C, KEY[j]);
    C = _mm_aesenclast_si128(C, KEY[10]);
    // hash1
    for (i = 0; i < ad_len / 64; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i + 1]), BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i + 2]), BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i + 3]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(D, tmp1);
        reduce4(H1, H2, H3, H4, tmp4, tmp3, tmp2, tmp1, &D);
    }
    for (i = 4 * i; i < ad_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[i]), BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H1, &D);
    }
    for (i = 0; i < (pt_len - 16) / 64; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[4 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[4 * i + 1]), BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[4 * i + 2]), BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[4 * i + 3]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(D, tmp1);
        reduce4(H1, H2, H3, H4, tmp4, tmp3, tmp2, tmp1, &D);
    }
    for (i = 4 * i; i < pt_len / 16 - 1; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[i]), BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H1, &D);
    }
    gfmul(D, H1, &D);
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8, 0);
    tmp1 = _mm_insert_epi64(tmp1, ad_len * 8 + 128, 1);
    D = _mm_xor_si128(D, tmp1);
    gfmul(D, H1, &D);
    D = _mm_shuffle_epi8(D, BSWAP_MASK);
    D = _mm_xor_si128(D, C);
    // ctr
    KEY = (__m128i *)ctx->Kc;
    for (i = 0; i < ad_len / 64; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i + 1]), BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i + 2]), BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[4 * i + 3]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(F, tmp1);
        reduce4(H1, H2, H3, H4, tmp4, tmp3, tmp2, tmp1, &F);
    }
    for (i = 4 * i; i < ad_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[i]), BSWAP_MASK);
        F = _mm_xor_si128(F, tmp1);
        gfmul(F, H1, &F);
    }
    gfmul(F, H1, &F);
    ctr1 = _mm_shuffle_epi8(D, BSWAP_EPI64);
    ctr2 = _mm_add_epi64(ctr1, ONE);
    ctr3 = _mm_add_epi64(ctr2, ONE);
    ctr4 = _mm_add_epi64(ctr3, ONE);
    for (i = 0; i < (pt_len - 16) / 64; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
        tmp2 = _mm_shuffle_epi8(ctr2, BSWAP_EPI64);
        tmp3 = _mm_shuffle_epi8(ctr3, BSWAP_EPI64);
        tmp4 = _mm_shuffle_epi8(ctr4, BSWAP_EPI64);
        ctr1 = _mm_add_epi64(ctr1, FOUR);
        ctr2 = _mm_add_epi64(ctr2, FOUR);
        ctr3 = _mm_add_epi64(ctr3, FOUR);
        ctr4 = _mm_add_epi64(ctr4, FOUR);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        tmp2 = _mm_xor_si128(tmp2, KEY[0]);
        tmp3 = _mm_xor_si128(tmp3, KEY[0]);
        tmp4 = _mm_xor_si128(tmp4, KEY[0]);
        for (int j = 1; j < 10 - 1; j += 2)
        {
            tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
            tmp2 = _mm_aesenc_si128(tmp2, KEY[j]);
            tmp3 = _mm_aesenc_si128(tmp3, KEY[j]);
            tmp4 = _mm_aesenc_si128(tmp4, KEY[j]);

            tmp1 = _mm_aesenc_si128(tmp1, KEY[j + 1]);
            tmp2 = _mm_aesenc_si128(tmp2, KEY[j + 1]);
            tmp3 = _mm_aesenc_si128(tmp3, KEY[j + 1]);
            tmp4 = _mm_aesenc_si128(tmp4, KEY[j + 1]);
        }
        tmp1 = _mm_aesenc_si128(tmp1, KEY[10 - 1]);
        tmp2 = _mm_aesenc_si128(tmp2, KEY[10 - 1]);
        tmp3 = _mm_aesenc_si128(tmp3, KEY[10 - 1]);
        tmp4 = _mm_aesenc_si128(tmp4, KEY[10 - 1]);
        tmp1 = _mm_aesenclast_si128(tmp1, KEY[10]);
        tmp2 = _mm_aesenclast_si128(tmp2, KEY[10]);
        tmp3 = _mm_aesenclast_si128(tmp3, KEY[10]);
        tmp4 = _mm_aesenclast_si128(tmp4, KEY[10]);
        tmp1 = _mm_xor_si128(tmp1, _mm_load_si128(&((__m128i *)pt)[i * 4 + 0]));
        tmp2 = _mm_xor_si128(tmp2, _mm_load_si128(&((__m128i *)pt)[i * 4 + 1]));
        tmp3 = _mm_xor_si128(tmp3, _mm_load_si128(&((__m128i *)pt)[i * 4 + 2]));
        tmp4 = _mm_xor_si128(tmp4, _mm_load_si128(&((__m128i *)pt)[i * 4 + 3]));
        _mm_store_si128(&((__m128i *)ct)[i * 4 + 0], tmp1);
        _mm_store_si128(&((__m128i *)ct)[i * 4 + 1], tmp2);
        _mm_store_si128(&((__m128i *)ct)[i * 4 + 2], tmp3);
        _mm_store_si128(&((__m128i *)ct)[i * 4 + 3], tmp4);
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(tmp2, BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(tmp3, BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(tmp4, BSWAP_MASK);
        tmp1 = _mm_xor_si128(F, tmp1);
        reduce4(H1, H2, H3, H4, tmp4, tmp3, tmp2, tmp1, &F);
    }
    for (i = i * 4; i < pt_len / 16 - 1; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
        ctr1 = _mm_add_epi64(ctr1, ONE);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[1]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[2]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[3]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[4]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[5]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[6]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[7]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[8]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[9]);
        tmp1 = _mm_aesenclast_si128(tmp1, KEY[10]);
        tmp1 = _mm_xor_si128(tmp1, _mm_load_si128(&((__m128i *)pt)[i]));
        _mm_store_si128(&((__m128i *)ct)[i], tmp1);
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        F = _mm_xor_si128(F, tmp1);
        gfmul(F, H1, &F);
    }
    // hash2
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8 - 128, 0);
    tmp1 = _mm_insert_epi64(tmp1, ad_len * 8 + 128, 1);
    F = _mm_xor_si128(F, tmp1);
    gfmul(F, H1, &F);
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8, 0);
    F = _mm_xor_si128(F, tmp1);
    gfmul(F, H1, &F);
    F = _mm_shuffle_epi8(F, BSWAP_MASK);
    F = _mm_xor_si128(F, D);
    KEY = (__m128i *)ctx->Kd;
    F = _mm_xor_si128(F, KEY[0]);
    for (int j = 1; j < 10; j++)
        F = _mm_aesdec_si128(F, KEY[j]);
    F = _mm_aesdeclast_si128(F, KEY[10]);
    _mm_storeu_si128(&((__m128i *)ct)[pt_len / 16 - 1], F);
}

void XCB_encrypt_8(const unsigned char *pt,
                   int pt_len,
                   const unsigned char *ad,
                   int ad_len,
                   unsigned char *ct,
                   ae_ctx *ctx)
{
    __m128i C, D = _mm_setzero_si128(), tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, ciphertext, F = _mm_setzero_si128();
    __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
    __m128i EIGHT = _mm_set_epi32(0, 8, 0, 0);
    __m128i ctr1 = _mm_setzero_si128(), ctr2, ctr3, ctr4, ctr5, ctr6, ctr7, ctr8;
    __m128i len = _mm_setzero_si128();
    __m128i H1, H2, H3, H4, H5, H6, H7, H8;
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    int i;
    __m128i BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5,
                                       6, 7);
    H1 = ctx->H;
    gfmul1(H1, H1, &H2);
    gfmul1(H1, H2, &H3);
    gfmul1(H1, H3, &H4);
    gfmul1(H1, H4, &H5);
    gfmul1(H1, H5, &H6);
    gfmul1(H1, H6, &H7);
    gfmul1(H1, H7, &H8);
    H1 = multx(H1);
    H2 = multx(H2);
    H3 = multx(H3);
    H4 = multx(H4);
    H5 = multx(H5);
    H6 = multx(H6);
    H7 = multx(H7);
    H8 = multx(H8);
    C = _mm_loadu_si128(&((__m128i *)pt)[pt_len / 16 - 1]);
    __m128i *KEY = (__m128i *)ctx->Ke;
    C = _mm_xor_si128(C, KEY[0]);
    for (int j = 1; j < 10; j++)
        C = _mm_aesenc_si128(C, KEY[j]);
    C = _mm_aesenclast_si128(C, KEY[10]);
    // hash1
    for (i = 0; i < ad_len / 128; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 1]), BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 2]), BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 3]), BSWAP_MASK);
        tmp5 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 4]), BSWAP_MASK);
        tmp6 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 5]), BSWAP_MASK);
        tmp7 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 6]), BSWAP_MASK);
        tmp8 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 7]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(D, tmp1);
        reduce8(H1, H2, H3, H4, H5, H6, H7, H8, tmp8, tmp7, tmp6, tmp5, tmp4, tmp3, tmp2, tmp1, &D);
    }
    for (i = 8 * i; i < ad_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[i]), BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H1, &D);
    }
    for (i = 0; i < (pt_len - 16) / 128; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 1]), BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 2]), BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 3]), BSWAP_MASK);
        tmp5 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 4]), BSWAP_MASK);
        tmp6 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 5]), BSWAP_MASK);
        tmp7 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 6]), BSWAP_MASK);
        tmp8 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 7]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(D, tmp1);
        reduce8(H1, H2, H3, H4, H5, H6, H7, H8, tmp8, tmp7, tmp6, tmp5, tmp4, tmp3, tmp2, tmp1, &D);
    }
    for (i = 8 * i; i < pt_len / 16 - 1; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[i]), BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H1, &D);
    }
    gfmul(D, H1, &D);
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8, 0);
    tmp1 = _mm_insert_epi64(tmp1, ad_len * 8 + 128, 1);
    D = _mm_xor_si128(D, tmp1);
    gfmul(D, H1, &D);
    D = _mm_shuffle_epi8(D, BSWAP_MASK);
    D = _mm_xor_si128(D, C);
    // ctr
    KEY = (__m128i *)ctx->Kc;
    for (i = 0; i < ad_len / 128; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 1]), BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 2]), BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 3]), BSWAP_MASK);
        tmp5 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 4]), BSWAP_MASK);
        tmp6 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 5]), BSWAP_MASK);
        tmp7 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 6]), BSWAP_MASK);
        tmp8 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[8 * i + 7]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(F, tmp1);
        reduce8(H1, H2, H3, H4, H5, H6, H7, H8, tmp8, tmp7, tmp6, tmp5, tmp4, tmp3, tmp2, tmp1, &F);
    }
    for (i = 8 * i; i < ad_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ad)[i]), BSWAP_MASK);
        F = _mm_xor_si128(F, tmp1);
        gfmul(F, H1, &F);
    }
    gfmul(F, H1, &F);
    ctr1 = _mm_shuffle_epi8(D, BSWAP_EPI64);
    ctr2 = _mm_add_epi64(ctr1, ONE);
    ctr3 = _mm_add_epi64(ctr2, ONE);
    ctr4 = _mm_add_epi64(ctr3, ONE);
    ctr5 = _mm_add_epi64(ctr4, ONE);
    ctr6 = _mm_add_epi64(ctr5, ONE);
    ctr7 = _mm_add_epi64(ctr6, ONE);
    ctr8 = _mm_add_epi64(ctr7, ONE);
    for (i = 0; i < (pt_len - 16) / 128; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
        tmp2 = _mm_shuffle_epi8(ctr2, BSWAP_EPI64);
        tmp3 = _mm_shuffle_epi8(ctr3, BSWAP_EPI64);
        tmp4 = _mm_shuffle_epi8(ctr4, BSWAP_EPI64);
        tmp5 = _mm_shuffle_epi8(ctr5, BSWAP_EPI64);
        tmp6 = _mm_shuffle_epi8(ctr6, BSWAP_EPI64);
        tmp7 = _mm_shuffle_epi8(ctr7, BSWAP_EPI64);
        tmp8 = _mm_shuffle_epi8(ctr8, BSWAP_EPI64);
        ctr1 = _mm_add_epi64(ctr1, EIGHT);
        ctr2 = _mm_add_epi64(ctr2, EIGHT);
        ctr3 = _mm_add_epi64(ctr3, EIGHT);
        ctr4 = _mm_add_epi64(ctr4, EIGHT);
        ctr5 = _mm_add_epi64(ctr5, EIGHT);
        ctr6 = _mm_add_epi64(ctr6, EIGHT);
        ctr7 = _mm_add_epi64(ctr7, EIGHT);
        ctr8 = _mm_add_epi64(ctr8, EIGHT);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        tmp2 = _mm_xor_si128(tmp2, KEY[0]);
        tmp3 = _mm_xor_si128(tmp3, KEY[0]);
        tmp4 = _mm_xor_si128(tmp4, KEY[0]);
        tmp5 = _mm_xor_si128(tmp5, KEY[0]);
        tmp6 = _mm_xor_si128(tmp6, KEY[0]);
        tmp7 = _mm_xor_si128(tmp7, KEY[0]);
        tmp8 = _mm_xor_si128(tmp8, KEY[0]);
        for (int j = 1; j < 10 - 1; j += 2)
        {
            tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
            tmp2 = _mm_aesenc_si128(tmp2, KEY[j]);
            tmp3 = _mm_aesenc_si128(tmp3, KEY[j]);
            tmp4 = _mm_aesenc_si128(tmp4, KEY[j]);
            tmp5 = _mm_aesenc_si128(tmp5, KEY[j]);
            tmp6 = _mm_aesenc_si128(tmp6, KEY[j]);
            tmp7 = _mm_aesenc_si128(tmp7, KEY[j]);
            tmp8 = _mm_aesenc_si128(tmp8, KEY[j]);
            tmp1 = _mm_aesenc_si128(tmp1, KEY[j + 1]);
            tmp2 = _mm_aesenc_si128(tmp2, KEY[j + 1]);
            tmp3 = _mm_aesenc_si128(tmp3, KEY[j + 1]);
            tmp4 = _mm_aesenc_si128(tmp4, KEY[j + 1]);
            tmp5 = _mm_aesenc_si128(tmp5, KEY[j + 1]);
            tmp6 = _mm_aesenc_si128(tmp6, KEY[j + 1]);
            tmp7 = _mm_aesenc_si128(tmp7, KEY[j + 1]);
            tmp8 = _mm_aesenc_si128(tmp8, KEY[j + 1]);
        }
        tmp1 = _mm_aesenc_si128(tmp1, KEY[10 - 1]);
        tmp2 = _mm_aesenc_si128(tmp2, KEY[10 - 1]);
        tmp3 = _mm_aesenc_si128(tmp3, KEY[10 - 1]);
        tmp4 = _mm_aesenc_si128(tmp4, KEY[10 - 1]);
        tmp5 = _mm_aesenc_si128(tmp5, KEY[10 - 1]);
        tmp6 = _mm_aesenc_si128(tmp6, KEY[10 - 1]);
        tmp7 = _mm_aesenc_si128(tmp7, KEY[10 - 1]);
        tmp8 = _mm_aesenc_si128(tmp8, KEY[10 - 1]);
        tmp1 = _mm_aesenclast_si128(tmp1, KEY[10]);
        tmp2 = _mm_aesenclast_si128(tmp2, KEY[10]);
        tmp3 = _mm_aesenclast_si128(tmp3, KEY[10]);
        tmp4 = _mm_aesenclast_si128(tmp4, KEY[10]);
        tmp5 = _mm_aesenclast_si128(tmp5, KEY[10]);
        tmp6 = _mm_aesenclast_si128(tmp6, KEY[10]);
        tmp7 = _mm_aesenclast_si128(tmp7, KEY[10]);
        tmp8 = _mm_aesenclast_si128(tmp8, KEY[10]);
        tmp1 = _mm_xor_si128(tmp1, _mm_load_si128(&((__m128i *)pt)[i * 8 + 0]));
        tmp2 = _mm_xor_si128(tmp2, _mm_load_si128(&((__m128i *)pt)[i * 8 + 1]));
        tmp3 = _mm_xor_si128(tmp3, _mm_load_si128(&((__m128i *)pt)[i * 8 + 2]));
        tmp4 = _mm_xor_si128(tmp4, _mm_load_si128(&((__m128i *)pt)[i * 8 + 3]));
        tmp5 = _mm_xor_si128(tmp5, _mm_load_si128(&((__m128i *)pt)[i * 8 + 4]));
        tmp6 = _mm_xor_si128(tmp6, _mm_load_si128(&((__m128i *)pt)[i * 8 + 5]));
        tmp7 = _mm_xor_si128(tmp7, _mm_load_si128(&((__m128i *)pt)[i * 8 + 6]));
        tmp8 = _mm_xor_si128(tmp8, _mm_load_si128(&((__m128i *)pt)[i * 8 + 7]));
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 0], tmp1);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 1], tmp2);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 2], tmp3);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 3], tmp4);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 4], tmp5);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 5], tmp6);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 6], tmp7);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 7], tmp8);
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(tmp2, BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(tmp3, BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(tmp4, BSWAP_MASK);
        tmp5 = _mm_shuffle_epi8(tmp5, BSWAP_MASK);
        tmp6 = _mm_shuffle_epi8(tmp6, BSWAP_MASK);
        tmp7 = _mm_shuffle_epi8(tmp7, BSWAP_MASK);
        tmp8 = _mm_shuffle_epi8(tmp8, BSWAP_MASK);
        tmp1 = _mm_xor_si128(F, tmp1);
        reduce8(H1, H2, H3, H4, H5, H6, H7, H8, tmp8, tmp7, tmp6, tmp5, tmp4, tmp3, tmp2, tmp1, &F);
    }
    for (i = i * 8; i < pt_len / 16 - 1; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
        ctr1 = _mm_add_epi64(ctr1, ONE);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[1]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[2]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[3]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[4]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[5]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[6]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[7]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[8]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[9]);
        tmp1 = _mm_aesenclast_si128(tmp1, KEY[10]);
        tmp1 = _mm_xor_si128(tmp1, _mm_load_si128(&((__m128i *)pt)[i]));
        _mm_store_si128(&((__m128i *)ct)[i], tmp1);
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        F = _mm_xor_si128(F, tmp1);
        gfmul(F, H1, &F);
    }
    // hash2
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8 - 128, 0);
    tmp1 = _mm_insert_epi64(tmp1, ad_len * 8 + 128, 1);
    F = _mm_xor_si128(F, tmp1);
    gfmul(F, H1, &F);
    tmp1 = _mm_insert_epi64(tmp1, pt_len * 8, 0);
    F = _mm_xor_si128(F, tmp1);
    gfmul(F, H1, &F);
    F = _mm_shuffle_epi8(F, BSWAP_MASK);
    F = _mm_xor_si128(F, D);
    KEY = (__m128i *)ctx->Kd;
    F = _mm_xor_si128(F, KEY[0]);
    for (int j = 1; j < 10; j++)
        F = _mm_aesdec_si128(F, KEY[j]);
    F = _mm_aesdeclast_si128(F, KEY[10]);
    _mm_storeu_si128(&((__m128i *)ct)[pt_len / 16 - 1], F);
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