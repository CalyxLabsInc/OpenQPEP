/*
 * OpenQPEP Official Release 1.2.8 (v1.2.8) — Native C99 WOTS+ & XMSS Merkle Hypertree
 * Accelerator (QHS-512 over 24-round qSponge-512 / Keccak-f[1600]).
 *
 * Performance & Security Architecture:
 *   - 4-Way Interleaved SIMD-Vectorizable Keccak-f[1600] (`keccak_f1600_x4`):
 *     Processes 4 independent Winternitz chains simultaneously across uint64_t[4]
 *     (auto-vectorizes directly to 256-bit AVX2 YMM / 128-bit NEON registers under
 *     -O3 -mavx2/-march=armv8-a -ftree-vectorize with zero external dependencies).
 *   - Register-Resident 15-Step WOTS+ Chaining: Keeps all 4 x 256-bit chain states
 *     directly in canonical Keccak lanes across all 15 steps with zero intermediate copies.
 *   - Zero-Heap O(h)-Stack TreeHash (`openqpep_qhs_treehash_subtree`) & Top-Tree Folding
 *     (`openqpep_qhs_fold_subtrees`): Fully reentrant and thread-safe for arbitrary
 *     multi-core parallel subtree construction (height h <= 20 using < 1 KiB of stack).
 *   - Built-In Verify-Before-Emit Fault-Guard inside `openqpep_qhs_sign_core`
 *     (returns OPENQPEP_ERR_FAULT_GUARD on internal verification mismatch).
 *   - Compiler-barrier zeroization (`openqpep_explicit_bzero` / `openqpep_keccak_wipe`)
 *     of all secret seeds, WOTS+ secret chains, and Keccak states.
 *
 * Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
 */
#include "openqpep.h"
#include <string.h>
#if defined(__AVX2__)
#  include <immintrin.h>
#endif

#define QHS_ROTL64(x, s) (((uint64_t)(x) << (s)) | ((uint64_t)(x) >> (64U - (s))))

/* Immutable cryptographic domain-separation tags (NEVER modify across v1.x releases) */
static const uint8_t DOMAIN_QHS_CHAIN[]   = "CALYX-QHS-CHAIN|";
static const uint8_t DOMAIN_QHS_WOTS_SK[] = "CALYX-QHS-WOTS-SK|";
static const uint8_t DOMAIN_QHS_WOTS_PK[] = "CALYX-QHS-WOTS-PK|";
static const uint8_t DOMAIN_QHS_NODE[]    = "CALYX-QHS-NODE|";
static const uint8_t DOMAIN_QHS_HEDGE[]   = "CALYX-QHS-HEDGE-v1.1.4|";
static const uint8_t DOMAIN_QHS_DET[]     = "CALYX-QHS-DET-v1.1.4|";
static const uint8_t DOMAIN_QHS_MSG[]     = "CALYX-QHS-MSG|";

static const uint64_t QHS_KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static inline uint64_t qhs_load64_le(const uint8_t *p) {
    return ((uint64_t)p[0])       |
           ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static inline void qhs_store64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
    p[4] = (uint8_t)((v >> 32) & 0xFFU);
    p[5] = (uint8_t)((v >> 40) & 0xFFU);
    p[6] = (uint8_t)((v >> 48) & 0xFFU);
    p[7] = (uint8_t)((v >> 56) & 0xFFU);
}

static inline void qhs_store32_be(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)((v >> 24) & 0xFFU);
    out[1] = (uint8_t)((v >> 16) & 0xFFU);
    out[2] = (uint8_t)((v >> 8) & 0xFFU);
    out[3] = (uint8_t)(v & 0xFFU);
}

static inline uint32_t qhs_load32_be(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  |
           ((uint32_t)in[3]);
}

/*
 * 4-Way Interleaved SIMD 24-Round Keccak-f[1600] Permutation.
 * Uses hardware 256-bit AVX2 (__m256i) when compiled with -mavx2, with a clean
 * portable ISO C99 fallback for ARM64/NEON and PORTABLE=1 builds.
 */
#if defined(__AVX2__)

#define QHS_AVX2_XOR(a, b)    _mm256_xor_si256((a), (b))
#define QHS_AVX2_XOR5(a,b,c,d,e) QHS_AVX2_XOR(QHS_AVX2_XOR(QHS_AVX2_XOR((a),(b)), QHS_AVX2_XOR((c),(d))), (e))
#define QHS_AVX2_ROTL(x, s)   _mm256_or_si256(_mm256_slli_epi64((x), (s)), _mm256_srli_epi64((x), 64 - (s)))
#define QHS_AVX2_CHI(a, b, c) _mm256_xor_si256((a), _mm256_andnot_si256((b), (c)))

static void keccak_f1600_x4_avx2_regs(__m256i s[25]) {
    for (int round = 0; round < 24; round += 2) {
        __m256i c0, c1, c2, c3, c4;
        __m256i d0, d1, d2, d3, d4;
        __m256i b0, b1, b2, b3, b4;
        __m256i e[25];

        /* Round (round + 0): s -> e */
        c0 = QHS_AVX2_XOR5(s[ 0], s[ 5], s[10], s[15], s[20]);
        c1 = QHS_AVX2_XOR5(s[ 1], s[ 6], s[11], s[16], s[21]);
        c2 = QHS_AVX2_XOR5(s[ 2], s[ 7], s[12], s[17], s[22]);
        c3 = QHS_AVX2_XOR5(s[ 3], s[ 8], s[13], s[18], s[23]);
        c4 = QHS_AVX2_XOR5(s[ 4], s[ 9], s[14], s[19], s[24]);

        d0 = QHS_AVX2_XOR(c4, QHS_AVX2_ROTL(c1, 1));
        d1 = QHS_AVX2_XOR(c0, QHS_AVX2_ROTL(c2, 1));
        d2 = QHS_AVX2_XOR(c1, QHS_AVX2_ROTL(c3, 1));
        d3 = QHS_AVX2_XOR(c2, QHS_AVX2_ROTL(c4, 1));
        d4 = QHS_AVX2_XOR(c3, QHS_AVX2_ROTL(c0, 1));

        b0 = QHS_AVX2_XOR(s[ 0], d0);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 6], d1), 44);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[12], d2), 43);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[18], d3), 21);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[24], d4), 14);
        e[ 0] = QHS_AVX2_XOR(QHS_AVX2_CHI(b0, b1, b2), _mm256_set1_epi64x((long long)QHS_KECCAK_RC[round]));
        e[ 1] = QHS_AVX2_CHI(b1, b2, b3);
        e[ 2] = QHS_AVX2_CHI(b2, b3, b4);
        e[ 3] = QHS_AVX2_CHI(b3, b4, b0);
        e[ 4] = QHS_AVX2_CHI(b4, b0, b1);

        b0 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 3], d3), 28);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 9], d4), 20);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[10], d0),  3);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[16], d1), 45);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[22], d2), 61);
        e[ 5] = QHS_AVX2_CHI(b0, b1, b2);
        e[ 6] = QHS_AVX2_CHI(b1, b2, b3);
        e[ 7] = QHS_AVX2_CHI(b2, b3, b4);
        e[ 8] = QHS_AVX2_CHI(b3, b4, b0);
        e[ 9] = QHS_AVX2_CHI(b4, b0, b1);

        b0 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 1], d1),  1);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 7], d2),  6);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[13], d3), 25);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[19], d4),  8);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[20], d0), 18);
        e[10] = QHS_AVX2_CHI(b0, b1, b2);
        e[11] = QHS_AVX2_CHI(b1, b2, b3);
        e[12] = QHS_AVX2_CHI(b2, b3, b4);
        e[13] = QHS_AVX2_CHI(b3, b4, b0);
        e[14] = QHS_AVX2_CHI(b4, b0, b1);

        b0 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 4], d4), 27);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 5], d0), 36);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[11], d1), 10);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[17], d2), 15);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[23], d3), 56);
        e[15] = QHS_AVX2_CHI(b0, b1, b2);
        e[16] = QHS_AVX2_CHI(b1, b2, b3);
        e[17] = QHS_AVX2_CHI(b2, b3, b4);
        e[18] = QHS_AVX2_CHI(b3, b4, b0);
        e[19] = QHS_AVX2_CHI(b4, b0, b1);

        b0 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 2], d2), 62);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[ 8], d3), 55);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[14], d4), 39);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[15], d0), 41);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(s[21], d1),  2);
        e[20] = QHS_AVX2_CHI(b0, b1, b2);
        e[21] = QHS_AVX2_CHI(b1, b2, b3);
        e[22] = QHS_AVX2_CHI(b2, b3, b4);
        e[23] = QHS_AVX2_CHI(b3, b4, b0);
        e[24] = QHS_AVX2_CHI(b4, b0, b1);

        /* Round (round + 1): e -> s */
        c0 = QHS_AVX2_XOR5(e[ 0], e[ 5], e[10], e[15], e[20]);
        c1 = QHS_AVX2_XOR5(e[ 1], e[ 6], e[11], e[16], e[21]);
        c2 = QHS_AVX2_XOR5(e[ 2], e[ 7], e[12], e[17], e[22]);
        c3 = QHS_AVX2_XOR5(e[ 3], e[ 8], e[13], e[18], e[23]);
        c4 = QHS_AVX2_XOR5(e[ 4], e[ 9], e[14], e[19], e[24]);

        d0 = QHS_AVX2_XOR(c4, QHS_AVX2_ROTL(c1, 1));
        d1 = QHS_AVX2_XOR(c0, QHS_AVX2_ROTL(c2, 1));
        d2 = QHS_AVX2_XOR(c1, QHS_AVX2_ROTL(c3, 1));
        d3 = QHS_AVX2_XOR(c2, QHS_AVX2_ROTL(c4, 1));
        d4 = QHS_AVX2_XOR(c3, QHS_AVX2_ROTL(c0, 1));

        b0 = QHS_AVX2_XOR(e[ 0], d0);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 6], d1), 44);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[12], d2), 43);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[18], d3), 21);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[24], d4), 14);
        s[ 0] = QHS_AVX2_XOR(QHS_AVX2_CHI(b0, b1, b2), _mm256_set1_epi64x((long long)QHS_KECCAK_RC[round + 1]));
        s[ 1] = QHS_AVX2_CHI(b1, b2, b3);
        s[ 2] = QHS_AVX2_CHI(b2, b3, b4);
        s[ 3] = QHS_AVX2_CHI(b3, b4, b0);
        s[ 4] = QHS_AVX2_CHI(b4, b0, b1);

        b0 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 3], d3), 28);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 9], d4), 20);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[10], d0),  3);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[16], d1), 45);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[22], d2), 61);
        s[ 5] = QHS_AVX2_CHI(b0, b1, b2);
        s[ 6] = QHS_AVX2_CHI(b1, b2, b3);
        s[ 7] = QHS_AVX2_CHI(b2, b3, b4);
        s[ 8] = QHS_AVX2_CHI(b3, b4, b0);
        s[ 9] = QHS_AVX2_CHI(b4, b0, b1);

        b0 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 1], d1),  1);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 7], d2),  6);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[13], d3), 25);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[19], d4),  8);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[20], d0), 18);
        s[10] = QHS_AVX2_CHI(b0, b1, b2);
        s[11] = QHS_AVX2_CHI(b1, b2, b3);
        s[12] = QHS_AVX2_CHI(b2, b3, b4);
        s[13] = QHS_AVX2_CHI(b3, b4, b0);
        s[14] = QHS_AVX2_CHI(b4, b0, b1);

        b0 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 4], d4), 27);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 5], d0), 36);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[11], d1), 10);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[17], d2), 15);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[23], d3), 56);
        s[15] = QHS_AVX2_CHI(b0, b1, b2);
        s[16] = QHS_AVX2_CHI(b1, b2, b3);
        s[17] = QHS_AVX2_CHI(b2, b3, b4);
        s[18] = QHS_AVX2_CHI(b3, b4, b0);
        s[19] = QHS_AVX2_CHI(b4, b0, b1);

        b0 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 2], d2), 62);
        b1 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[ 8], d3), 55);
        b2 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[14], d4), 39);
        b3 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[15], d0), 41);
        b4 = QHS_AVX2_ROTL(QHS_AVX2_XOR(e[21], d1),  2);
        s[20] = QHS_AVX2_CHI(b0, b1, b2);
        s[21] = QHS_AVX2_CHI(b1, b2, b3);
        s[22] = QHS_AVX2_CHI(b2, b3, b4);
        s[23] = QHS_AVX2_CHI(b3, b4, b0);
        s[24] = QHS_AVX2_CHI(b4, b0, b1);
    }
}

static void keccak_f1600_x4(uint64_t A[25][4]) {
    __m256i s[25];
    for (int i = 0; i < 25; i++) {
        s[i] = _mm256_loadu_si256((const __m256i *)(const void *)A[i]);
    }
    keccak_f1600_x4_avx2_regs(s);
    for (int i = 0; i < 25; i++) {
        _mm256_storeu_si256((__m256i *)(void *)A[i], s[i]);
    }
}

#else

#define QHS_KECCAK_ROUND_X4(SRC, DST, RC_VAL) do {                                   \
    uint64_t C0[4], C1[4], C2[4], C3[4], C4[4];                                      \
    uint64_t D0[4], D1[4], D2[4], D3[4], D4[4];                                      \
    for (int k = 0; k < 4; k++) {                                                    \
        C0[k] = (SRC)[ 0][k] ^ (SRC)[ 5][k] ^ (SRC)[10][k] ^ (SRC)[15][k] ^ (SRC)[20][k]; \
        C1[k] = (SRC)[ 1][k] ^ (SRC)[ 6][k] ^ (SRC)[11][k] ^ (SRC)[16][k] ^ (SRC)[21][k]; \
        C2[k] = (SRC)[ 2][k] ^ (SRC)[ 7][k] ^ (SRC)[12][k] ^ (SRC)[17][k] ^ (SRC)[22][k]; \
        C3[k] = (SRC)[ 3][k] ^ (SRC)[ 8][k] ^ (SRC)[13][k] ^ (SRC)[18][k] ^ (SRC)[23][k]; \
        C4[k] = (SRC)[ 4][k] ^ (SRC)[ 9][k] ^ (SRC)[14][k] ^ (SRC)[19][k] ^ (SRC)[24][k]; \
        D0[k] = C4[k] ^ QHS_ROTL64(C1[k], 1U);                                       \
        D1[k] = C0[k] ^ QHS_ROTL64(C2[k], 1U);                                       \
        D2[k] = C1[k] ^ QHS_ROTL64(C3[k], 1U);                                       \
        D3[k] = C2[k] ^ QHS_ROTL64(C4[k], 1U);                                       \
        D4[k] = C3[k] ^ QHS_ROTL64(C0[k], 1U);                                       \
    }                                                                                \
    for (int k = 0; k < 4; k++) {                                                    \
        uint64_t b0 = (SRC)[ 0][k] ^ D0[k];                                          \
        uint64_t b1 = QHS_ROTL64((SRC)[ 6][k] ^ D1[k], 44U);                         \
        uint64_t b2 = QHS_ROTL64((SRC)[12][k] ^ D2[k], 43U);                         \
        uint64_t b3 = QHS_ROTL64((SRC)[18][k] ^ D3[k], 21U);                         \
        uint64_t b4 = QHS_ROTL64((SRC)[24][k] ^ D4[k], 14U);                         \
        (DST)[ 0][k] = b0 ^ ((~b1) & b2) ^ (RC_VAL);                                 \
        (DST)[ 1][k] = b1 ^ ((~b2) & b3);                                            \
        (DST)[ 2][k] = b2 ^ ((~b3) & b4);                                            \
        (DST)[ 3][k] = b3 ^ ((~b4) & b0);                                            \
        (DST)[ 4][k] = b4 ^ ((~b0) & b1);                                            \
    }                                                                                \
    for (int k = 0; k < 4; k++) {                                                    \
        uint64_t b0 = QHS_ROTL64((SRC)[ 3][k] ^ D3[k], 28U);                         \
        uint64_t b1 = QHS_ROTL64((SRC)[ 9][k] ^ D4[k], 20U);                         \
        uint64_t b2 = QHS_ROTL64((SRC)[10][k] ^ D0[k],  3U);                         \
        uint64_t b3 = QHS_ROTL64((SRC)[16][k] ^ D1[k], 45U);                         \
        uint64_t b4 = QHS_ROTL64((SRC)[22][k] ^ D2[k], 61U);                         \
        (DST)[ 5][k] = b0 ^ ((~b1) & b2);                                            \
        (DST)[ 6][k] = b1 ^ ((~b2) & b3);                                            \
        (DST)[ 7][k] = b2 ^ ((~b3) & b4);                                            \
        (DST)[ 8][k] = b3 ^ ((~b4) & b0);                                            \
        (DST)[ 9][k] = b4 ^ ((~b0) & b1);                                            \
    }                                                                                \
    for (int k = 0; k < 4; k++) {                                                    \
        uint64_t b0 = QHS_ROTL64((SRC)[ 1][k] ^ D1[k],  1U);                         \
        uint64_t b1 = QHS_ROTL64((SRC)[ 7][k] ^ D2[k],  6U);                         \
        uint64_t b2 = QHS_ROTL64((SRC)[13][k] ^ D3[k], 25U);                         \
        uint64_t b3 = QHS_ROTL64((SRC)[19][k] ^ D4[k],  8U);                         \
        uint64_t b4 = QHS_ROTL64((SRC)[20][k] ^ D0[k], 18U);                         \
        (DST)[10][k] = b0 ^ ((~b1) & b2);                                            \
        (DST)[11][k] = b1 ^ ((~b2) & b3);                                            \
        (DST)[12][k] = b2 ^ ((~b3) & b4);                                            \
        (DST)[13][k] = b3 ^ ((~b4) & b0);                                            \
        (DST)[14][k] = b4 ^ ((~b0) & b1);                                            \
    }                                                                                \
    for (int k = 0; k < 4; k++) {                                                    \
        uint64_t b0 = QHS_ROTL64((SRC)[ 4][k] ^ D4[k], 27U);                         \
        uint64_t b1 = QHS_ROTL64((SRC)[ 5][k] ^ D0[k], 36U);                         \
        uint64_t b2 = QHS_ROTL64((SRC)[11][k] ^ D1[k], 10U);                         \
        uint64_t b3 = QHS_ROTL64((SRC)[17][k] ^ D2[k], 15U);                         \
        uint64_t b4 = QHS_ROTL64((SRC)[23][k] ^ D3[k], 56U);                         \
        (DST)[15][k] = b0 ^ ((~b1) & b2);                                            \
        (DST)[16][k] = b1 ^ ((~b2) & b3);                                            \
        (DST)[17][k] = b2 ^ ((~b3) & b4);                                            \
        (DST)[18][k] = b3 ^ ((~b4) & b0);                                            \
        (DST)[19][k] = b4 ^ ((~b0) & b1);                                            \
    }                                                                                \
    for (int k = 0; k < 4; k++) {                                                    \
        uint64_t b0 = QHS_ROTL64((SRC)[ 2][k] ^ D2[k], 62U);                         \
        uint64_t b1 = QHS_ROTL64((SRC)[ 8][k] ^ D3[k], 55U);                         \
        uint64_t b2 = QHS_ROTL64((SRC)[14][k] ^ D4[k], 39U);                         \
        uint64_t b3 = QHS_ROTL64((SRC)[15][k] ^ D0[k], 41U);                         \
        uint64_t b4 = QHS_ROTL64((SRC)[21][k] ^ D1[k],  2U);                         \
        (DST)[20][k] = b0 ^ ((~b1) & b2);                                            \
        (DST)[21][k] = b1 ^ ((~b2) & b3);                                            \
        (DST)[22][k] = b2 ^ ((~b3) & b4);                                            \
        (DST)[23][k] = b3 ^ ((~b4) & b0);                                            \
        (DST)[24][k] = b4 ^ ((~b0) & b1);                                            \
    }                                                                                \
} while (0)

static void keccak_f1600_x4(uint64_t A[25][4]) {
    uint64_t E[25][4];
    for (int round = 0; round < 24; round += 2) {
        QHS_KECCAK_ROUND_X4(A, E, QHS_KECCAK_RC[round]);
        QHS_KECCAK_ROUND_X4(E, A, QHS_KECCAK_RC[round + 1]);
    }
    openqpep_explicit_bzero(E, sizeof(E));
}

#endif /* defined(__AVX2__) */

/* Convert 32-byte digest into 67 base-16 WOTS+ digits (64 payload + 3 checksum). */
static void qhs_msg_to_base_w(const uint8_t msg_digest32[32], uint8_t digits[OPENQPEP_QHS_WOTS_LEN]) {
    uint32_t csum = 0U;
    for (uint32_t i = 0U; i < 32U; i++) {
        uint8_t hi = (uint8_t)((msg_digest32[i] >> 4) & 0x0FU);
        uint8_t lo = (uint8_t)(msg_digest32[i] & 0x0FU);
        digits[2U * i] = hi;
        digits[2U * i + 1U] = lo;
        csum += (15U - (uint32_t)hi) + (15U - (uint32_t)lo);
    }
    digits[64] = (uint8_t)((csum >> 8) & 0x0FU);
    digits[65] = (uint8_t)((csum >> 4) & 0x0FU);
    digits[66] = (uint8_t)(csum & 0x0FU);
}

/* Internal Merkle parent node hash: SHA3-512("CALYX-QHS-NODE|" || pub_seed || left || right)[:32] */
static int qhs_hash_node(
    const uint8_t pub_seed32[32],
    const uint8_t left32[32],
    const uint8_t right32[32],
    uint8_t out32[32]
) {
    uint64_t st[25];
    uint8_t blk0[72];
    uint8_t blk1[72];

    /* 15 + 32 + 32 + 32 = 111 bytes -> Block 0 (72 B) + Block 1 (39 B) */
    memcpy(blk0, DOMAIN_QHS_NODE, 15U);
    memcpy(blk0 + 15U, pub_seed32, 32U);
    memcpy(blk0 + 47U, left32, 25U);

    memset(blk1, 0, sizeof(blk1));
    memcpy(blk1, left32 + 25U, 7U);
    memcpy(blk1 + 7U, right32, 32U);
    blk1[39] = (uint8_t)OPENQPEP_SHA3_DOMAIN_SEP;
    blk1[71] |= 0x80U;

    memset(st, 0, sizeof(st));
    for (int i = 0; i < 9; i++) {
        st[i] = qhs_load64_le(blk0 + i * 8);
    }
    openqpep_keccak_f1600(st);
    for (int i = 0; i < 9; i++) {
        st[i] ^= qhs_load64_le(blk1 + i * 8);
    }
    openqpep_keccak_f1600(st);

    qhs_store64_le(out32 +  0U, st[0]);
    qhs_store64_le(out32 +  8U, st[1]);
    qhs_store64_le(out32 + 16U, st[2]);
    qhs_store64_le(out32 + 24U, st[3]);

    openqpep_explicit_bzero(st, sizeof(st));
    openqpep_explicit_bzero(blk0, sizeof(blk0));
    openqpep_explicit_bzero(blk1, sizeof(blk1));
    return OPENQPEP_OK;
}

/*
 * 4-Way WOTS+ Secret Key Derivation:
 * Computes sk_i = SHAKE-256("CALYX-QHS-WOTS-SK|" || sk_seed || BE32(leaf_idx) || BE16(c_idx[k]), 32)
 * for k in 0..3 in a single 4-way Keccak-f[1600] permutation, returning lanes in v0..v3.
 */
static void qhs_wots_sk_x4(
    const uint64_t sk_prefix6[6],
    const uint8_t sk_tail6[6],
    const uint16_t chain_idx[4],
    uint64_t v0[4],
    uint64_t v1[4],
    uint64_t v2[4],
    uint64_t v3[4]
) {
    uint64_t A[25][4];
    memset(A, 0, sizeof(A));

    for (int l = 0; l < 6; l++) {
        uint64_t p = sk_prefix6[l];
        A[l][0] = p; A[l][1] = p; A[l][2] = p; A[l][3] = p;
    }

    /* Lane 6 = bytes 48..55: sk_seed[30..31] (2 B) || BE32(leaf_idx) (4 B) || BE16(chain_idx[k]) (2 B) */
    uint64_t base_l6 = ((uint64_t)sk_tail6[0])       |
                       ((uint64_t)sk_tail6[1] << 8)  |
                       ((uint64_t)sk_tail6[2] << 16) |
                       ((uint64_t)sk_tail6[3] << 24) |
                       ((uint64_t)sk_tail6[4] << 32) |
                       ((uint64_t)sk_tail6[5] << 40);
    for (int k = 0; k < 4; k++) {
        uint64_t c_hi = (uint64_t)((chain_idx[k] >> 8) & 0xFFU);
        uint64_t c_lo = (uint64_t)(chain_idx[k] & 0xFFU);
        A[6][k] = base_l6 | (c_hi << 48) | (c_lo << 56);
        A[7][k] = (uint64_t)OPENQPEP_SHAKE_DOMAIN_SEP; /* byte 56 = 0x1F */
        A[16][k] = 0x8000000000000000ULL;              /* byte 135 = 0x80 */
    }

    keccak_f1600_x4(A);

    for (int k = 0; k < 4; k++) {
        v0[k] = A[0][k];
        v1[k] = A[1][k];
        v2[k] = A[2][k];
        v3[k] = A[3][k];
    }
    openqpep_explicit_bzero(A, sizeof(A));
}

/* ------------------------------------------------------------------------- */
/* Public QHS-512 C99 API Functions                                          */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_qhs_wots_chain(
    const uint8_t in32[32],
    uint32_t start,
    uint32_t steps,
    const uint8_t pub_seed32[32],
    uint32_t leaf_idx,
    uint16_t chain_idx,
    uint8_t out32[32]
) {
    if (!in32 || !pub_seed32 || !out32) return OPENQPEP_ERR_NULL_PTR;
    if (chain_idx >= OPENQPEP_QHS_WOTS_LEN) return OPENQPEP_ERR_INVALID_LEN;
    if (start > 15U || steps > 15U || start + steps > 15U) return OPENQPEP_ERR_INVALID_LEN;

    uint64_t v0 = qhs_load64_le(in32 +  0U);
    uint64_t v1 = qhs_load64_le(in32 +  8U);
    uint64_t v2 = qhs_load64_le(in32 + 16U);
    uint64_t v3 = qhs_load64_le(in32 + 24U);

    if (steps > 0U) {
        /* Prefix lanes 0..5 = "CALYX-QHS-CHAIN|" (16 B) || pub_seed32 (32 B) = 48 B */
        uint64_t p0 = qhs_load64_le(DOMAIN_QHS_CHAIN + 0U);
        uint64_t p1 = qhs_load64_le(DOMAIN_QHS_CHAIN + 8U);
        uint64_t p2 = qhs_load64_le(pub_seed32 +  0U);
        uint64_t p3 = qhs_load64_le(pub_seed32 +  8U);
        uint64_t p4 = qhs_load64_le(pub_seed32 + 16U);
        uint64_t p5 = qhs_load64_le(pub_seed32 + 24U);

        uint8_t meta[6];
        qhs_store32_be(meta, leaf_idx);
        meta[4] = (uint8_t)((chain_idx >> 8) & 0xFFU);
        meta[5] = (uint8_t)(chain_idx & 0xFFU);
        uint64_t l6_base = ((uint64_t)meta[0])       |
                           ((uint64_t)meta[1] << 8)  |
                           ((uint64_t)meta[2] << 16) |
                           ((uint64_t)meta[3] << 24) |
                           ((uint64_t)meta[4] << 32) |
                           ((uint64_t)meta[5] << 40);

        uint64_t st[25];
        for (uint32_t s = start; s < start + steps; s++) {
            memset(st, 0, sizeof(st));
            st[0] = p0;
            st[1] = p1;
            st[2] = p2;
            st[3] = p3;
            st[4] = p4;
            st[5] = p5;
            st[6] = l6_base | ((uint64_t)(s & 0xFFU) << 48) | ((v0 & 0xFFULL) << 56);
            st[7] = (v0 >> 8) | (v1 << 56);
            st[8] = (v1 >> 8) | (v2 << 56);
            openqpep_keccak_f1600(st);

            st[0] ^= (v2 >> 8) | (v3 << 56);
            st[1] ^= (v3 >> 8) | ((uint64_t)OPENQPEP_SHA3_DOMAIN_SEP << 56);
            st[8] ^= 0x8000000000000000ULL;
            openqpep_keccak_f1600(st);

            v0 = st[0];
            v1 = st[1];
            v2 = st[2];
            v3 = st[3];
        }
        openqpep_explicit_bzero(st, sizeof(st));
    }

    qhs_store64_le(out32 +  0U, v0);
    qhs_store64_le(out32 +  8U, v1);
    qhs_store64_le(out32 + 16U, v2);
    qhs_store64_le(out32 + 24U, v3);
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qhs_wots_pk_from_sk_seed(
    const uint8_t sk_seed32[32],
    const uint8_t pub_seed32[32],
    uint32_t leaf_idx,
    uint8_t leaf_pk32_out[32]
) {
    if (!sk_seed32 || !pub_seed32 || !leaf_pk32_out) return OPENQPEP_ERR_NULL_PTR;

    /* Prepare shared SK prefix (bytes 0..47 = "CALYX-QHS-WOTS-SK|" || sk_seed[0..29]) */
    uint8_t sk_hdr[48];
    memcpy(sk_hdr, DOMAIN_QHS_WOTS_SK, 18U);
    memcpy(sk_hdr + 18U, sk_seed32, 30U);
    uint64_t sk_prefix6[6];
    for (int l = 0; l < 6; l++) {
        sk_prefix6[l] = qhs_load64_le(sk_hdr + l * 8);
    }
    uint8_t sk_tail6[6];
    sk_tail6[0] = sk_seed32[30];
    sk_tail6[1] = sk_seed32[31];
    qhs_store32_be(sk_tail6 + 2U, leaf_idx);

    /* Prepare shared CHAIN prefix (bytes 0..47 = "CALYX-QHS-CHAIN|" || pub_seed32) */
    uint64_t ch_p0 = qhs_load64_le(DOMAIN_QHS_CHAIN + 0U);
    uint64_t ch_p1 = qhs_load64_le(DOMAIN_QHS_CHAIN + 8U);
    uint64_t ch_p2 = qhs_load64_le(pub_seed32 +  0U);
    uint64_t ch_p3 = qhs_load64_le(pub_seed32 +  8U);
    uint64_t ch_p4 = qhs_load64_le(pub_seed32 + 16U);
    uint64_t ch_p5 = qhs_load64_le(pub_seed32 + 24U);

    uint8_t leaf_be[4];
    qhs_store32_be(leaf_be, leaf_idx);
    uint64_t leaf_l6 = ((uint64_t)leaf_be[0])       |
                       ((uint64_t)leaf_be[1] << 8)  |
                       ((uint64_t)leaf_be[2] << 16) |
                       ((uint64_t)leaf_be[3] << 24);

    /* Stream all 67 chain endpoints directly into CALYX-QHS-WOTS-PK| SHA3-512 context */
    openqpep_keccak_ctx_t pk_ctx;
    int rc = openqpep_sha3_512_init(&pk_ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&pk_ctx, DOMAIN_QHS_WOTS_PK, sizeof(DOMAIN_QHS_WOTS_PK) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&pk_ctx, pub_seed32, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&pk_ctx, leaf_be, 4U);

    uint64_t v0[4], v1[4], v2[4], v3[4];
    uint8_t tips[4 * 32];
#if !defined(__AVX2__)
    uint64_t A[25][4];
#endif

    for (uint32_t base = 0U; rc == OPENQPEP_OK && base < OPENQPEP_QHS_WOTS_LEN; base += 4U) {
        uint32_t lanes = OPENQPEP_QHS_WOTS_LEN - base;
        if (lanes > 4U) lanes = 4U;

        uint16_t cidx[4];
        uint64_t l6_base[4];
        for (uint32_t k = 0U; k < 4U; k++) {
            uint16_t ci = (uint16_t)((base + k < OPENQPEP_QHS_WOTS_LEN) ? (base + k) : (OPENQPEP_QHS_WOTS_LEN - 1U));
            cidx[k] = ci;
            l6_base[k] = leaf_l6
                       | ((uint64_t)((ci >> 8) & 0xFFU) << 32)
                       | ((uint64_t)(ci & 0xFFU) << 40);
        }

        /* Step 0: Derive 4 secret chain starts simultaneously */
        qhs_wots_sk_x4(sk_prefix6, sk_tail6, cidx, v0, v1, v2, v3);

        /* Steps 0..14: 15-step 4-way SIMD Winternitz chaining entirely in registers */
#if defined(__AVX2__)
        {
            __m256i st[25];
            __m256i p0v = _mm256_set1_epi64x((long long)ch_p0);
            __m256i p1v = _mm256_set1_epi64x((long long)ch_p1);
            __m256i p2v = _mm256_set1_epi64x((long long)ch_p2);
            __m256i p3v = _mm256_set1_epi64x((long long)ch_p3);
            __m256i p4v = _mm256_set1_epi64x((long long)ch_p4);
            __m256i p5v = _mm256_set1_epi64x((long long)ch_p5);
            __m256i l6v = _mm256_loadu_si256((const __m256i *)(const void *)l6_base);
            __m256i mask_ff = _mm256_set1_epi64x(0xFFLL);
            __m256i dom_sha3 = _mm256_set1_epi64x((long long)((uint64_t)OPENQPEP_SHA3_DOMAIN_SEP << 56));
            __m256i pad_end = _mm256_set1_epi64x((long long)0x8000000000000000ULL);
            __m256i zero_v = _mm256_setzero_si256();

            __m256i r0 = _mm256_loadu_si256((const __m256i *)(const void *)v0);
            __m256i r1 = _mm256_loadu_si256((const __m256i *)(const void *)v1);
            __m256i r2 = _mm256_loadu_si256((const __m256i *)(const void *)v2);
            __m256i r3 = _mm256_loadu_si256((const __m256i *)(const void *)v3);

            for (uint32_t s = 0U; s < (OPENQPEP_QHS_WOTS_W - 1U); s++) {
                __m256i sv = _mm256_set1_epi64x((long long)(((uint64_t)s) << 48));
                st[0] = p0v;
                st[1] = p1v;
                st[2] = p2v;
                st[3] = p3v;
                st[4] = p4v;
                st[5] = p5v;
                st[6] = _mm256_or_si256(_mm256_or_si256(l6v, sv), _mm256_slli_epi64(_mm256_and_si256(r0, mask_ff), 56));
                st[7] = _mm256_or_si256(_mm256_srli_epi64(r0, 8), _mm256_slli_epi64(r1, 56));
                st[8] = _mm256_or_si256(_mm256_srli_epi64(r1, 8), _mm256_slli_epi64(r2, 56));
                for (int z = 9; z < 25; z++) st[z] = zero_v;
                keccak_f1600_x4_avx2_regs(st);

                st[0] = _mm256_xor_si256(st[0], _mm256_or_si256(_mm256_srli_epi64(r2, 8), _mm256_slli_epi64(r3, 56)));
                st[1] = _mm256_xor_si256(st[1], _mm256_or_si256(_mm256_srli_epi64(r3, 8), dom_sha3));
                st[8] = _mm256_xor_si256(st[8], pad_end);
                keccak_f1600_x4_avx2_regs(st);

                r0 = st[0];
                r1 = st[1];
                r2 = st[2];
                r3 = st[3];
            }
            _mm256_storeu_si256((__m256i *)(void *)v0, r0);
            _mm256_storeu_si256((__m256i *)(void *)v1, r1);
            _mm256_storeu_si256((__m256i *)(void *)v2, r2);
            _mm256_storeu_si256((__m256i *)(void *)v3, r3);
            openqpep_explicit_bzero(st, sizeof(st));
        }
#else
        for (uint32_t s = 0U; s < (OPENQPEP_QHS_WOTS_W - 1U); s++) {
            uint64_t s_shift = ((uint64_t)s) << 48;
            memset(A, 0, sizeof(A));
            for (int k = 0; k < 4; k++) {
                A[0][k] = ch_p0;
                A[1][k] = ch_p1;
                A[2][k] = ch_p2;
                A[3][k] = ch_p3;
                A[4][k] = ch_p4;
                A[5][k] = ch_p5;
                A[6][k] = l6_base[k] | s_shift | ((v0[k] & 0xFFULL) << 56);
                A[7][k] = (v0[k] >> 8) | (v1[k] << 56);
                A[8][k] = (v1[k] >> 8) | (v2[k] << 56);
            }
            keccak_f1600_x4(A);

            for (int k = 0; k < 4; k++) {
                A[0][k] ^= (v2[k] >> 8) | (v3[k] << 56);
                A[1][k] ^= (v3[k] >> 8) | ((uint64_t)OPENQPEP_SHA3_DOMAIN_SEP << 56);
                A[8][k] ^= 0x8000000000000000ULL;
            }
            keccak_f1600_x4(A);

            for (int k = 0; k < 4; k++) {
                v0[k] = A[0][k];
                v1[k] = A[1][k];
                v2[k] = A[2][k];
                v3[k] = A[3][k];
            }
        }
#endif

        for (uint32_t k = 0U; k < lanes; k++) {
            qhs_store64_le(tips + k * 32U +  0U, v0[k]);
            qhs_store64_le(tips + k * 32U +  8U, v1[k]);
            qhs_store64_le(tips + k * 32U + 16U, v2[k]);
            qhs_store64_le(tips + k * 32U + 24U, v3[k]);
        }
        rc = openqpep_keccak_absorb(&pk_ctx, tips, (size_t)lanes * 32U);
    }

    uint8_t digest[OPENQPEP_QSPONGE_512_BYTES];
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&pk_ctx, digest, sizeof(digest));
    if (rc == OPENQPEP_OK) memcpy(leaf_pk32_out, digest, OPENQPEP_QHS_WOTS_N);

    openqpep_explicit_bzero(sk_hdr, sizeof(sk_hdr));
    openqpep_explicit_bzero(sk_prefix6, sizeof(sk_prefix6));
    openqpep_explicit_bzero(sk_tail6, sizeof(sk_tail6));
#if !defined(__AVX2__)
    openqpep_explicit_bzero(A, sizeof(A));
#endif
    openqpep_explicit_bzero(v0, sizeof(v0));
    openqpep_explicit_bzero(v1, sizeof(v1));
    openqpep_explicit_bzero(v2, sizeof(v2));
    openqpep_explicit_bzero(v3, sizeof(v3));
    openqpep_explicit_bzero(tips, sizeof(tips));
    openqpep_explicit_bzero(digest, sizeof(digest));
    openqpep_keccak_wipe(&pk_ctx);
    return rc;
}

OPENQPEP_API int openqpep_qhs_wots_sign(
    const uint8_t sk_seed32[32],
    const uint8_t pub_seed32[32],
    uint32_t leaf_idx,
    const uint8_t msg_digest32[32],
    uint8_t wots_sig_out[2144]
) {
    if (!sk_seed32 || !pub_seed32 || !msg_digest32 || !wots_sig_out) return OPENQPEP_ERR_NULL_PTR;

    uint8_t digits[OPENQPEP_QHS_WOTS_LEN];
    qhs_msg_to_base_w(msg_digest32, digits);

    uint8_t sk_hdr[48];
    memcpy(sk_hdr, DOMAIN_QHS_WOTS_SK, 18U);
    memcpy(sk_hdr + 18U, sk_seed32, 30U);
    uint64_t sk_prefix6[6];
    for (int l = 0; l < 6; l++) {
        sk_prefix6[l] = qhs_load64_le(sk_hdr + l * 8);
    }
    uint8_t sk_tail6[6];
    sk_tail6[0] = sk_seed32[30];
    sk_tail6[1] = sk_seed32[31];
    qhs_store32_be(sk_tail6 + 2U, leaf_idx);

    uint64_t v0[4], v1[4], v2[4], v3[4];
    uint8_t sk_i[32];
    int rc = OPENQPEP_OK;

    for (uint32_t base = 0U; rc == OPENQPEP_OK && base < OPENQPEP_QHS_WOTS_LEN; base += 4U) {
        uint32_t lanes = OPENQPEP_QHS_WOTS_LEN - base;
        if (lanes > 4U) lanes = 4U;

        uint16_t cidx[4];
        for (uint32_t k = 0U; k < 4U; k++) {
            cidx[k] = (uint16_t)((base + k < OPENQPEP_QHS_WOTS_LEN) ? (base + k) : (OPENQPEP_QHS_WOTS_LEN - 1U));
        }
        qhs_wots_sk_x4(sk_prefix6, sk_tail6, cidx, v0, v1, v2, v3);

        for (uint32_t k = 0U; k < lanes; k++) {
            uint32_t idx = base + k;
            qhs_store64_le(sk_i +  0U, v0[k]);
            qhs_store64_le(sk_i +  8U, v1[k]);
            qhs_store64_le(sk_i + 16U, v2[k]);
            qhs_store64_le(sk_i + 24U, v3[k]);
            rc = openqpep_qhs_wots_chain(
                sk_i,
                0U,
                (uint32_t)digits[idx],
                pub_seed32,
                leaf_idx,
                (uint16_t)idx,
                wots_sig_out + (size_t)idx * OPENQPEP_QHS_WOTS_N
            );
            if (rc != OPENQPEP_OK) break;
        }
    }

    openqpep_explicit_bzero(sk_hdr, sizeof(sk_hdr));
    openqpep_explicit_bzero(sk_prefix6, sizeof(sk_prefix6));
    openqpep_explicit_bzero(sk_tail6, sizeof(sk_tail6));
    openqpep_explicit_bzero(v0, sizeof(v0));
    openqpep_explicit_bzero(v1, sizeof(v1));
    openqpep_explicit_bzero(v2, sizeof(v2));
    openqpep_explicit_bzero(v3, sizeof(v3));
    openqpep_explicit_bzero(sk_i, sizeof(sk_i));
    return rc;
}

OPENQPEP_API int openqpep_qhs_wots_pk_from_sig(
    const uint8_t wots_sig[2144],
    const uint8_t msg_digest32[32],
    const uint8_t pub_seed32[32],
    uint32_t leaf_idx,
    uint8_t leaf_pk32_out[32]
) {
    if (!wots_sig || !msg_digest32 || !pub_seed32 || !leaf_pk32_out) return OPENQPEP_ERR_NULL_PTR;

    uint8_t digits[OPENQPEP_QHS_WOTS_LEN];
    qhs_msg_to_base_w(msg_digest32, digits);

    uint8_t leaf_be[4];
    qhs_store32_be(leaf_be, leaf_idx);

    openqpep_keccak_ctx_t pk_ctx;
    int rc = openqpep_sha3_512_init(&pk_ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&pk_ctx, DOMAIN_QHS_WOTS_PK, sizeof(DOMAIN_QHS_WOTS_PK) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&pk_ctx, pub_seed32, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&pk_ctx, leaf_be, 4U);

    uint8_t tip[OPENQPEP_QHS_WOTS_N];
    for (uint32_t i = 0U; rc == OPENQPEP_OK && i < OPENQPEP_QHS_WOTS_LEN; i++) {
        uint32_t d = (uint32_t)digits[i];
        rc = openqpep_qhs_wots_chain(
            wots_sig + (size_t)i * OPENQPEP_QHS_WOTS_N,
            d,
            (OPENQPEP_QHS_WOTS_W - 1U) - d,
            pub_seed32,
            leaf_idx,
            (uint16_t)i,
            tip
        );
        if (rc == OPENQPEP_OK) {
            rc = openqpep_keccak_absorb(&pk_ctx, tip, OPENQPEP_QHS_WOTS_N);
        }
    }

    uint8_t digest[OPENQPEP_QSPONGE_512_BYTES];
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&pk_ctx, digest, sizeof(digest));
    if (rc == OPENQPEP_OK) memcpy(leaf_pk32_out, digest, OPENQPEP_QHS_WOTS_N);

    openqpep_explicit_bzero(tip, sizeof(tip));
    openqpep_explicit_bzero(digest, sizeof(digest));
    openqpep_keccak_wipe(&pk_ctx);
    return rc;
}

OPENQPEP_API int openqpep_qhs_treehash_subtree(
    const uint8_t sk_seed32[32],
    const uint8_t pub_seed32[32],
    uint32_t start_leaf,
    uint32_t subtree_height,
    uint32_t target_leaf,
    int capture_auth,
    uint8_t *auth_out,
    uint8_t root32_out[32]
) {
    if (!sk_seed32 || !pub_seed32 || !root32_out) return OPENQPEP_ERR_NULL_PTR;
    if (subtree_height > OPENQPEP_QHS_MAX_HEIGHT) return OPENQPEP_ERR_INVALID_LEN;
    if (capture_auth && subtree_height > 0U && !auth_out) return OPENQPEP_ERR_NULL_PTR;

    uint32_t num_leaves = 1U << subtree_height;
    if ((start_leaf & (num_leaves - 1U)) != 0U) return OPENQPEP_ERR_INVALID_LEN;
    if ((uint64_t)start_leaf + (uint64_t)num_leaves > 0x100000000ULL) return OPENQPEP_ERR_INVALID_LEN;
    if (capture_auth) {
        if (target_leaf < start_leaf || (target_leaf - start_leaf) >= num_leaves) {
            return OPENQPEP_ERR_INVALID_LEN;
        }
    }

    uint8_t stack_nodes[(OPENQPEP_QHS_MAX_HEIGHT + 1U) * OPENQPEP_QHS_WOTS_N];
    uint32_t stack_lvl[OPENQPEP_QHS_MAX_HEIGHT + 1U];
    uint32_t sp = 0U;
    uint8_t cur_node[OPENQPEP_QHS_WOTS_N];
    uint8_t parent[OPENQPEP_QHS_WOTS_N];
    int rc = OPENQPEP_OK;

    for (uint32_t offset = 0U; offset < num_leaves; offset++) {
        uint32_t leaf = start_leaf + offset;
        rc = openqpep_qhs_wots_pk_from_sk_seed(sk_seed32, pub_seed32, leaf, cur_node);
        if (rc != OPENQPEP_OK) break;

        uint32_t cur_lvl = 0U;
        uint32_t cur_idx = leaf;
        if (capture_auth && cur_lvl < subtree_height && cur_idx == ((target_leaf >> cur_lvl) ^ 1U)) {
            memcpy(auth_out + (size_t)cur_lvl * OPENQPEP_QHS_WOTS_N, cur_node, OPENQPEP_QHS_WOTS_N);
        }

        while (sp > 0U && stack_lvl[sp - 1U] == cur_lvl) {
            sp--;
            rc = qhs_hash_node(
                pub_seed32,
                stack_nodes + (size_t)sp * OPENQPEP_QHS_WOTS_N,
                cur_node,
                parent
            );
            if (rc != OPENQPEP_OK) break;
            memcpy(cur_node, parent, OPENQPEP_QHS_WOTS_N);
            cur_lvl++;
            cur_idx >>= 1;
            if (capture_auth && cur_lvl < subtree_height && cur_idx == ((target_leaf >> cur_lvl) ^ 1U)) {
                memcpy(auth_out + (size_t)cur_lvl * OPENQPEP_QHS_WOTS_N, cur_node, OPENQPEP_QHS_WOTS_N);
            }
        }
        if (rc != OPENQPEP_OK) break;

        memcpy(stack_nodes + (size_t)sp * OPENQPEP_QHS_WOTS_N, cur_node, OPENQPEP_QHS_WOTS_N);
        stack_lvl[sp] = cur_lvl;
        sp++;
    }

    if (rc == OPENQPEP_OK) {
        memcpy(root32_out, stack_nodes, OPENQPEP_QHS_WOTS_N);
    }

    openqpep_explicit_bzero(stack_nodes, sizeof(stack_nodes));
    openqpep_explicit_bzero(cur_node, sizeof(cur_node));
    openqpep_explicit_bzero(parent, sizeof(parent));
    return rc;
}

OPENQPEP_API int openqpep_qhs_fold_subtrees(
    const uint8_t pub_seed32[32],
    const uint8_t *subtree_roots,
    uint32_t top_height,
    uint32_t target_subtree_idx,
    int capture_auth,
    uint8_t *top_auth_out,
    uint8_t root32_out[32]
) {
    if (!pub_seed32 || !subtree_roots || !root32_out) return OPENQPEP_ERR_NULL_PTR;
    if (top_height > OPENQPEP_QHS_MAX_HEIGHT) return OPENQPEP_ERR_INVALID_LEN;
    if (capture_auth && top_height > 0U && !top_auth_out) return OPENQPEP_ERR_NULL_PTR;

    uint32_t num_subtrees = 1U << top_height;
    if (capture_auth && target_subtree_idx >= num_subtrees) return OPENQPEP_ERR_INVALID_LEN;

    uint8_t stack_nodes[(OPENQPEP_QHS_MAX_HEIGHT + 1U) * OPENQPEP_QHS_WOTS_N];
    uint32_t stack_lvl[OPENQPEP_QHS_MAX_HEIGHT + 1U];
    uint32_t sp = 0U;
    uint8_t cur_node[OPENQPEP_QHS_WOTS_N];
    uint8_t parent[OPENQPEP_QHS_WOTS_N];
    int rc = OPENQPEP_OK;

    for (uint32_t sidx = 0U; sidx < num_subtrees; sidx++) {
        memcpy(cur_node, subtree_roots + (size_t)sidx * OPENQPEP_QHS_WOTS_N, OPENQPEP_QHS_WOTS_N);
        uint32_t cur_lvl = 0U;
        uint32_t cur_idx = sidx;
        if (capture_auth && cur_lvl < top_height && cur_idx == ((target_subtree_idx >> cur_lvl) ^ 1U)) {
            memcpy(top_auth_out + (size_t)cur_lvl * OPENQPEP_QHS_WOTS_N, cur_node, OPENQPEP_QHS_WOTS_N);
        }

        while (sp > 0U && stack_lvl[sp - 1U] == cur_lvl) {
            sp--;
            rc = qhs_hash_node(
                pub_seed32,
                stack_nodes + (size_t)sp * OPENQPEP_QHS_WOTS_N,
                cur_node,
                parent
            );
            if (rc != OPENQPEP_OK) break;
            memcpy(cur_node, parent, OPENQPEP_QHS_WOTS_N);
            cur_lvl++;
            cur_idx >>= 1;
            if (capture_auth && cur_lvl < top_height && cur_idx == ((target_subtree_idx >> cur_lvl) ^ 1U)) {
                memcpy(top_auth_out + (size_t)cur_lvl * OPENQPEP_QHS_WOTS_N, cur_node, OPENQPEP_QHS_WOTS_N);
            }
        }
        if (rc != OPENQPEP_OK) break;

        memcpy(stack_nodes + (size_t)sp * OPENQPEP_QHS_WOTS_N, cur_node, OPENQPEP_QHS_WOTS_N);
        stack_lvl[sp] = cur_lvl;
        sp++;
    }

    if (rc == OPENQPEP_OK) {
        memcpy(root32_out, stack_nodes, OPENQPEP_QHS_WOTS_N);
    }

    openqpep_explicit_bzero(stack_nodes, sizeof(stack_nodes));
    openqpep_explicit_bzero(cur_node, sizeof(cur_node));
    openqpep_explicit_bzero(parent, sizeof(parent));
    return rc;
}

OPENQPEP_API int openqpep_qhs_keygen_from_seeds(
    uint32_t height,
    const uint8_t sk_seed32[32],
    const uint8_t pub_seed32[32],
    uint8_t pk_out[65],
    uint8_t sk_out[97]
) {
    if (!sk_seed32 || !pub_seed32 || !pk_out || !sk_out) return OPENQPEP_ERR_NULL_PTR;
    if (height > OPENQPEP_QHS_MAX_HEIGHT) return OPENQPEP_ERR_INVALID_LEN;

    uint8_t root[OPENQPEP_QHS_WOTS_N];
    int rc = openqpep_qhs_treehash_subtree(sk_seed32, pub_seed32, 0U, height, 0U, 0, NULL, root);
    if (rc != OPENQPEP_OK) {
        openqpep_explicit_bzero(root, sizeof(root));
        return rc;
    }

    pk_out[0] = (uint8_t)height;
    memcpy(pk_out + 1U, pub_seed32, 32U);
    memcpy(pk_out + 33U, root, 32U);

    sk_out[0] = (uint8_t)height;
    memcpy(sk_out + 1U, sk_seed32, 32U);
    memcpy(sk_out + 33U, pub_seed32, 32U);
    memcpy(sk_out + 65U, root, 32U);

    openqpep_explicit_bzero(root, sizeof(root));
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qhs_verify(
    const uint8_t pk65[65],
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sig,
    size_t sig_len
) {
    if (!pk65 || !sig) return OPENQPEP_ERR_NULL_PTR;
    if (msg_len > 0U && !msg) return OPENQPEP_ERR_NULL_PTR;

    uint32_t height = (uint32_t)pk65[0];
    if (height > OPENQPEP_QHS_MAX_HEIGHT) return OPENQPEP_ERR_AUTH_FAIL;

    size_t expected_len = (size_t)OPENQPEP_QHS_SIG_FIXED_BYTES + (size_t)height * OPENQPEP_QHS_WOTS_N;
    if (sig_len != expected_len) return OPENQPEP_ERR_AUTH_FAIL;

    const uint8_t *pub_seed = pk65 + 1U;
    const uint8_t *expected_root = pk65 + 33U;

    uint32_t leaf_idx = qhs_load32_be(sig);
    if (leaf_idx >= (1U << height)) return OPENQPEP_ERR_AUTH_FAIL;

    const uint8_t *opt_rand = sig + 4U;
    const uint8_t *wots_sig = sig + 36U;
    const uint8_t *auth_bytes = sig + OPENQPEP_QHS_SIG_FIXED_BYTES;

    openqpep_keccak_ctx_t ctx;
    uint8_t h_all[OPENQPEP_QSPONGE_512_BYTES];
    int rc = openqpep_sha3_512_init(&ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, DOMAIN_QHS_MSG, sizeof(DOMAIN_QHS_MSG) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, opt_rand, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, pub_seed, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, expected_root, 32U);
    if (rc == OPENQPEP_OK && msg_len > 0U) rc = openqpep_keccak_absorb(&ctx, msg, msg_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, h_all, sizeof(h_all));
    openqpep_keccak_wipe(&ctx);
    if (rc != OPENQPEP_OK) {
        openqpep_explicit_bzero(h_all, sizeof(h_all));
        return rc;
    }

    uint8_t cur[OPENQPEP_QHS_WOTS_N];
    uint8_t nxt[OPENQPEP_QHS_WOTS_N];
    rc = openqpep_qhs_wots_pk_from_sig(wots_sig, h_all, pub_seed, leaf_idx, cur);
    openqpep_explicit_bzero(h_all, sizeof(h_all));
    if (rc != OPENQPEP_OK) {
        openqpep_explicit_bzero(cur, sizeof(cur));
        return rc;
    }

    uint32_t idx = leaf_idx;
    for (uint32_t lvl = 0U; lvl < height; lvl++) {
        const uint8_t *sib = auth_bytes + (size_t)lvl * OPENQPEP_QHS_WOTS_N;
        if ((idx & 1U) == 0U) {
            rc = qhs_hash_node(pub_seed, cur, sib, nxt);
        } else {
            rc = qhs_hash_node(pub_seed, sib, cur, nxt);
        }
        if (rc != OPENQPEP_OK) break;
        memcpy(cur, nxt, OPENQPEP_QHS_WOTS_N);
        idx >>= 1;
    }

    int eq = (rc == OPENQPEP_OK) ? openqpep_ct_eq(cur, expected_root, OPENQPEP_QHS_WOTS_N) : 0;
    openqpep_explicit_bzero(cur, sizeof(cur));
    openqpep_explicit_bzero(nxt, sizeof(nxt));
    if (rc != OPENQPEP_OK) return rc;
    return eq ? OPENQPEP_OK : OPENQPEP_ERR_AUTH_FAIL;
}

OPENQPEP_API int openqpep_qhs_sign_core(
    const uint8_t sk97[97],
    const uint8_t *msg,
    size_t msg_len,
    int hedged,
    const uint8_t *rnd32,
    uint8_t *sig_out,
    size_t sig_out_len
) {
    if (!sk97 || !sig_out) return OPENQPEP_ERR_NULL_PTR;
    if (msg_len > 0U && !msg) return OPENQPEP_ERR_NULL_PTR;
    if (hedged && !rnd32) return OPENQPEP_ERR_NULL_PTR;

    uint32_t height = (uint32_t)sk97[0];
    if (height > OPENQPEP_QHS_MAX_HEIGHT) return OPENQPEP_ERR_INVALID_LEN;

    size_t expected_len = (size_t)OPENQPEP_QHS_SIG_FIXED_BYTES + (size_t)height * OPENQPEP_QHS_WOTS_N;
    if (sig_out_len != expected_len) return OPENQPEP_ERR_INVALID_LEN;

    const uint8_t *sk_seed = sk97 + 1U;
    const uint8_t *pub_seed = sk97 + 33U;
    const uint8_t *root = sk97 + 65U;

    /* 1. Derive opt_rand (hedged or deterministic, matching v1.1.4 immutable tags) */
    openqpep_keccak_ctx_t ctx;
    uint8_t digest[OPENQPEP_QSPONGE_512_BYTES];
    uint8_t opt_rand[32];

    int rc = openqpep_sha3_512_init(&ctx);
    if (hedged) {
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, DOMAIN_QHS_HEDGE, sizeof(DOMAIN_QHS_HEDGE) - 1U);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, sk_seed, 32U);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, rnd32, 32U);
    } else {
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, DOMAIN_QHS_DET, sizeof(DOMAIN_QHS_DET) - 1U);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, sk_seed, 32U);
    }
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, pub_seed, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, root, 32U);
    if (rc == OPENQPEP_OK && msg_len > 0U) rc = openqpep_keccak_absorb(&ctx, msg, msg_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, digest, sizeof(digest));
    openqpep_keccak_wipe(&ctx);
    if (rc != OPENQPEP_OK) {
        openqpep_explicit_bzero(digest, sizeof(digest));
        return rc;
    }
    memcpy(opt_rand, digest, 32U);

    /* 2. Derive msg_digest32 and stateless leaf_idx */
    rc = openqpep_sha3_512_init(&ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, DOMAIN_QHS_MSG, sizeof(DOMAIN_QHS_MSG) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, opt_rand, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, pub_seed, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, root, 32U);
    if (rc == OPENQPEP_OK && msg_len > 0U) rc = openqpep_keccak_absorb(&ctx, msg, msg_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, digest, sizeof(digest));
    openqpep_keccak_wipe(&ctx);
    if (rc != OPENQPEP_OK) {
        openqpep_explicit_bzero(digest, sizeof(digest));
        openqpep_explicit_bzero(opt_rand, sizeof(opt_rand));
        return rc;
    }

    uint32_t num_leaves = 1U << height;
    uint32_t leaf_idx = qhs_load32_be(digest + 32U) & (num_leaves - 1U);

    /* 3. Write header + WOTS+ signature + O(h) TreeHash auth path */
    qhs_store32_be(sig_out, leaf_idx);
    memcpy(sig_out + 4U, opt_rand, 32U);
    rc = openqpep_qhs_wots_sign(sk_seed, pub_seed, leaf_idx, digest, sig_out + 36U);
    openqpep_explicit_bzero(digest, sizeof(digest));
    openqpep_explicit_bzero(opt_rand, sizeof(opt_rand));

    uint8_t rebuilt_root[OPENQPEP_QHS_WOTS_N];
    if (rc == OPENQPEP_OK) {
        rc = openqpep_qhs_treehash_subtree(
            sk_seed,
            pub_seed,
            0U,
            height,
            leaf_idx,
            1,
            (height > 0U) ? (sig_out + OPENQPEP_QHS_SIG_FIXED_BYTES) : NULL,
            rebuilt_root
        );
    }

    /* 4. Verify-Before-Emit Fault-Guard */
    if (rc == OPENQPEP_OK) {
        uint8_t pk65[OPENQPEP_QHS_PK_BYTES];
        pk65[0] = (uint8_t)height;
        memcpy(pk65 + 1U, pub_seed, 32U);
        memcpy(pk65 + 33U, root, 32U);
        int root_ok = openqpep_ct_eq(rebuilt_root, root, OPENQPEP_QHS_WOTS_N);
        int vrc = openqpep_qhs_verify(pk65, msg, msg_len, sig_out, sig_out_len);
        openqpep_explicit_bzero(pk65, sizeof(pk65));
        if (!root_ok || vrc != OPENQPEP_OK) {
            openqpep_explicit_bzero(sig_out, sig_out_len);
            rc = OPENQPEP_ERR_FAULT_GUARD;
        }
    }

    openqpep_explicit_bzero(rebuilt_root, sizeof(rebuilt_root));
    return rc;
}
