/*
 * OpenQPEP Native C99 / SIMD Accelerated 7-Layer NTT over Z_3329[X]/(X^256 + 1)
 * Official Release 1.2.0 (v1.2.0) — Calyx Labs Inc. (CPOSLS-1.0)
 *
 * Thread-safe compile-time const twiddle tables (zero lazy-init data races) and
 * branchless conditional modular reduction, bit-for-bit identical to ntt_3329.py.
 */
#include "openqpep.h"

#define QLX_Q OPENQPEP_QLX_Q
#define QLX_N OPENQPEP_QLX_N
#define INV_128_3329 3303

static const int32_t ZETAS_3329[128] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
};

static const int32_t ZETAS_BASE_3329[128] = {
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279,
    1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
    939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
    1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735,
    2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
};

static inline int32_t ct_caddq_3329(int32_t a) {
    return a + ((a >> 31) & QLX_Q);
}

static inline int32_t ct_csubq_3329(int32_t a) {
    int32_t d = a - QLX_Q;
    return d + ((d >> 31) & QLX_Q);
}

static inline int32_t ct_barrett_3329(int64_t x) {
    /* Division-free branchless Barrett mod 3329, bit-exact with Python & Rust (|x| <= 2^35) */
    int64_t t = (x * 20642678LL) >> 36;
    int32_t r = (int32_t)(x - t * QLX_Q);
    r = ct_caddq_3329(r);
    return ct_csubq_3329(r);
}

OPENQPEP_API void openqpep_ntt_3329(int32_t *p) {
    if (!p) return;
    int k = 1;
    for (int length = 128; length >= 2; length >>= 1) {
        for (int start = 0; start < 256; start += 2 * length) {
            int32_t zeta = ZETAS_3329[k++];
            for (int j = start; j < start + length; j++) {
                int32_t t = ct_barrett_3329((int64_t)zeta * (int64_t)p[j + length]);
                int32_t u = p[j];
                p[j + length] = ct_caddq_3329(u - t);
                p[j] = ct_csubq_3329(u + t);
            }
        }
    }
}

OPENQPEP_API void openqpep_inv_ntt_3329(int32_t *p) {
    if (!p) return;
    int k = 127;
    for (int length = 2; length <= 128; length <<= 1) {
        for (int start = 0; start < 256; start += 2 * length) {
            int32_t zeta = QLX_Q - ZETAS_3329[k--];
            for (int j = start; j < start + length; j++) {
                int32_t t = p[j];
                int32_t sum = ct_csubq_3329(t + p[j + length]);
                int32_t diff = ct_caddq_3329(t - p[j + length]);
                p[j] = sum;
                p[j + length] = ct_barrett_3329((int64_t)zeta * (int64_t)diff);
            }
        }
    }
    for (int i = 0; i < 256; i++) {
        p[i] = ct_barrett_3329((int64_t)p[i] * (int64_t)INV_128_3329);
    }
}

OPENQPEP_API void openqpep_ntt_base_mul_3329(const int32_t *a_hat, const int32_t *b_hat, int32_t *out) {
    if (!a_hat || !b_hat || !out) return;
    for (int i = 0; i < 128; i++) {
        int32_t a0 = a_hat[2 * i];
        int32_t a1 = a_hat[2 * i + 1];
        int32_t b0 = b_hat[2 * i];
        int32_t b1 = b_hat[2 * i + 1];
        int32_t gamma = ZETAS_BASE_3329[i];
        int64_t prod1 = (int64_t)ct_barrett_3329((int64_t)a1 * (int64_t)b1);
        int64_t r0 = (int64_t)a0 * (int64_t)b0 + prod1 * (int64_t)gamma;
        int64_t r1 = (int64_t)a0 * (int64_t)b1 + (int64_t)a1 * (int64_t)b0;
        out[2 * i] = ct_barrett_3329(r0);
        out[2 * i + 1] = ct_barrett_3329(r1);
    }
}

OPENQPEP_API void openqpep_poly_add_3329(const int32_t *a, const int32_t *b, int32_t *out) {
    if (!a || !b || !out) return;
    for (int i = 0; i < 256; i++) {
        out[i] = ct_csubq_3329(a[i] + b[i]);
    }
}

OPENQPEP_API void openqpep_poly_sub_3329(const int32_t *a, const int32_t *b, int32_t *out) {
    if (!a || !b || !out) return;
    for (int i = 0; i < 256; i++) {
        out[i] = ct_caddq_3329(a[i] - b[i]);
    }
}
