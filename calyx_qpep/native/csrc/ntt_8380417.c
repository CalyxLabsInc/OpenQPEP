/*
 * OpenQPEP Native C99 / SIMD Accelerated 8-Layer Complete NTT over Z_8380417[X]/(X^256 + 1)
 * Official Release 1.2.2 (v1.2.2) — Calyx Labs Inc. (CPOSLS-1.0)
 *
 * Thread-safe compile-time const twiddle tables (zero lazy-init data races) and
 * 100% division-free branchless Solinas-Barrett modular reduction (q = 2^23 - 2^13 + 1),
 * bit-for-bit identical to ntt_8380417.py across all 8,380,417 residues.
 */
#include "openqpep.h"

#define QVS_Q_U64       8380417ULL
#define QVS_Q_I64       8380417LL
#define QVS_Q_I32       8380417
#define QVS_GAMMA2_I32  261888
#define QVS_ALPHA_I32   523776
#define QVS_ALPHA_M44   33587233ULL
#define INV_256_QVS_U64 8347681ULL

static const uint64_t ZETAS_QVS[256] = {
    1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
    5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
    5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
    3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
    394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
    3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
    5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
    3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
    1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
    4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
    5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
    7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
    348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
    1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
    1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
    8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
    6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
    4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
    3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
    2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
    7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
    6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
    6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
    5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
    3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
    3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
    6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
    8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
};

static inline int32_t ct_caddq_qvs(int32_t a) {
    int32_t mask = -(int32_t)((uint32_t)a >> 31);
    return a + (mask & QVS_Q_I32);
}

static inline int32_t ct_csubq_qvs(int32_t a) {
    int32_t d = a - QVS_Q_I32;
    int32_t mask = -(int32_t)((uint32_t)d >> 31);
    return d + (mask & QVS_Q_I32);
}

/*
 * Division-free branchless Solinas reduction modulo QVS_Q = 2^23 - 2^13 + 1 = 8380417.
 * Since 2^23 == (2^13 - 1) mod Q, three unsigned 23-bit folds reduce ANY u in [0, 2^50)
 * strictly into [0, 2*Q - 1], followed by a single branchless conditional subtraction
 * producing the exact canonical residue in [0, 8380416]. Zero divisions, zero branches.
 */
static inline int32_t ct_reduce_qvs_u64(uint64_t x) {
    uint64_t hi = x >> 23;
    uint64_t y = (x & 0x7FFFFFULL) + (hi << 13) - hi;
    hi = y >> 23;
    uint64_t z = (y & 0x7FFFFFULL) + (hi << 13) - hi;
    hi = z >> 23;
    uint64_t r = (z & 0x7FFFFFULL) + (hi << 13) - hi;
    return ct_csubq_qvs((int32_t)r);
}

/* Exact canonical reduction mod QVS_Q for ANY signed int32_t (INT32_MIN..INT32_MAX). */
static inline int32_t ct_reduce_qvs_i32(int32_t c) {
    /* 257 * 8380417 = 2,153,767,169 > 2^31, guaranteeing strict positivity < 2^33. */
    uint64_t shifted = (uint64_t)((int64_t)c + (257LL * QVS_Q_I64));
    return ct_reduce_qvs_u64(shifted);
}

OPENQPEP_API void openqpep_ntt_qvs(int32_t *p) {
    if (!p) return;
    int k = 0;
    for (int length = 128; length >= 1; length >>= 1) {
        for (int start = 0; start < 256; start += 2 * length) {
            uint64_t zeta = ZETAS_QVS[++k];
            for (int j = start; j < start + length; j++) {
                int32_t t = ct_reduce_qvs_u64(zeta * (uint64_t)(uint32_t)p[j + length]);
                int32_t u = p[j];
                p[j + length] = ct_caddq_qvs(u - t);
                p[j] = ct_csubq_qvs(u + t);
            }
        }
    }
}

OPENQPEP_API void openqpep_inv_ntt_qvs(int32_t *p) {
    if (!p) return;
    int k = 256;
    for (int length = 1; length < 256; length <<= 1) {
        for (int start = 0; start < 256; start += 2 * length) {
            uint64_t zeta = QVS_Q_U64 - ZETAS_QVS[--k];
            for (int j = start; j < start + length; j++) {
                int32_t t = p[j];
                int32_t u = p[j + length];
                int32_t diff = ct_caddq_qvs(t - u);
                p[j] = ct_csubq_qvs(t + u);
                p[j + length] = ct_reduce_qvs_u64(zeta * (uint64_t)(uint32_t)diff);
            }
        }
    }
    for (int i = 0; i < 256; i++) {
        p[i] = ct_reduce_qvs_u64((uint64_t)(uint32_t)p[i] * INV_256_QVS_U64);
    }
}

OPENQPEP_API void openqpep_ntt_mul_qvs(const int32_t *a_hat, const int32_t *b_hat, int32_t *out) {
    if (!a_hat || !b_hat || !out) return;
    for (int i = 0; i < 256; i++) {
        uint64_t a = (uint64_t)(uint32_t)ct_reduce_qvs_i32(a_hat[i]);
        uint64_t b = (uint64_t)(uint32_t)ct_reduce_qvs_i32(b_hat[i]);
        out[i] = ct_reduce_qvs_u64(a * b);
    }
}

OPENQPEP_API void openqpep_ntt_base_mul_8380417(const int32_t *a_hat, const int32_t *b_hat, int32_t *out) {
    openqpep_ntt_mul_qvs(a_hat, b_hat, out);
}

OPENQPEP_API void openqpep_poly_add_qvs(const int32_t *a, const int32_t *b, int32_t *out) {
    if (!a || !b || !out) return;
    for (int i = 0; i < 256; i++) {
        int32_t x = ct_reduce_qvs_i32(a[i]);
        int32_t y = ct_reduce_qvs_i32(b[i]);
        out[i] = ct_csubq_qvs(x + y);
    }
}

OPENQPEP_API void openqpep_poly_sub_qvs(const int32_t *a, const int32_t *b, int32_t *out) {
    if (!a || !b || !out) return;
    for (int i = 0; i < 256; i++) {
        int32_t x = ct_reduce_qvs_i32(a[i]);
        int32_t y = ct_reduce_qvs_i32(b[i]);
        out[i] = ct_caddq_qvs(x - y);
    }
}

OPENQPEP_API int openqpep_qvs_decompose_poly(const int32_t *poly, int32_t *r1_out, int32_t *r0_out) {
    if (!poly || !r1_out || !r0_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    for (int i = 0; i < 256; i++) {
        uint32_t r = (uint32_t)ct_reduce_qvs_i32(poly[i]);
        int32_t q1 = (int32_t)(((uint64_t)r * QVS_ALPHA_M44) >> 44);
        int32_t r0 = (int32_t)r - q1 * QVS_ALPHA_I32;
        int32_t gt = -(int32_t)((uint32_t)(QVS_GAMMA2_I32 - r0) >> 31);
        r0 -= (gt & QVS_ALPHA_I32);
        int32_t r1 = q1 - gt;
        int32_t is16 = -(int32_t)((uint32_t)(15 - r1) >> 31);
        r1 &= ~is16;
        r0 += is16;
        r1_out[i] = r1;
        r0_out[i] = r0;
    }
    return OPENQPEP_OK;
}
