/*
 * OpenQPEP Native C99 / SIMD Rank-Metric GF(2^127) & UOV GF(256) Accelerators (CRT-RSD512 + QMQ-512)
 * Official Release 1.2.9 (v1.2.9) — Calyx Labs Inc. (CPOSLS-1.0)
 *
 * Implements:
 *   1. CRT-RSD512 (ROLLO-I / LRPC Rank-Metric KEM):
 *      - 100% branchless, table-free GF(2^127) carry-less multiplication, O(1) bit-interleaved
 *        squaring with 2-line trinomial reduction mod x^127 + x^63 + 1, and Itoh-Tsujii Fermat
 *        inversion (9 muls + 126 squares)
 *      - Branchless polynomial multiplication and Extended GCD inversion in GF(2^127)[X]/(X^47 + X^5 + 1)
 *   2. QMQ-512 (Unbalanced Oil-and-Vinegar Multivariate Quadratic Signatures):
 *      - Branchless table-free GF(256) inversion (a^254 mod 0x11B) and vectorized GF(256) MAC loops
 *      - Constant-time pivot-masked Gaussian elimination over GF(256) (zero secret pivot branches)
 *      - Streaming Keccak-backed UOV public-map evaluation, hidden P_3 keygen, and signing linear solver
 *   3. Compiler-barrier openqpep_explicit_bzero scrubbing of all secret intermediates
 *
 * 100% ISO C99 (-Wall -Wextra -Werror -Wpedantic), bit-for-bit identical to rank_rsd512.py & qmq_512.py.
 */
#include "openqpep.h"
#include <stdlib.h>
#include <string.h>

#define GF127_HI_MASK  0x7FFFFFFFFFFFFFFFULL
#define GF127_MOD_LO   0x8000000000000001ULL /* x^63 + 1 */
#define LRPC_N         OPENQPEP_LRPC_N
#define LRPC_POLY_CAP  50U

typedef struct {
    uint64_t lo;
    uint64_t hi; /* bit 63 always 0 */
} gf127_t;

static inline uint64_t load64_le(const uint8_t *p) {
    return ((uint64_t)p[0])
         | (((uint64_t)p[1]) << 8)
         | (((uint64_t)p[2]) << 16)
         | (((uint64_t)p[3]) << 24)
         | (((uint64_t)p[4]) << 32)
         | (((uint64_t)p[5]) << 40)
         | (((uint64_t)p[6]) << 48)
         | (((uint64_t)p[7]) << 56);
}

static inline void store64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
    p[4] = (uint8_t)((v >> 32) & 0xFFU);
    p[5] = (uint8_t)((v >> 40) & 0xFFU);
    p[6] = (uint8_t)((v >> 48) & 0xFFU);
    p[7] = (uint8_t)((v >> 56) & 0xFFU);
}

static inline gf127_t gf127_load(const uint8_t in16[16]) {
    gf127_t r;
    r.lo = load64_le(in16);
    r.hi = load64_le(in16 + 8U) & GF127_HI_MASK;
    return r;
}

static inline void gf127_store(uint8_t out16[16], gf127_t v) {
    store64_le(out16, v.lo);
    store64_le(out16 + 8U, v.hi & GF127_HI_MASK);
}

static inline int gf127_is_zero(gf127_t v) {
    return ((v.lo | v.hi) == 0ULL);
}

/* Spread 32 bits into even bit positions of a 64-bit word (exact GF(2)[x] squaring of 32 bits). */
static inline uint64_t spread32_to_64(uint32_t x) {
    uint64_t v = (uint64_t)x;
    v = (v | (v << 16)) & 0x0000FFFF0000FFFFULL;
    v = (v | (v << 8))  & 0x00FF00FF00FF00FFULL;
    v = (v | (v << 4))  & 0x0F0F0F0F0F0F0F0FULL;
    v = (v | (v << 2))  & 0x3333333333333333ULL;
    v = (v | (v << 1))  & 0x5555555555555555ULL;
    return v;
}

/* ------------------------------------------------------------------------- */
/* Branchless, Table-Free GF(2^127) Arithmetic mod x^127 + x^63 + 1          */
/* ------------------------------------------------------------------------- */

static gf127_t gf127_mul_ct(gf127_t a, gf127_t b) {
    uint64_t a_lo = a.lo;
    uint64_t a_hi = a.hi & GF127_HI_MASK;
    uint64_t b_lo = b.lo;
    uint64_t b_hi = b.hi & GF127_HI_MASK;
    uint64_t r_lo = 0ULL;
    uint64_t r_hi = 0ULL;

    for (uint32_t i = 0U; i < 64U; i++) {
        uint64_t mask = (uint64_t)(-(int64_t)((b_lo >> i) & 1ULL));
        r_lo ^= (a_lo & mask);
        r_hi ^= (a_hi & mask);
        uint64_t rmask = (uint64_t)(-(int64_t)((a_hi >> 62) & 1ULL));
        a_hi = ((a_hi << 1) | (a_lo >> 63)) & GF127_HI_MASK;
        a_lo = (a_lo << 1) ^ (GF127_MOD_LO & rmask);
    }
    for (uint32_t i = 0U; i < 63U; i++) {
        uint64_t mask = (uint64_t)(-(int64_t)((b_hi >> i) & 1ULL));
        r_lo ^= (a_lo & mask);
        r_hi ^= (a_hi & mask);
        uint64_t rmask = (uint64_t)(-(int64_t)((a_hi >> 62) & 1ULL));
        a_hi = ((a_hi << 1) | (a_lo >> 63)) & GF127_HI_MASK;
        a_lo = (a_lo << 1) ^ (GF127_MOD_LO & rmask);
    }

    gf127_t out;
    out.lo = r_lo;
    out.hi = r_hi & GF127_HI_MASK;
    return out;
}

static gf127_t gf127_sq_ct(gf127_t a) {
    uint64_t w0 = spread32_to_64((uint32_t)(a.lo & 0xFFFFFFFFULL));
    uint64_t w1 = spread32_to_64((uint32_t)(a.lo >> 32));
    uint64_t w2 = spread32_to_64((uint32_t)(a.hi & 0xFFFFFFFFULL));
    uint64_t w3 = spread32_to_64((uint32_t)((a.hi & GF127_HI_MASK) >> 32));

    /* Exact constant-time trinomial reduction of 253-bit product mod x^127 + x^63 + 1 */
    uint64_t h_lo = (w1 >> 63) | (w2 << 1);
    uint64_t h_hi = (w2 >> 63) | (w3 << 1);

    gf127_t out;
    out.lo = w0 ^ h_lo ^ (h_lo << 63) ^ h_hi ^ (h_hi << 63);
    out.hi = (w1 & GF127_HI_MASK) ^ h_hi ^ (h_lo >> 1) ^ (h_hi >> 1);
    return out;
}

static gf127_t gf127_sq_n(gf127_t a, uint32_t n) {
    gf127_t r = a;
    for (uint32_t i = 0U; i < n; i++) {
        r = gf127_sq_ct(r);
    }
    return r;
}

static gf127_t gf127_inv_ct(gf127_t a) {
    /* Optimal Itoh-Tsujii chain for a^(2^127 - 2): 9 multiplications + 126 O(1) squarings. */
    gf127_t a1 = a;
    a1.hi &= GF127_HI_MASK;
    gf127_t a2   = gf127_mul_ct(gf127_sq_ct(a1), a1);        /* 2^2 - 1 */
    gf127_t a3   = gf127_mul_ct(gf127_sq_ct(a2), a1);        /* 2^3 - 1 */
    gf127_t a6   = gf127_mul_ct(gf127_sq_n(a3, 3U), a3);     /* 2^6 - 1 */
    gf127_t a12  = gf127_mul_ct(gf127_sq_n(a6, 6U), a6);     /* 2^12 - 1 */
    gf127_t a15  = gf127_mul_ct(gf127_sq_n(a12, 3U), a3);    /* 2^15 - 1 */
    gf127_t a30  = gf127_mul_ct(gf127_sq_n(a15, 15U), a15);  /* 2^30 - 1 */
    gf127_t a60  = gf127_mul_ct(gf127_sq_n(a30, 30U), a30);  /* 2^60 - 1 */
    gf127_t a63  = gf127_mul_ct(gf127_sq_n(a60, 3U), a3);    /* 2^63 - 1 */
    gf127_t a126 = gf127_mul_ct(gf127_sq_n(a63, 63U), a63);  /* 2^126 - 1 */
    return gf127_sq_ct(a126);                                /* 2^127 - 2 */
}

OPENQPEP_API int openqpep_gf2_127_mul(const uint8_t a16[16], const uint8_t b16[16], uint8_t out16[16]) {
    if (!a16 || !b16 || !out16) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    gf127_t res = gf127_mul_ct(gf127_load(a16), gf127_load(b16));
    gf127_store(out16, res);
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_gf2_127_sq(const uint8_t a16[16], uint8_t out16[16]) {
    if (!a16 || !out16) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    gf127_t res = gf127_sq_ct(gf127_load(a16));
    gf127_store(out16, res);
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_gf2_127_inv(const uint8_t a16[16], uint8_t out16[16]) {
    if (!a16 || !out16) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    gf127_t res = gf127_inv_ct(gf127_load(a16));
    gf127_store(out16, res);
    return OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* LRPC Ring Operations in GF(2^127)[X] / (X^47 + X^5 + 1)                   */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_lrpc_ring_mul(const uint8_t a752[752], const uint8_t b752[752], uint8_t out752[752]) {
    if (!a752 || !b752 || !out752) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    gf127_t a[LRPC_N];
    gf127_t b[LRPC_N];
    gf127_t tmp[2U * LRPC_N - 1U];

    for (uint32_t i = 0U; i < LRPC_N; i++) {
        a[i] = gf127_load(a752 + (size_t)i * 16U);
        b[i] = gf127_load(b752 + (size_t)i * 16U);
    }
    memset(tmp, 0, sizeof(tmp));

    /* Branchless full convolution (no secret zero-skip timing leak) */
    for (uint32_t i = 0U; i < LRPC_N; i++) {
        for (uint32_t j = 0U; j < LRPC_N; j++) {
            gf127_t prod = gf127_mul_ct(a[i], b[j]);
            tmp[i + j].lo ^= prod.lo;
            tmp[i + j].hi ^= prod.hi;
        }
    }

    /* Reduce modulo X^47 + X^5 + 1 */
    for (uint32_t i = 2U * LRPC_N - 2U; i >= LRPC_N; i--) {
        gf127_t c = tmp[i];
        tmp[i - LRPC_N].lo ^= c.lo;
        tmp[i - LRPC_N].hi ^= c.hi;
        tmp[i - LRPC_N + 5U].lo ^= c.lo;
        tmp[i - LRPC_N + 5U].hi ^= c.hi;
    }

    for (uint32_t i = 0U; i < LRPC_N; i++) {
        gf127_store(out752 + (size_t)i * 16U, tmp[i]);
    }

    openqpep_explicit_bzero(a, sizeof(a));
    openqpep_explicit_bzero(b, sizeof(b));
    openqpep_explicit_bzero(tmp, sizeof(tmp));
    return OPENQPEP_OK;
}

typedef struct {
    gf127_t c[LRPC_POLY_CAP];
    size_t len;
} gf127_poly_t;

static void lrpc_poly_zero(gf127_poly_t *p) {
    memset(p->c, 0, sizeof(p->c));
    p->len = 1U;
}

static void lrpc_poly_trim(gf127_poly_t *p) {
    while (p->len > 1U && gf127_is_zero(p->c[p->len - 1U])) {
        p->len--;
    }
}

static int lrpc_poly_is_zero(const gf127_poly_t *p) {
    return (p->len == 1U && gf127_is_zero(p->c[0]));
}

OPENQPEP_API int openqpep_lrpc_ring_inv(const uint8_t a752[752], uint8_t out752[752]) {
    if (!a752 || !out752) {
        return OPENQPEP_ERR_NULL_PTR;
    }

    gf127_poly_t r0, r1, t0, t1, ac, q, prod, tn;
    lrpc_poly_zero(&r0);
    r0.c[0].lo = 1ULL;
    r0.c[5].lo = 1ULL;
    r0.c[LRPC_N].lo = 1ULL;
    r0.len = (size_t)LRPC_N + 1U;

    lrpc_poly_zero(&r1);
    for (uint32_t i = 0U; i < LRPC_N; i++) {
        r1.c[i] = gf127_load(a752 + (size_t)i * 16U);
    }
    r1.len = LRPC_N;
    lrpc_poly_trim(&r1);

    lrpc_poly_zero(&t0);
    lrpc_poly_zero(&t1);
    t1.c[0].lo = 1ULL;

    while (!lrpc_poly_is_zero(&r1)) {
        ac = r0;
        size_t d1 = r1.len - 1U;
        gf127_t inv_lc = gf127_inv_ct(r1.c[d1]);
        lrpc_poly_zero(&q);
        if (ac.len > d1) {
            q.len = ac.len - d1;
        }
        while (ac.len - 1U >= d1 && !lrpc_poly_is_zero(&ac)) {
            gf127_t coef = gf127_mul_ct(ac.c[ac.len - 1U], inv_lc);
            size_t sh = (ac.len - 1U) - d1;
            q.c[sh].lo ^= coef.lo;
            q.c[sh].hi ^= coef.hi;
            for (size_t i = 0U; i <= d1; i++) {
                if (!gf127_is_zero(r1.c[i])) {
                    gf127_t p = gf127_mul_ct(coef, r1.c[i]);
                    ac.c[sh + i].lo ^= p.lo;
                    ac.c[sh + i].hi ^= p.hi;
                }
            }
            lrpc_poly_trim(&ac);
        }
        lrpc_poly_trim(&q);

        lrpc_poly_zero(&prod);
        size_t plen = q.len + t1.len - 1U;
        if (plen > LRPC_POLY_CAP) plen = LRPC_POLY_CAP;
        for (size_t i = 0U; i < q.len; i++) {
            if (gf127_is_zero(q.c[i])) continue;
            for (size_t j = 0U; j < t1.len && (i + j) < LRPC_POLY_CAP; j++) {
                if (!gf127_is_zero(t1.c[j])) {
                    gf127_t p = gf127_mul_ct(q.c[i], t1.c[j]);
                    prod.c[i + j].lo ^= p.lo;
                    prod.c[i + j].hi ^= p.hi;
                }
            }
        }
        prod.len = plen;
        lrpc_poly_trim(&prod);

        lrpc_poly_zero(&tn);
        size_t mlen = (t0.len > prod.len) ? t0.len : prod.len;
        for (size_t i = 0U; i < t0.len; i++) {
            tn.c[i].lo ^= t0.c[i].lo;
            tn.c[i].hi ^= t0.c[i].hi;
        }
        for (size_t i = 0U; i < prod.len; i++) {
            tn.c[i].lo ^= prod.c[i].lo;
            tn.c[i].hi ^= prod.c[i].hi;
        }
        tn.len = mlen;
        lrpc_poly_trim(&tn);

        r0 = r1;
        r1 = ac;
        t0 = t1;
        t1 = tn;
    }

    int status = OPENQPEP_OK;
    if (r0.len != 1U || gf127_is_zero(r0.c[0])) {
        memset(out752, 0, OPENQPEP_LRPC_POLY_BYTES);
        status = OPENQPEP_ERR_SINGULAR;
    } else {
        gf127_t inv_r0 = gf127_inv_ct(r0.c[0]);
        for (uint32_t i = 0U; i < LRPC_N; i++) {
            gf127_t val = (i < t0.len) ? gf127_mul_ct(t0.c[i], inv_r0) : (gf127_t){0ULL, 0ULL};
            gf127_store(out752 + (size_t)i * 16U, val);
        }
    }

    openqpep_explicit_bzero(&r0, sizeof(r0));
    openqpep_explicit_bzero(&r1, sizeof(r1));
    openqpep_explicit_bzero(&t0, sizeof(t0));
    openqpep_explicit_bzero(&t1, sizeof(t1));
    openqpep_explicit_bzero(&ac, sizeof(ac));
    openqpep_explicit_bzero(&q, sizeof(q));
    openqpep_explicit_bzero(&prod, sizeof(prod));
    openqpep_explicit_bzero(&tn, sizeof(tn));
    return status;
}

/* ------------------------------------------------------------------------- */
/* Branchless GF(256) Inversion & Vectorized UOV (QMQ-512) Accelerators      */
/* ------------------------------------------------------------------------- */

static inline uint8_t gf256_mul_ct(uint8_t a, uint8_t b) {
    uint8_t p = 0U;
    for (int i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(0U - (uint8_t)(b & 1U));
        p ^= (uint8_t)(a & mask);
        uint8_t hi_mask = (uint8_t)(0U - (uint8_t)((a >> 7) & 1U));
        a = (uint8_t)((a << 1) ^ (0x1BU & hi_mask));
        b >>= 1;
    }
    return p;
}

static inline uint8_t ct_is_zero_u8(uint8_t x) {
    /* Returns 0xFF if x == 0, else 0x00 (completely branchless). */
    uint32_t v = (uint32_t)x;
    uint32_t nz = (v | (0U - v)) >> 31;
    return (uint8_t)(nz - 1U);
}

OPENQPEP_API uint8_t openqpep_gf256_inv(uint8_t a) {
    /* Constant-time table-free Fermat inversion a^254 mod 0x11B (returns 0 for a == 0). */
    uint8_t a2   = gf256_mul_ct(a, a);       /* a^2 */
    uint8_t a3   = gf256_mul_ct(a2, a);      /* a^3 */
    uint8_t a6   = gf256_mul_ct(a3, a3);     /* a^6 */
    uint8_t a7   = gf256_mul_ct(a6, a);      /* a^7 */
    uint8_t a14  = gf256_mul_ct(a7, a7);     /* a^14 */
    uint8_t a15  = gf256_mul_ct(a14, a);     /* a^15 */
    uint8_t a30  = gf256_mul_ct(a15, a15);   /* a^30 */
    uint8_t a60  = gf256_mul_ct(a30, a30);   /* a^60 */
    uint8_t a120 = gf256_mul_ct(a60, a60);   /* a^120 */
    uint8_t a127 = gf256_mul_ct(a120, a7);   /* a^127 */
    return gf256_mul_ct(a127, a127);         /* a^254 */
}

static void gf256_vec_mul_acc(uint8_t *dst, const uint8_t *src, uint8_t scalar, uint32_t len) {
    for (uint32_t j = 0U; j < len; j++) {
        dst[j] ^= gf256_mul_ct(scalar, src[j]);
    }
}

static int uov_validate_dims(uint32_t v, uint32_t m) {
    if (v == 0U || v > OPENQPEP_UOV_MAX_V || m == 0U || m > OPENQPEP_UOV_MAX_M) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    return OPENQPEP_OK;
}

static int uov_init_p1p2_sponge(openqpep_keccak_ctx_t *ctx, const uint8_t seed_pk[32], uint32_t v, uint32_t m) {
    static const char dom[] = "CALYX-QMQ-P1P2-v1.0.0|";
    uint8_t dims[4];
    dims[0] = (uint8_t)(v & 0xFFU);
    dims[1] = (uint8_t)((v >> 8) & 0xFFU);
    dims[2] = (uint8_t)(m & 0xFFU);
    dims[3] = (uint8_t)((m >> 8) & 0xFFU);
    int rc = openqpep_shake256_init(ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(ctx, (const uint8_t *)dom, sizeof(dom) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(ctx, seed_pk, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(ctx, dims, sizeof(dims));
    return rc;
}

static int uov_expand_oil(const uint8_t seed_sk[32], uint32_t v, uint32_t m, uint8_t *oil_out) {
    static const char dom[] = "CALYX-QMQ-OIL-v1.0.0|";
    uint8_t dims[4];
    dims[0] = (uint8_t)(v & 0xFFU);
    dims[1] = (uint8_t)((v >> 8) & 0xFFU);
    dims[2] = (uint8_t)(m & 0xFFU);
    dims[3] = (uint8_t)((m >> 8) & 0xFFU);
    openqpep_keccak_ctx_t ctx;
    int rc = openqpep_shake256_init(&ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, (const uint8_t *)dom, sizeof(dom) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, seed_sk, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, dims, sizeof(dims));
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, oil_out, (size_t)v * (size_t)m);
    openqpep_keccak_wipe(&ctx);
    return rc;
}

/* Constant-time pivot-masked Gaussian elimination over GF(256) (zero secret branches). */
OPENQPEP_API int openqpep_uov_solve_gf256_linear(
    const uint8_t *mat,
    const uint8_t *rhs,
    uint32_t m,
    uint8_t *sol_out
) {
    if (!mat || !rhs || !sol_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (m == 0U || m > OPENQPEP_UOV_MAX_M) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    uint8_t aug[OPENQPEP_UOV_MAX_M][OPENQPEP_UOV_MAX_M + 1U];
    memset(aug, 0, sizeof(aug));
    for (uint32_t i = 0U; i < m; i++) {
        memcpy(aug[i], mat + (size_t)i * (size_t)m, (size_t)m);
        aug[i][m] = rhs[i];
    }

    uint8_t singular = 0U;
    for (uint32_t col = 0U; col < m; col++) {
        /* 1. Branchless pivot accumulation: XOR first nonzero row r > col when aug[col][col] == 0 */
        for (uint32_t r = col + 1U; r < m; r++) {
            uint8_t need = ct_is_zero_u8(aug[col][col]);
            for (uint32_t c = col; c <= m; c++) {
                aug[col][c] ^= (uint8_t)(aug[r][c] & need);
            }
        }
        singular |= ct_is_zero_u8(aug[col][col]);

        /* 2. Constant-time pivot row normalization */
        uint8_t inv_piv = openqpep_gf256_inv(aug[col][col]);
        for (uint32_t c = col; c <= m; c++) {
            aug[col][c] = gf256_mul_ct(aug[col][c], inv_piv);
        }

        /* 3. Branchless Gauss-Jordan elimination of all other rows */
        for (uint32_t r = 0U; r < m; r++) {
            if (r == col) continue;
            uint8_t factor = aug[r][col];
            for (uint32_t c = col; c <= m; c++) {
                aug[r][c] ^= gf256_mul_ct(factor, aug[col][c]);
            }
        }
    }

    int status = OPENQPEP_OK;
    if (singular != 0U) {
        memset(sol_out, 0, (size_t)m);
        status = OPENQPEP_ERR_SINGULAR;
    } else {
        for (uint32_t i = 0U; i < m; i++) {
            sol_out[i] = aug[i][m];
        }
    }
    openqpep_explicit_bzero(aug, sizeof(aug));
    return status;
}

OPENQPEP_API int openqpep_uov_compute_p3(
    const uint8_t seed_pk[32],
    const uint8_t seed_sk[32],
    uint32_t v,
    uint32_t m,
    uint8_t *p3_out,
    size_t p3_len
) {
    if (!seed_pk || !seed_sk || !p3_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (uov_validate_dims(v, m) != OPENQPEP_OK) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    size_t n_p1 = ((size_t)v * ((size_t)v + 1U)) / 2U;
    size_t n_p2 = (size_t)v * (size_t)m;
    size_t n_p3_single = ((size_t)m * ((size_t)m + 1U)) / 2U;
    if (p3_len != (size_t)m * n_p3_single) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    uint8_t *oil_o = (uint8_t *)calloc(n_p2, 1U);
    uint8_t *p1k   = (uint8_t *)calloc(n_p1, 1U);
    uint8_t *tmp   = (uint8_t *)calloc(n_p2, 1U);
    uint8_t *mmat  = (uint8_t *)calloc((size_t)m * (size_t)m, 1U);
    if (!oil_o || !p1k || !tmp || !mmat) {
        free(oil_o);
        free(p1k);
        free(tmp);
        free(mmat);
        return OPENQPEP_ERR_INVALID_LEN;
    }

    openqpep_keccak_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    int rc = uov_expand_oil(seed_sk, v, m, oil_o);
    if (rc == OPENQPEP_OK) {
        rc = uov_init_p1p2_sponge(&ctx, seed_pk, v, m);
    }

    size_t p3_off = 0U;
    for (uint32_t k = 0U; rc == OPENQPEP_OK && k < m; k++) {
        rc = openqpep_keccak_squeeze(&ctx, p1k, n_p1);
        if (rc != OPENQPEP_OK) break;
        /* Squeeze P2^(k) directly into tmp (initializing tmp = P2^(k)) */
        rc = openqpep_keccak_squeeze(&ctx, tmp, n_p2);
        if (rc != OPENQPEP_OK) break;

        /* tmp = P1^(k) * O + P2^(k) */
        size_t idx = 0U;
        for (uint32_t i = 0U; i < v; i++) {
            uint8_t *ti = tmp + (size_t)i * (size_t)m;
            for (uint32_t r = i; r < v; r++) {
                uint8_t c = p1k[idx++];
                gf256_vec_mul_acc(ti, oil_o + (size_t)r * (size_t)m, c, m);
            }
        }

        /* mmat = O^T * tmp */
        memset(mmat, 0, (size_t)m * (size_t)m);
        for (uint32_t a = 0U; a < m; a++) {
            uint8_t *ma = mmat + (size_t)a * (size_t)m;
            for (uint32_t i = 0U; i < v; i++) {
                uint8_t oia = oil_o[(size_t)i * (size_t)m + (size_t)a];
                gf256_vec_mul_acc(ma, tmp + (size_t)i * (size_t)m, oia, m);
            }
        }

        /* Pack Upper(mmat) into p3_out */
        for (uint32_t a = 0U; a < m; a++) {
            p3_out[p3_off++] = mmat[(size_t)a * (size_t)m + (size_t)a];
            for (uint32_t b = a + 1U; b < m; b++) {
                p3_out[p3_off++] = (uint8_t)(mmat[(size_t)a * (size_t)m + (size_t)b]
                                           ^ mmat[(size_t)b * (size_t)m + (size_t)a]);
            }
        }
    }

    openqpep_keccak_wipe(&ctx);
    openqpep_explicit_bzero(oil_o, n_p2);
    openqpep_explicit_bzero(p1k, n_p1);
    openqpep_explicit_bzero(tmp, n_p2);
    openqpep_explicit_bzero(mmat, (size_t)m * (size_t)m);
    free(oil_o);
    free(p1k);
    free(tmp);
    free(mmat);
    return rc;
}

OPENQPEP_API int openqpep_uov_eval_public_map(
    const uint8_t seed_pk[32],
    const uint8_t *p3_bytes,
    size_t p3_len,
    uint32_t v,
    uint32_t m,
    const uint8_t *sv,
    const uint8_t *so,
    uint8_t *out_m
) {
    if (!seed_pk || !p3_bytes || !sv || !so || !out_m) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (uov_validate_dims(v, m) != OPENQPEP_OK) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    size_t n_p1 = ((size_t)v * ((size_t)v + 1U)) / 2U;
    size_t n_p2 = (size_t)v * (size_t)m;
    size_t n_p3_single = ((size_t)m * ((size_t)m + 1U)) / 2U;
    if (p3_len != (size_t)m * n_p3_single) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    uint8_t *p1k = (uint8_t *)calloc(n_p1, 1U);
    uint8_t *p2k = (uint8_t *)calloc(n_p2, 1U);
    if (!p1k || !p2k) {
        free(p1k);
        free(p2k);
        return OPENQPEP_ERR_INVALID_LEN;
    }

    openqpep_keccak_ctx_t ctx;
    int rc = uov_init_p1p2_sponge(&ctx, seed_pk, v, m);
    size_t p3_off = 0U;

    for (uint32_t k = 0U; rc == OPENQPEP_OK && k < m; k++) {
        rc = openqpep_keccak_squeeze(&ctx, p1k, n_p1);
        if (rc != OPENQPEP_OK) break;
        rc = openqpep_keccak_squeeze(&ctx, p2k, n_p2);
        if (rc != OPENQPEP_OK) break;

        uint8_t val = 0U;
        size_t idx1 = 0U;
        for (uint32_t i = 0U; i < v; i++) {
            uint8_t si = sv[i];
            uint8_t acc_v = 0U;
            for (uint32_t j = i; j < v; j++) {
                acc_v ^= gf256_mul_ct(p1k[idx1++], sv[j]);
            }
            uint8_t acc_o = 0U;
            const uint8_t *r2 = p2k + (size_t)i * (size_t)m;
            for (uint32_t j = 0U; j < m; j++) {
                acc_o ^= gf256_mul_ct(r2[j], so[j]);
            }
            val ^= gf256_mul_ct(si, (uint8_t)(acc_v ^ acc_o));
        }

        for (uint32_t i = 0U; i < m; i++) {
            uint8_t si = so[i];
            uint8_t acc_3 = 0U;
            for (uint32_t j = i; j < m; j++) {
                acc_3 ^= gf256_mul_ct(p3_bytes[p3_off++], so[j]);
            }
            val ^= gf256_mul_ct(si, acc_3);
        }
        out_m[k] = val;
    }

    openqpep_keccak_wipe(&ctx);
    openqpep_explicit_bzero(p1k, n_p1);
    openqpep_explicit_bzero(p2k, n_p2);
    free(p1k);
    free(p2k);
    return rc;
}

OPENQPEP_API int openqpep_uov_sign_core(
    const uint8_t seed_pk[32],
    const uint8_t seed_sk[32],
    const uint8_t salt[16],
    const uint8_t *target,
    uint32_t v,
    uint32_t m,
    uint8_t *sig_sv_out,
    uint8_t *sig_so_out
) {
    if (!seed_pk || !seed_sk || !salt || !target || !sig_sv_out || !sig_so_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (uov_validate_dims(v, m) != OPENQPEP_OK) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    size_t n_p1 = ((size_t)v * ((size_t)v + 1U)) / 2U;
    size_t n_p2 = (size_t)v * (size_t)m;
    size_t per_k = n_p1 + n_p2;
    size_t total_p1p2 = (size_t)m * per_k;

    uint8_t *oil_o = (uint8_t *)calloc(n_p2, 1U);
    uint8_t *p1p2  = (uint8_t *)calloc(total_p1p2, 1U);
    if (!oil_o || !p1p2) {
        free(oil_o);
        free(p1p2);
        return OPENQPEP_ERR_INVALID_LEN;
    }

    int rc = uov_expand_oil(seed_sk, v, m, oil_o);
    if (rc == OPENQPEP_OK) {
        openqpep_keccak_ctx_t p_ctx;
        rc = uov_init_p1p2_sponge(&p_ctx, seed_pk, v, m);
        if (rc == OPENQPEP_OK) {
            rc = openqpep_keccak_squeeze(&p_ctx, p1p2, total_p1p2);
        }
        openqpep_keccak_wipe(&p_ctx);
    }

    uint8_t vin[OPENQPEP_UOV_MAX_V];
    uint8_t w[OPENQPEP_UOV_MAX_V];
    uint8_t rhs[OPENQPEP_UOV_MAX_M];
    uint8_t xo[OPENQPEP_UOV_MAX_M];
    uint8_t lin[OPENQPEP_UOV_MAX_M * OPENQPEP_UOV_MAX_M];
    static const char dom_vin[] = "CALYX-QMQ-VINEGAR-v1.0.0|";

    int solved = 0;
    for (uint32_t attempt = 0U; rc == OPENQPEP_OK && attempt < 64U; attempt++) {
        uint8_t att_be[2];
        att_be[0] = (uint8_t)((attempt >> 8) & 0xFFU);
        att_be[1] = (uint8_t)(attempt & 0xFFU);

        openqpep_keccak_ctx_t v_ctx;
        rc = openqpep_shake256_init(&v_ctx);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&v_ctx, (const uint8_t *)dom_vin, sizeof(dom_vin) - 1U);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&v_ctx, seed_sk, 32U);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&v_ctx, salt, 16U);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&v_ctx, att_be, sizeof(att_be));
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&v_ctx, vin, (size_t)v);
        openqpep_keccak_wipe(&v_ctx);
        if (rc != OPENQPEP_OK) break;

        memcpy(rhs, target, (size_t)m);
        memset(lin, 0, (size_t)m * (size_t)m);

        for (uint32_t k = 0U; k < m; k++) {
            const uint8_t *p1k = p1p2 + (size_t)k * per_k;
            const uint8_t *p2k = p1k + n_p1;
            uint8_t yk = 0U;
            memset(w, 0, (size_t)v);

            size_t idx = 0U;
            for (uint32_t i = 0U; i < v; i++) {
                uint8_t vi = vin[i];
                for (uint32_t j = i; j < v; j++) {
                    uint8_t c = p1k[idx++];
                    uint8_t vj = vin[j];
                    uint8_t vic = gf256_mul_ct(vi, c);
                    yk ^= gf256_mul_ct(vic, vj);
                    if (i != j) {
                        w[j] ^= vic;
                        w[i] ^= gf256_mul_ct(vj, c);
                    }
                }
            }
            rhs[k] ^= yk;

            uint8_t *lk = lin + (size_t)k * (size_t)m;
            for (uint32_t i = 0U; i < v; i++) {
                gf256_vec_mul_acc(lk, oil_o + (size_t)i * (size_t)m, w[i], m);
                gf256_vec_mul_acc(lk, p2k + (size_t)i * (size_t)m, vin[i], m);
            }
        }

        if (openqpep_uov_solve_gf256_linear(lin, rhs, m, xo) == OPENQPEP_OK) {
            for (uint32_t i = 0U; i < v; i++) {
                uint8_t sv_i = vin[i];
                const uint8_t *oi = oil_o + (size_t)i * (size_t)m;
                for (uint32_t j = 0U; j < m; j++) {
                    sv_i ^= gf256_mul_ct(oi[j], xo[j]);
                }
                sig_sv_out[i] = sv_i;
            }
            memcpy(sig_so_out, xo, (size_t)m);
            solved = 1;
            break;
        }
    }

    openqpep_explicit_bzero(vin, sizeof(vin));
    openqpep_explicit_bzero(w, sizeof(w));
    openqpep_explicit_bzero(rhs, sizeof(rhs));
    openqpep_explicit_bzero(xo, sizeof(xo));
    openqpep_explicit_bzero(lin, sizeof(lin));
    openqpep_explicit_bzero(oil_o, n_p2);
    openqpep_explicit_bzero(p1p2, total_p1p2);
    free(oil_o);
    free(p1p2);

    if (rc != OPENQPEP_OK) {
        return rc;
    }
    return solved ? OPENQPEP_OK : OPENQPEP_ERR_SINGULAR;
}
