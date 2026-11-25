/*
 * OpenQPEP Native C99 / SIMD Polynomial Ring Codecs, Samplers & Matrix-Vector Engine (QLX + QVS)
 * Official Release 1.2.5 (v1.2.5) — Calyx Labs Inc. (CPOSLS-1.0)
 *
 * Implements:
 *   - KyberSlash-immune division-free QLX compression/decompression & 12-bit byte encoding/decoding
 *   - Streaming zero-heap QLX NTT matrix-vector multiply (A*s + e / A^T*r) & fused inner products
 *   - Division-free QVS 24-bit poly packing/unpacking, mask-y & ball sampling
 *   - Precomputed & streaming QVS matrix-vector multiplication with 64-bit Solinas-Barrett reduction
 *   - Compiler-barrier explicit zeroization (openqpep_explicit_bzero) on all stack secret scratch
 *
 * 100% ISO C99 (-Wall -Wextra -Werror -Wpedantic), bit-for-bit identical to poly_ring.py,
 * qlx_kem.py, and qvs_dsa.py.
 */
#include "openqpep.h"
#include <string.h>

#define QLX_Q_I32          OPENQPEP_QLX_Q
#define QLX_Q_U64          3329ULL
#define QLX_HALF_Q_U64     1664ULL
#define QLX_COMPRESS_RECIP 20642679ULL
#define QLX_BARRETT_M36    20642678ULL

#define QVS_Q_I32          OPENQPEP_QVS_Q
#define QVS_Q_I64          8380417LL
#define QVS_GAMMA1_I32     524288

static inline int32_t ct_caddq_3329(int32_t a) {
    int32_t mask = -(int32_t)((uint32_t)a >> 31);
    return a + (mask & QLX_Q_I32);
}

static inline int32_t ct_csubq_3329(int32_t a) {
    int32_t d = a - QLX_Q_I32;
    int32_t mask = -(int32_t)((uint32_t)d >> 31);
    return d + (mask & QLX_Q_I32);
}

/* Exact division-free canonical reduction mod 3329 for ALL signed int32_t (INT32_MIN..INT32_MAX). */
static inline int32_t ct_barrett_3329_i32(int32_t c) {
    /* 645084 * 3329 = 2,147,484,636 > 2^31 -> u strictly in [988, 4,294,968,283] < 2^32. */
    uint64_t u = (uint64_t)((int64_t)c + (645084LL * 3329LL));
    uint64_t t = (u * QLX_BARRETT_M36) >> 36;
    int32_t r = (int32_t)(u - t * QLX_Q_U64);
    return ct_csubq_3329(r);
}

static inline int32_t ct_caddq_qvs(int32_t a) {
    int32_t mask = -(int32_t)((uint32_t)a >> 31);
    return a + (mask & QVS_Q_I32);
}

static inline int32_t ct_csubq_qvs(int32_t a) {
    int32_t d = a - QVS_Q_I32;
    int32_t mask = -(int32_t)((uint32_t)d >> 31);
    return d + (mask & QVS_Q_I32);
}

/* Division-free branchless Solinas reduction mod 8380417 = 2^23 - 2^13 + 1 for all x in [0, 2^50). */
static inline int32_t ct_reduce_qvs_u64(uint64_t x) {
    uint64_t hi = x >> 23;
    uint64_t y = (x & 0x7FFFFFULL) + (hi << 13) - hi;
    hi = y >> 23;
    uint64_t z = (y & 0x7FFFFFULL) + (hi << 13) - hi;
    hi = z >> 23;
    uint64_t r = (z & 0x7FFFFFULL) + (hi << 13) - hi;
    return ct_csubq_qvs((int32_t)r);
}

static inline int32_t ct_reduce_qvs_i32(int32_t c) {
    uint64_t shifted = (uint64_t)((int64_t)c + (257LL * QVS_Q_I64));
    return ct_reduce_qvs_u64(shifted);
}

/* ------------------------------------------------------------------------- */
/* QLX Bit-Packing & KyberSlash-Free Compression (Z_3329)                    */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_byte_encode_12(const int32_t *poly, uint8_t out384[384]) {
    if (!poly || !out384) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    for (int i = 0; i < 128; i++) {
        uint32_t c0 = (uint32_t)ct_barrett_3329_i32(poly[2 * i]);
        uint32_t c1 = (uint32_t)ct_barrett_3329_i32(poly[2 * i + 1]);
        out384[3 * i]     = (uint8_t)(c0 & 0xFFU);
        out384[3 * i + 1] = (uint8_t)(((c0 >> 8) & 0x0FU) | ((c1 & 0x0FU) << 4));
        out384[3 * i + 2] = (uint8_t)((c1 >> 4) & 0xFFU);
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_byte_decode_12(const uint8_t in384[384], int32_t out_poly[256]) {
    if (!in384 || !out_poly) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    for (int i = 0; i < 128; i++) {
        int32_t b0 = (int32_t)in384[3 * i];
        int32_t b1 = (int32_t)in384[3 * i + 1];
        int32_t b2 = (int32_t)in384[3 * i + 2];
        out_poly[2 * i]     = ct_csubq_3329(b0 | ((b1 & 0x0F) << 8));
        out_poly[2 * i + 1] = ct_csubq_3329((b1 >> 4) | (b2 << 4));
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_poly_compress_3329(const int32_t *poly, uint32_t d, uint8_t *out, size_t out_len) {
    if (!poly || !out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (d < 1U || d > 12U || out_len != (size_t)(32U * d)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    uint32_t mask = (1U << d) - 1U;
    uint32_t bits = 0U;
    uint32_t bit_len = 0U;
    size_t out_idx = 0U;
    for (int i = 0; i < 256; i++) {
        uint64_t x = (uint64_t)(uint32_t)ct_barrett_3329_i32(poly[i]);
        uint32_t val = (uint32_t)(((((x << d) + QLX_HALF_Q_U64) * QLX_COMPRESS_RECIP) >> 36) & (uint64_t)mask);
        bits |= (val << bit_len);
        bit_len += d;
        while (bit_len >= 8U) {
            out[out_idx++] = (uint8_t)(bits & 0xFFU);
            bits >>= 8;
            bit_len -= 8U;
        }
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_poly_decompress_3329(const uint8_t *in, size_t in_len, uint32_t d, int32_t out_poly[256]) {
    if (!in || !out_poly) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (d < 1U || d > 12U || in_len != (size_t)(32U * d)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    uint32_t mask = (1U << d) - 1U;
    uint32_t half = 1U << (d - 1U);
    uint32_t bits = 0U;
    uint32_t bit_len = 0U;
    size_t idx = 0U;
    for (int i = 0; i < 256; i++) {
        while (bit_len < d) {
            bits |= ((uint32_t)in[idx++]) << bit_len;
            bit_len += 8U;
        }
        uint32_t val = bits & mask;
        bits >>= d;
        bit_len -= d;
        out_poly[i] = (int32_t)(((val * 3329U) + half) >> d);
    }
    return OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* QLX Matrix Sampling & Streaming Matrix-Vector Engine (Z_3329)             */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_qlx_sample_ntt_3329(const uint8_t rho[32], uint8_t row, uint8_t col, int32_t out_poly[256]) {
    if (!rho || !out_poly) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    static const uint8_t domain[16] = {
        'C', 'A', 'L', 'Y', 'X', '-', 'Q', 'L', 'X', '-', 'M', 'A', 'T', '-', 'A', '|'
    };
    uint8_t seed[50];
    uint8_t stream[840];
    memcpy(seed, domain, 16);
    memcpy(seed + 16, rho, 32);
    seed[48] = col;
    seed[49] = row;

    int rc = openqpep_qsponge_var(seed, sizeof(seed), stream, sizeof(stream));
    if (rc != OPENQPEP_OK) {
        return rc;
    }

    size_t idx = 0U;
    size_t cnt = 0U;
    while (cnt < 256U) {
        if (idx + 2U >= sizeof(stream)) {
            return OPENQPEP_ERR_INVALID_LEN;
        }
        int32_t d1 = (int32_t)stream[idx] + (((int32_t)(stream[idx + 1U] & 0x0FU)) << 8);
        int32_t d2 = (int32_t)(stream[idx + 1U] >> 4) + (((int32_t)stream[idx + 2U]) << 4);
        idx += 3U;
        if (d1 < QLX_Q_I32) {
            out_poly[cnt++] = d1;
        }
        if (d2 < QLX_Q_I32 && cnt < 256U) {
            out_poly[cnt++] = d2;
        }
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qlx_matvec_3329(
    const uint8_t rho[32],
    uint32_t k,
    int transpose,
    const int32_t *vec_hat,
    const int32_t *add_hat,
    int32_t *out_hat
) {
    if (!rho || !vec_hat || !out_hat) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (k == 0U || k > 255U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    int32_t a_ij[256];
    int32_t acc[256];

    for (uint32_t i = 0U; i < k; i++) {
        memset(acc, 0, sizeof(acc));
        for (uint32_t j = 0U; j < k; j++) {
            uint8_t r = (uint8_t)(transpose ? j : i);
            uint8_t c = (uint8_t)(transpose ? i : j);
            int rc = openqpep_qlx_sample_ntt_3329(rho, r, c, a_ij);
            if (rc != OPENQPEP_OK) {
                openqpep_explicit_bzero(a_ij, sizeof(a_ij));
                openqpep_explicit_bzero(acc, sizeof(acc));
                return rc;
            }
            openqpep_ntt_base_mul_acc_3329(acc, a_ij, vec_hat + ((size_t)j * 256U));
        }
        int32_t *dst = out_hat + ((size_t)i * 256U);
        if (add_hat) {
            openqpep_poly_add_3329(acc, add_hat + ((size_t)i * 256U), dst);
        } else {
            memcpy(dst, acc, sizeof(acc));
        }
    }

    openqpep_explicit_bzero(a_ij, sizeof(a_ij));
    openqpep_explicit_bzero(acc, sizeof(acc));
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qlx_inner_prod_3329(
    const int32_t *a_vec_hat,
    const int32_t *b_vec_hat,
    uint32_t k,
    int32_t out_poly[256]
) {
    if (!a_vec_hat || !b_vec_hat || !out_poly) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (k == 0U || k > 255U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    int32_t acc[256];
    memset(acc, 0, sizeof(acc));
    for (uint32_t j = 0U; j < k; j++) {
        openqpep_ntt_base_mul_acc_3329(
            acc,
            a_vec_hat + ((size_t)j * 256U),
            b_vec_hat + ((size_t)j * 256U)
        );
    }
    memcpy(out_poly, acc, sizeof(acc));
    openqpep_explicit_bzero(acc, sizeof(acc));
    return OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* QVS Bit-Packing, Sampling & Matrix-Vector Engine (Z_8380417)              */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_qvs_pack_poly24(const int32_t *poly, uint8_t out768[768]) {
    if (!poly || !out768) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    for (int i = 0; i < 256; i++) {
        uint32_t v = (uint32_t)ct_reduce_qvs_i32(poly[i]);
        out768[3 * i]     = (uint8_t)(v & 0xFFU);
        out768[3 * i + 1] = (uint8_t)((v >> 8) & 0xFFU);
        out768[3 * i + 2] = (uint8_t)((v >> 16) & 0xFFU);
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qvs_unpack_poly24(const uint8_t in768[768], int32_t out_poly[256]) {
    if (!in768 || !out_poly) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    for (int i = 0; i < 256; i++) {
        int32_t raw = (int32_t)in768[3 * i]
                    | (((int32_t)in768[3 * i + 1]) << 8)
                    | (((int32_t)in768[3 * i + 2]) << 16);
        out_poly[i] = ct_csubq_qvs(ct_csubq_qvs(raw));
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qvs_sample_ntt(const uint8_t rho[32], uint8_t row, uint8_t col, int32_t out_poly[256]) {
    if (!rho || !out_poly) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    static const uint8_t domain[16] = {
        'C', 'A', 'L', 'Y', 'X', '-', 'Q', 'V', 'S', '-', 'M', 'A', 'T', '-', 'A', '|'
    };
    uint8_t seed[50];
    uint8_t stream[1024];
    memcpy(seed, domain, 16);
    memcpy(seed + 16, rho, 32);
    seed[48] = row;
    seed[49] = col;

    int rc = openqpep_qsponge_var(seed, sizeof(seed), stream, sizeof(stream));
    if (rc != OPENQPEP_OK) {
        return rc;
    }

    size_t idx = 0U;
    size_t cnt = 0U;
    while (cnt < 256U) {
        if (idx + 2U >= sizeof(stream)) {
            return OPENQPEP_ERR_INVALID_LEN;
        }
        int32_t val = ((int32_t)stream[idx]
                    | (((int32_t)stream[idx + 1U]) << 8)
                    | (((int32_t)stream[idx + 2U]) << 16)) & 0x7FFFFF;
        idx += 3U;
        if (val < QVS_Q_I32) {
            out_poly[cnt++] = val;
        }
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qvs_sample_mask_y(const uint8_t *seed, size_t seed_len, uint16_t nonce, int32_t out_poly[256]) {
    if (!out_poly || (seed_len > 0U && !seed)) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    static const uint8_t domain[17] = {
        'C', 'A', 'L', 'Y', 'X', '-', 'Q', 'V', 'S', '-', 'M', 'A', 'S', 'K', '-', 'Y', '|'
    };
    uint8_t nonce_le[2];
    nonce_le[0] = (uint8_t)(nonce & 0xFFU);
    nonce_le[1] = (uint8_t)((nonce >> 8) & 0xFFU);

    openqpep_keccak_ctx_t ctx;
    uint8_t raw_buf[768];
    int rc = openqpep_shake256_init(&ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, domain, sizeof(domain));
    if (rc == OPENQPEP_OK && seed_len > 0U) rc = openqpep_keccak_absorb(&ctx, seed, seed_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, nonce_le, sizeof(nonce_le));
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, raw_buf, sizeof(raw_buf));
    openqpep_keccak_wipe(&ctx);
    if (rc != OPENQPEP_OK) {
        openqpep_explicit_bzero(raw_buf, sizeof(raw_buf));
        return rc;
    }

    for (int i = 0; i < 256; i++) {
        int32_t raw = ((int32_t)raw_buf[3 * i]
                    | (((int32_t)raw_buf[3 * i + 1]) << 8)
                    | (((int32_t)raw_buf[3 * i + 2]) << 16)) & 0xFFFFF;
        out_poly[i] = ct_caddq_qvs(QVS_GAMMA1_I32 - raw);
    }
    openqpep_explicit_bzero(raw_buf, sizeof(raw_buf));
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qvs_sample_in_ball(const uint8_t *c_tilde, size_t c_tilde_len, uint32_t tau, int32_t out_poly[256]) {
    if (!out_poly || (c_tilde_len > 0U && !c_tilde)) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (tau > 64U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    static const uint8_t domain[15] = {
        'C', 'A', 'L', 'Y', 'X', '-', 'Q', 'V', 'S', '-', 'B', 'A', 'L', 'L', '|'
    };
    openqpep_keccak_ctx_t ctx;
    uint8_t stream[256];
    int rc = openqpep_shake256_init(&ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, domain, sizeof(domain));
    if (rc == OPENQPEP_OK && c_tilde_len > 0U) rc = openqpep_keccak_absorb(&ctx, c_tilde, c_tilde_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, stream, sizeof(stream));
    openqpep_keccak_wipe(&ctx);
    if (rc != OPENQPEP_OK) {
        return rc;
    }

    uint64_t sign_bits = ((uint64_t)stream[0])
                       | (((uint64_t)stream[1]) << 8)
                       | (((uint64_t)stream[2]) << 16)
                       | (((uint64_t)stream[3]) << 24)
                       | (((uint64_t)stream[4]) << 32)
                       | (((uint64_t)stream[5]) << 40)
                       | (((uint64_t)stream[6]) << 48)
                       | (((uint64_t)stream[7]) << 56);

    memset(out_poly, 0, 256U * sizeof(int32_t));
    size_t idx = 8U;
    for (uint32_t i = 256U - tau; i < 256U; i++) {
        uint32_t j = 0U;
        for (;;) {
            if (idx >= sizeof(stream)) {
                return OPENQPEP_ERR_INVALID_LEN;
            }
            j = (uint32_t)stream[idx++];
            if (j <= i) {
                break;
            }
        }
        out_poly[i] = out_poly[j];
        uint32_t neg_mask = (uint32_t)(-(int32_t)(sign_bits & 1ULL));
        out_poly[j] = (int32_t)(((uint32_t)(QVS_Q_I32 - 1) & neg_mask) | (1U & ~neg_mask));
        sign_bits >>= 1;
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qvs_expand_matrix(const uint8_t rho[32], uint32_t k, uint32_t l, int32_t *a_hat_flat) {
    if (!rho || !a_hat_flat) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (k == 0U || l == 0U || k > 255U || l > 255U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    for (uint32_t i = 0U; i < k; i++) {
        for (uint32_t j = 0U; j < l; j++) {
            size_t offset = ((size_t)i * (size_t)l + (size_t)j) * 256U;
            int rc = openqpep_qvs_sample_ntt(rho, (uint8_t)i, (uint8_t)j, a_hat_flat + offset);
            if (rc != OPENQPEP_OK) {
                return rc;
            }
        }
    }
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qvs_matvec_precomputed(
    const int32_t *a_hat_flat,
    uint32_t k,
    uint32_t l,
    const int32_t *vec_hat,
    int32_t *out_hat
) {
    if (!a_hat_flat || !vec_hat || !out_hat) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (k == 0U || l == 0U || k > 255U || l > 255U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    uint64_t acc[256];
    for (uint32_t i = 0U; i < k; i++) {
        memset(acc, 0, sizeof(acc));
        for (uint32_t j = 0U; j < l; j++) {
            const int32_t *a_ij = a_hat_flat + (((size_t)i * (size_t)l + (size_t)j) * 256U);
            const int32_t *v_j  = vec_hat + ((size_t)j * 256U);
            for (int m = 0; m < 256; m++) {
                uint64_t a_m = (uint64_t)(uint32_t)ct_reduce_qvs_i32(a_ij[m]);
                uint64_t v_m = (uint64_t)(uint32_t)ct_reduce_qvs_i32(v_j[m]);
                acc[m] += a_m * v_m;
            }
            /* Keep sum strictly below 2^50 (16 * QVS_Q^2 < 2^50) for arbitrary l. */
            if (((j + 1U) & 15U) == 0U) {
                for (int m = 0; m < 256; m++) {
                    acc[m] = (uint64_t)(uint32_t)ct_reduce_qvs_u64(acc[m]);
                }
            }
        }
        int32_t *dst = out_hat + ((size_t)i * 256U);
        for (int m = 0; m < 256; m++) {
            dst[m] = ct_reduce_qvs_u64(acc[m]);
        }
    }
    openqpep_explicit_bzero(acc, sizeof(acc));
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_qvs_matvec(
    const uint8_t rho[32],
    uint32_t k,
    uint32_t l,
    const int32_t *vec_hat,
    const int32_t *add_vec,
    int apply_inv_ntt,
    int32_t *out_vec
) {
    if (!rho || !vec_hat || !out_vec) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (k == 0U || l == 0U || k > 255U || l > 255U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    int32_t a_ij[256];
    uint64_t acc[256];
    int32_t row_out[256];

    for (uint32_t i = 0U; i < k; i++) {
        memset(acc, 0, sizeof(acc));
        for (uint32_t j = 0U; j < l; j++) {
            int rc = openqpep_qvs_sample_ntt(rho, (uint8_t)i, (uint8_t)j, a_ij);
            if (rc != OPENQPEP_OK) {
                openqpep_explicit_bzero(a_ij, sizeof(a_ij));
                openqpep_explicit_bzero(acc, sizeof(acc));
                openqpep_explicit_bzero(row_out, sizeof(row_out));
                return rc;
            }
            const int32_t *v_j = vec_hat + ((size_t)j * 256U);
            for (int m = 0; m < 256; m++) {
                uint64_t a_m = (uint64_t)(uint32_t)a_ij[m];
                uint64_t v_m = (uint64_t)(uint32_t)ct_reduce_qvs_i32(v_j[m]);
                acc[m] += a_m * v_m;
            }
            if (((j + 1U) & 15U) == 0U) {
                for (int m = 0; m < 256; m++) {
                    acc[m] = (uint64_t)(uint32_t)ct_reduce_qvs_u64(acc[m]);
                }
            }
        }
        for (int m = 0; m < 256; m++) {
            row_out[m] = ct_reduce_qvs_u64(acc[m]);
        }
        if (apply_inv_ntt) {
            openqpep_inv_ntt_qvs(row_out);
        }
        int32_t *dst = out_vec + ((size_t)i * 256U);
        if (add_vec) {
            openqpep_poly_add_qvs(row_out, add_vec + ((size_t)i * 256U), dst);
        } else {
            memcpy(dst, row_out, sizeof(row_out));
        }
    }

    openqpep_explicit_bzero(a_ij, sizeof(a_ij));
    openqpep_explicit_bzero(acc, sizeof(acc));
    openqpep_explicit_bzero(row_out, sizeof(row_out));
    return OPENQPEP_OK;
}
