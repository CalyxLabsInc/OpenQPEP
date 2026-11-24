/*
 * OpenQPEP Native C99 / SIMD Row-Streamed Unstructured Plain-LWE Accelerator (CULC-2048 / CSP-Omega)
 * Official Release 1.2.3 (v1.2.3) — Calyx Labs Inc. (CPOSLS-1.0)
 *
 * Implements Family 1 of Calyx Sovereign-Pentad (CSP-Omega) & Calyx Unstructured-Citadel (CULC-2048):
 *   - Pure unstructured Plain-LWE over Z_{65536}^{n x n} (zero polynomial ring, zero NTT, zero Galois symmetry)
 *   - O(1)-RAM Keccak-f[1600] row-tiled streaming matrix A generation (512-byte stack tile)
 *   - AVX2/NEON auto-vectorizable unit-stride uint16_t modular multiply-accumulate inner loops
 *   - One-shot C99 keygen, IND-CPA encrypt, FO IND-CCA2 encaps, and constant-time ct_cmov decaps
 *   - Compiler-barrier openqpep_explicit_bzero scrubbing of every secret intermediate buffer
 *
 * 100% ISO C99 (-Wall -Wextra -Werror -Wpedantic), bit-for-bit identical to plain_lwe.py.
 */
#include "openqpep.h"
#include <stdlib.h>
#include <string.h>

#define PLWE_STACK_ELEMS 2048U  /* 4 KiB stack fast-path (zero-heap for n<=256, nbar<=8; pthread-safe) */
#define PLWE_ROW_TILE    256U   /* 256 uint16_t = 512 bytes streamed per Keccak squeeze tile */
#define PLWE_NOISE_CHUNK 256U

static inline uint16_t load16_le(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline void store16_le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
}

static inline void store32_be(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)((v >> 24) & 0xFFU);
    out[1] = (uint8_t)((v >> 16) & 0xFFU);
    out[2] = (uint8_t)((v >> 8) & 0xFFU);
    out[3] = (uint8_t)(v & 0xFFU);
}

static int plwe_validate_dims(uint32_t n, uint32_t nbar) {
    if (n == 0U || n > OPENQPEP_PLAIN_LWE_MAX_N || nbar == 0U || nbar > OPENQPEP_PLAIN_LWE_MAX_NBAR) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    return OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* Legacy Row-Level ABI Helpers (Preserved from v1.2.0 ABI)                  */
/* ------------------------------------------------------------------------- */

OPENQPEP_API void openqpep_plain_lwe_row_accum_u16(
    uint16_t *dst,
    const uint16_t *row,
    uint16_t scalar,
    uint32_t n
) {
    if (!dst || !row) return;
    for (uint32_t j = 0U; j < n; j++) {
        dst[j] = (uint16_t)(dst[j] + (uint16_t)(scalar * row[j]));
    }
}

OPENQPEP_API void openqpep_plain_lwe_keygen_row_u16(
    uint16_t *b_row,
    const uint16_t *e_row,
    const uint16_t *a_row,
    const uint16_t *s_flat,
    uint32_t n,
    uint32_t nbar
) {
    if (!b_row || !e_row || !a_row || !s_flat) return;
    for (uint32_t j = 0U; j < nbar; j++) {
        b_row[j] = e_row[j];
    }
    for (uint32_t k = 0U; k < n; k++) {
        uint16_t a_k = a_row[k];
        const uint16_t *s_row = s_flat + ((size_t)k * (size_t)nbar);
        for (uint32_t j = 0U; j < nbar; j++) {
            b_row[j] = (uint16_t)(b_row[j] + (uint16_t)(a_k * s_row[j]));
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Centered Binomial Noise & Matrix Row Expansion Primitives                 */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_plain_lwe_sample_noise(
    const uint8_t *domain,
    size_t domain_len,
    const uint8_t *seed,
    size_t seed_len,
    size_t count,
    uint16_t *out_u16
) {
    if ((domain_len > 0U && !domain) || (seed_len > 0U && !seed) || (count > 0U && !out_u16)) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (count == 0U) {
        return OPENQPEP_OK;
    }

    openqpep_keccak_ctx_t ctx;
    uint8_t chunk[PLWE_NOISE_CHUNK];
    int rc = openqpep_shake256_init(&ctx);
    if (rc == OPENQPEP_OK && domain_len > 0U) rc = openqpep_keccak_absorb(&ctx, domain, domain_len);
    if (rc == OPENQPEP_OK && seed_len > 0U) rc = openqpep_keccak_absorb(&ctx, seed, seed_len);
    if (rc != OPENQPEP_OK) {
        openqpep_keccak_wipe(&ctx);
        return rc;
    }

    size_t pos = 0U;
    while (pos < count) {
        size_t take = count - pos;
        if (take > PLWE_NOISE_CHUNK) take = PLWE_NOISE_CHUNK;
        rc = openqpep_keccak_squeeze(&ctx, chunk, take);
        if (rc != OPENQPEP_OK) {
            openqpep_keccak_wipe(&ctx);
            openqpep_explicit_bzero(chunk, sizeof(chunk));
            return rc;
        }
        for (size_t i = 0U; i < take; i++) {
            uint32_t b = (uint32_t)chunk[i];
            uint32_t a = (b & 1U) + ((b >> 1) & 1U);
            uint32_t c = ((b >> 2) & 1U) + ((b >> 3) & 1U);
            out_u16[pos + i] = (uint16_t)(a - c);
        }
        pos += take;
    }

    openqpep_keccak_wipe(&ctx);
    openqpep_explicit_bzero(chunk, sizeof(chunk));
    return OPENQPEP_OK;
}

static int plwe_init_row_sponge(openqpep_keccak_ctx_t *ctx, const uint8_t seed_a[32], uint32_t row_idx) {
    static const char dom[] = "CALYX-PLAIN-LWE-ROW-v1.0.0|";
    uint8_t row_be[4];
    store32_be(row_be, row_idx);
    int rc = openqpep_shake256_init(ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(ctx, (const uint8_t *)dom, sizeof(dom) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(ctx, seed_a, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(ctx, row_be, sizeof(row_be));
    return rc;
}

OPENQPEP_API int openqpep_plain_lwe_expand_row(
    const uint8_t seed_a[32],
    uint32_t row_idx,
    uint32_t n,
    uint16_t *out_row
) {
    if (!seed_a || !out_row) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (n == 0U || n > OPENQPEP_PLAIN_LWE_MAX_N) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    openqpep_keccak_ctx_t ctx;
    uint8_t tile_bytes[PLWE_ROW_TILE * 2U];
    int rc = plwe_init_row_sponge(&ctx, seed_a, row_idx);
    if (rc != OPENQPEP_OK) {
        openqpep_keccak_wipe(&ctx);
        return rc;
    }

    uint32_t col = 0U;
    while (col < n) {
        uint32_t take = n - col;
        if (take > PLWE_ROW_TILE) take = PLWE_ROW_TILE;
        rc = openqpep_keccak_squeeze(&ctx, tile_bytes, (size_t)take * 2U);
        if (rc != OPENQPEP_OK) {
            openqpep_keccak_wipe(&ctx);
            return rc;
        }
        for (uint32_t t = 0U; t < take; t++) {
            out_row[col + t] = load16_le(tile_bytes + ((size_t)t * 2U));
        }
        col += take;
    }

    openqpep_keccak_wipe(&ctx);
    return OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* Streaming Row-Tiled Matrix-Matrix Operations (Zero Full-Matrix RAM)       */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_plain_lwe_keygen_matrix(
    const uint8_t seed_a[32],
    const uint16_t *s_flat,
    const uint16_t *e_flat,
    uint32_t n,
    uint32_t nbar,
    uint16_t *b_flat_out
) {
    if (!seed_a || !s_flat || !e_flat || !b_flat_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (plwe_validate_dims(n, nbar) != OPENQPEP_OK) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    openqpep_keccak_ctx_t ctx;
    uint8_t tile_bytes[PLWE_ROW_TILE * 2U];
    uint16_t a_tile[PLWE_ROW_TILE];

    for (uint32_t i = 0U; i < n; i++) {
        uint16_t *b_row = b_flat_out + ((size_t)i * (size_t)nbar);
        const uint16_t *e_row = e_flat + ((size_t)i * (size_t)nbar);
        for (uint32_t j = 0U; j < nbar; j++) {
            b_row[j] = e_row[j];
        }

        int rc = plwe_init_row_sponge(&ctx, seed_a, i);
        if (rc != OPENQPEP_OK) {
            openqpep_keccak_wipe(&ctx);
            return rc;
        }

        uint32_t col = 0U;
        while (col < n) {
            uint32_t take = n - col;
            if (take > PLWE_ROW_TILE) take = PLWE_ROW_TILE;
            rc = openqpep_keccak_squeeze(&ctx, tile_bytes, (size_t)take * 2U);
            if (rc != OPENQPEP_OK) {
                openqpep_keccak_wipe(&ctx);
                return rc;
            }
            for (uint32_t t = 0U; t < take; t++) {
                a_tile[t] = load16_le(tile_bytes + ((size_t)t * 2U));
            }
            for (uint32_t t = 0U; t < take; t++) {
                uint16_t a_val = a_tile[t];
                const uint16_t *s_row = s_flat + ((size_t)(col + t) * (size_t)nbar);
                for (uint32_t j = 0U; j < nbar; j++) {
                    b_row[j] = (uint16_t)(b_row[j] + (uint16_t)(a_val * s_row[j]));
                }
            }
            col += take;
        }
        openqpep_keccak_wipe(&ctx);
    }

    return OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* Full One-Shot C99 Plain-LWE Keygen, IND-CPA Enc, FO Encaps & FO Decaps    */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_plain_lwe_keygen_from_seeds(
    uint32_t n,
    uint32_t nbar,
    const uint8_t seed_a[32],
    const uint8_t seed_s[32],
    const uint8_t seed_z[32],
    uint8_t *pk_out,
    size_t pk_len,
    uint8_t *sk_out,
    size_t sk_len
) {
    if (!seed_a || !seed_s || !seed_z || !pk_out || !sk_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (plwe_validate_dims(n, nbar) != OPENQPEP_OK) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    size_t elems = (size_t)n * (size_t)nbar;
    size_t expected_pk = 4U + 32U + 2U * elems;
    size_t expected_sk = 4U + 32U + expected_pk + 2U * elems;
    if (pk_len != expected_pk || sk_len != expected_sk) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    uint16_t stack_s[PLWE_STACK_ELEMS];
    uint16_t stack_e[PLWE_STACK_ELEMS];
    uint16_t stack_b[PLWE_STACK_ELEMS];
    uint16_t *s_flat = stack_s;
    uint16_t *e_flat = stack_e;
    uint16_t *b_flat = stack_b;
    int heap_used = 0;

    if (elems > PLWE_STACK_ELEMS) {
        s_flat = (uint16_t *)calloc(elems, sizeof(uint16_t));
        e_flat = (uint16_t *)calloc(elems, sizeof(uint16_t));
        b_flat = (uint16_t *)calloc(elems, sizeof(uint16_t));
        heap_used = 1;
        if (!s_flat || !e_flat || !b_flat) {
            free(s_flat);
            free(e_flat);
            free(b_flat);
            return OPENQPEP_ERR_INVALID_LEN;
        }
    }

    static const char dom_s[] = "CALYX-PLWE-S-v1.0.0|";
    static const char dom_e[] = "CALYX-PLWE-E-v1.0.0|";
    int rc = openqpep_plain_lwe_sample_noise((const uint8_t *)dom_s, sizeof(dom_s) - 1U, seed_s, 32U, elems, s_flat);
    if (rc == OPENQPEP_OK) {
        rc = openqpep_plain_lwe_sample_noise((const uint8_t *)dom_e, sizeof(dom_e) - 1U, seed_s, 32U, elems, e_flat);
    }
    if (rc == OPENQPEP_OK) {
        rc = openqpep_plain_lwe_keygen_matrix(seed_a, s_flat, e_flat, n, nbar, b_flat);
    }
    if (rc == OPENQPEP_OK) {
        store16_le(pk_out, (uint16_t)n);
        store16_le(pk_out + 2U, (uint16_t)nbar);
        memcpy(pk_out + 4U, seed_a, 32U);
        for (size_t i = 0U; i < elems; i++) {
            store16_le(pk_out + 36U + 2U * i, b_flat[i]);
        }

        store16_le(sk_out, (uint16_t)n);
        store16_le(sk_out + 2U, (uint16_t)nbar);
        memcpy(sk_out + 4U, seed_z, 32U);
        memcpy(sk_out + 36U, pk_out, expected_pk);
        uint8_t *s_dst = sk_out + 36U + expected_pk;
        for (size_t i = 0U; i < elems; i++) {
            store16_le(s_dst + 2U * i, s_flat[i]);
        }
    }

    openqpep_explicit_bzero(s_flat, elems * sizeof(uint16_t));
    openqpep_explicit_bzero(e_flat, elems * sizeof(uint16_t));
    openqpep_explicit_bzero(b_flat, elems * sizeof(uint16_t));
    if (heap_used) {
        free(s_flat);
        free(e_flat);
        free(b_flat);
    }
    return rc;
}

OPENQPEP_API int openqpep_plain_lwe_indcpa_enc(
    const uint8_t *pk,
    size_t pk_len,
    const uint8_t msg16[16],
    const uint8_t coins32[32],
    uint8_t *ct_out,
    size_t ct_len
) {
    if (!pk || !msg16 || !coins32 || !ct_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (pk_len < 36U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    uint32_t n = (uint32_t)load16_le(pk);
    uint32_t nbar = (uint32_t)load16_le(pk + 2U);
    if (plwe_validate_dims(n, nbar) != OPENQPEP_OK) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    size_t elems = (size_t)n * (size_t)nbar;
    size_t nbar2 = (size_t)nbar * (size_t)nbar;
    size_t expected_pk = 36U + 2U * elems;
    size_t expected_ct = 2U * elems + 2U * nbar2;
    if (pk_len != expected_pk || ct_len != expected_ct) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    const uint8_t *seed_a = pk + 4U;
    const uint8_t *b_bytes = pk + 36U;

    uint16_t stack_sp[PLWE_STACK_ELEMS];
    uint16_t stack_u[PLWE_STACK_ELEMS];
    uint16_t *sp = stack_sp;
    uint16_t *u_flat = stack_u;
    uint16_t v_flat[OPENQPEP_PLAIN_LWE_MAX_NBAR * OPENQPEP_PLAIN_LWE_MAX_NBAR];
    int heap_used = 0;

    if (elems > PLWE_STACK_ELEMS) {
        sp = (uint16_t *)calloc(elems, sizeof(uint16_t));
        u_flat = (uint16_t *)calloc(elems, sizeof(uint16_t));
        heap_used = 1;
        if (!sp || !u_flat) {
            free(sp);
            free(u_flat);
            return OPENQPEP_ERR_INVALID_LEN;
        }
    }

    static const char dom_sp[] = "CALYX-PLWE-SP-v1.0.0|";
    static const char dom_ep[] = "CALYX-PLWE-EP-v1.0.0|";
    static const char dom_epp[] = "CALYX-PLWE-EPP-v1.0.0|";

    int rc = openqpep_plain_lwe_sample_noise((const uint8_t *)dom_sp, sizeof(dom_sp) - 1U, coins32, 32U, elems, sp);
    if (rc == OPENQPEP_OK) {
        rc = openqpep_plain_lwe_sample_noise((const uint8_t *)dom_ep, sizeof(dom_ep) - 1U, coins32, 32U, elems, u_flat);
    }
    if (rc == OPENQPEP_OK) {
        rc = openqpep_plain_lwe_sample_noise((const uint8_t *)dom_epp, sizeof(dom_epp) - 1U, coins32, 32U, nbar2, v_flat);
    }

    /* Stream matrix A row-by-row in 256-uint16 tiles: U = S' * A + E' */
    openqpep_keccak_ctx_t ctx;
    uint8_t tile_bytes[PLWE_ROW_TILE * 2U];
    uint16_t a_tile[PLWE_ROW_TILE];

    for (uint32_t k = 0U; rc == OPENQPEP_OK && k < n; k++) {
        rc = plwe_init_row_sponge(&ctx, seed_a, k);
        if (rc != OPENQPEP_OK) {
            openqpep_keccak_wipe(&ctx);
            break;
        }
        uint32_t col = 0U;
        while (col < n) {
            uint32_t take = n - col;
            if (take > PLWE_ROW_TILE) take = PLWE_ROW_TILE;
            rc = openqpep_keccak_squeeze(&ctx, tile_bytes, (size_t)take * 2U);
            if (rc != OPENQPEP_OK) {
                break;
            }
            for (uint32_t t = 0U; t < take; t++) {
                a_tile[t] = load16_le(tile_bytes + ((size_t)t * 2U));
            }
            for (uint32_t i = 0U; i < nbar; i++) {
                uint16_t s_ik = sp[(size_t)i * (size_t)n + (size_t)k];
                uint16_t *u_dst = u_flat + ((size_t)i * (size_t)n + (size_t)col);
                for (uint32_t t = 0U; t < take; t++) {
                    u_dst[t] = (uint16_t)(u_dst[t] + (uint16_t)(s_ik * a_tile[t]));
                }
            }
            col += take;
        }
        openqpep_keccak_wipe(&ctx);
    }

    /* Compute V = S' * B + E'' + encode(msg16) */
    if (rc == OPENQPEP_OK) {
        for (uint32_t k = 0U; k < n; k++) {
            uint16_t b_row[OPENQPEP_PLAIN_LWE_MAX_NBAR];
            const uint8_t *b_ptr = b_bytes + ((size_t)k * (size_t)nbar * 2U);
            for (uint32_t j = 0U; j < nbar; j++) {
                b_row[j] = load16_le(b_ptr + ((size_t)j * 2U));
            }
            for (uint32_t i = 0U; i < nbar; i++) {
                uint16_t s_ik = sp[(size_t)i * (size_t)n + (size_t)k];
                uint16_t *v_row = v_flat + ((size_t)i * (size_t)nbar);
                for (uint32_t j = 0U; j < nbar; j++) {
                    v_row[j] = (uint16_t)(v_row[j] + (uint16_t)(s_ik * b_row[j]));
                }
            }
        }
        for (size_t idx = 0U; idx < nbar2; idx++) {
            uint32_t bit_pos = (uint32_t)(idx * 2U);
            uint16_t two_bits = (uint16_t)((msg16[bit_pos >> 3] >> (bit_pos & 7U)) & 0x03U);
            v_flat[idx] = (uint16_t)(v_flat[idx] + (uint16_t)(two_bits << 14));
        }

        for (size_t i = 0U; i < elems; i++) {
            store16_le(ct_out + 2U * i, u_flat[i]);
        }
        uint8_t *v_dst = ct_out + 2U * elems;
        for (size_t i = 0U; i < nbar2; i++) {
            store16_le(v_dst + 2U * i, v_flat[i]);
        }
    }

    openqpep_explicit_bzero(sp, elems * sizeof(uint16_t));
    openqpep_explicit_bzero(u_flat, elems * sizeof(uint16_t));
    openqpep_explicit_bzero(v_flat, sizeof(v_flat));
    openqpep_explicit_bzero(tile_bytes, sizeof(tile_bytes));
    openqpep_explicit_bzero(a_tile, sizeof(a_tile));
    if (heap_used) {
        free(sp);
        free(u_flat);
    }
    return rc;
}

static int plwe_hash_pk(const uint8_t *pk, size_t pk_len, uint8_t h_pk[32]) {
    static const char dom[] = "CALYX-PLWE-HPK-v1.0.0|";
    openqpep_keccak_ctx_t ctx;
    int rc = openqpep_shake256_init(&ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, (const uint8_t *)dom, sizeof(dom) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, pk, pk_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, h_pk, 32U);
    openqpep_keccak_wipe(&ctx);
    return rc;
}

static int plwe_fo_g(const uint8_t msg16[16], const uint8_t h_pk[32], uint8_t kr64[64]) {
    static const char dom[] = "CALYX-PLWE-FO-G-v1.0.0|";
    openqpep_keccak_ctx_t ctx;
    int rc = openqpep_sha3_512_init(&ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, (const uint8_t *)dom, sizeof(dom) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, msg16, 16U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, h_pk, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, kr64, 64U);
    openqpep_keccak_wipe(&ctx);
    return rc;
}

OPENQPEP_API int openqpep_plain_lwe_encaps(
    const uint8_t *pk,
    size_t pk_len,
    const uint8_t msg16[16],
    uint8_t *ct_out,
    size_t ct_len,
    uint8_t ss_out[32]
) {
    if (!pk || !msg16 || !ct_out || !ss_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    uint8_t h_pk[32];
    uint8_t kr[64];
    int rc = plwe_hash_pk(pk, pk_len, h_pk);
    if (rc == OPENQPEP_OK) {
        rc = plwe_fo_g(msg16, h_pk, kr);
    }
    if (rc == OPENQPEP_OK) {
        rc = openqpep_plain_lwe_indcpa_enc(pk, pk_len, msg16, kr + 32U, ct_out, ct_len);
    }
    if (rc == OPENQPEP_OK) {
        memcpy(ss_out, kr, 32U);
    }
    openqpep_explicit_bzero(kr, sizeof(kr));
    openqpep_explicit_bzero(h_pk, sizeof(h_pk));
    return rc;
}

OPENQPEP_API int openqpep_plain_lwe_decaps(
    const uint8_t *sk,
    size_t sk_len,
    const uint8_t *ct,
    size_t ct_len,
    uint8_t ss_out[32]
) {
    if (!sk || !ct || !ss_out) {
        return OPENQPEP_ERR_NULL_PTR;
    }
    if (sk_len < 72U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    uint32_t n = (uint32_t)load16_le(sk);
    uint32_t nbar = (uint32_t)load16_le(sk + 2U);
    if (plwe_validate_dims(n, nbar) != OPENQPEP_OK) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    size_t elems = (size_t)n * (size_t)nbar;
    size_t nbar2 = (size_t)nbar * (size_t)nbar;
    size_t pk_len = 36U + 2U * elems;
    size_t expected_sk = 36U + pk_len + 2U * elems;
    size_t expected_ct = 2U * elems + 2U * nbar2;
    if (sk_len != expected_sk || ct_len != expected_ct) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    const uint8_t *seed_z = sk + 4U;
    const uint8_t *pk = sk + 36U;
    const uint8_t *s_bytes = sk + 36U + pk_len;
    const uint8_t *u_bytes = ct;
    const uint8_t *v_bytes = ct + 2U * elems;

    /* Compute US = U * S mod 65536 using O(nbar^2) stack accumulator and O(nbar) row buffer */
    uint16_t us[OPENQPEP_PLAIN_LWE_MAX_NBAR * OPENQPEP_PLAIN_LWE_MAX_NBAR];
    memset(us, 0, sizeof(us));
    for (uint32_t k = 0U; k < n; k++) {
        uint16_t s_row[OPENQPEP_PLAIN_LWE_MAX_NBAR];
        const uint8_t *s_ptr = s_bytes + ((size_t)k * (size_t)nbar * 2U);
        for (uint32_t j = 0U; j < nbar; j++) {
            s_row[j] = load16_le(s_ptr + ((size_t)j * 2U));
        }
        for (uint32_t i = 0U; i < nbar; i++) {
            uint16_t u_ik = load16_le(u_bytes + (((size_t)i * (size_t)n + (size_t)k) * 2U));
            uint16_t *us_row = us + ((size_t)i * (size_t)nbar);
            for (uint32_t j = 0U; j < nbar; j++) {
                us_row[j] = (uint16_t)(us_row[j] + (uint16_t)(u_ik * s_row[j]));
            }
        }
        openqpep_explicit_bzero(s_row, sizeof(s_row));
    }

    /* Constant-time reconciliation: W = V - U*S, round to 2 bits per entry */
    uint8_t m_prime[16];
    memset(m_prime, 0, sizeof(m_prime));
    for (size_t idx = 0U; idx < nbar2; idx++) {
        uint16_t v_val = load16_le(v_bytes + 2U * idx);
        uint16_t w = (uint16_t)(v_val - us[idx]);
        uint32_t two_bits = (((uint32_t)w + 8192U) >> 14) & 0x03U;
        uint32_t bit_pos = (uint32_t)(idx * 2U);
        m_prime[bit_pos >> 3] |= (uint8_t)(two_bits << (bit_pos & 7U));
    }
    openqpep_explicit_bzero(us, sizeof(us));

    uint8_t h_pk[32];
    uint8_t kr_prime[64];
    uint8_t k_reject[32];
    uint8_t stack_ct[PLWE_STACK_ELEMS * 2U + 128U];
    uint8_t *ct_prime = stack_ct;
    int heap_ct = 0;

    if (expected_ct > sizeof(stack_ct)) {
        ct_prime = (uint8_t *)calloc(expected_ct, 1U);
        heap_ct = 1;
        if (!ct_prime) {
            openqpep_explicit_bzero(m_prime, sizeof(m_prime));
            return OPENQPEP_ERR_INVALID_LEN;
        }
    }

    int rc = plwe_hash_pk(pk, pk_len, h_pk);
    if (rc == OPENQPEP_OK) {
        rc = plwe_fo_g(m_prime, h_pk, kr_prime);
    }
    if (rc == OPENQPEP_OK) {
        rc = openqpep_plain_lwe_indcpa_enc(pk, pk_len, m_prime, kr_prime + 32U, ct_prime, expected_ct);
    }
    if (rc == OPENQPEP_OK) {
        static const char dom_rej[] = "CALYX-PLWE-FO-REJECT-v1.0.0|";
        openqpep_keccak_ctx_t rej_ctx;
        rc = openqpep_shake256_init(&rej_ctx);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&rej_ctx, (const uint8_t *)dom_rej, sizeof(dom_rej) - 1U);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&rej_ctx, seed_z, 32U);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&rej_ctx, ct, ct_len);
        if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&rej_ctx, k_reject, 32U);
        openqpep_keccak_wipe(&rej_ctx);
    }
    if (rc == OPENQPEP_OK) {
        int is_valid = openqpep_ct_eq(ct, ct_prime, expected_ct);
        openqpep_ct_cmov(is_valid, ss_out, kr_prime, k_reject, 32U);
    }

    openqpep_explicit_bzero(m_prime, sizeof(m_prime));
    openqpep_explicit_bzero(h_pk, sizeof(h_pk));
    openqpep_explicit_bzero(kr_prime, sizeof(kr_prime));
    openqpep_explicit_bzero(k_reject, sizeof(k_reject));
    openqpep_explicit_bzero(ct_prime, expected_ct);
    if (heap_ct) {
        free(ct_prime);
    }
    return rc;
}
