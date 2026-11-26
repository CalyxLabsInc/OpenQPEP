/*
 * OpenQPEP Official Release 1.2.9 (v1.2.9) — Standalone Pure-C99 Self-Test & Differential
 * Verification Harness (`test_openqpep_c.c`).
 *
 * Coverage: Exercises ALL 108/108 exported OPENQPEP_API functions across all 12 cryptographic
 * subsystems under strict ISO C99 (-std=c99 -Wall -Wextra -Werror -Wpedantic) and runtime
 * AddressSanitizer + LeakSanitizer + UndefinedBehaviorSanitizer
 * (-fsanitize=address,undefined -fno-sanitize-recover=all).
 *
 * Modes:
 *   ./build/test_openqpep_c                -> Runs all 12 self-test suites and prints summary.
 *   ./build/test_openqpep_c --dump-vectors -> Also emits canonical KEY=HEX differential vectors
 *                                             verified bit-for-bit against Pure Python.
 *
 * Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
 */
#include "openqpep.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_dump_vectors = 0;
static int g_checks_run = 0;
static int g_checks_failed = 0;

#define QPEP_CHECK(cond, msg) do {                                                     \
    g_checks_run++;                                                                    \
    if (!(cond)) {                                                                     \
        fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, (msg));              \
        g_checks_failed++;                                                             \
        return 1;                                                                      \
    }                                                                                  \
} while (0)

static void dump_hex(const char *key, const uint8_t *buf, size_t len) {
    if (!g_dump_vectors) return;
    printf("VEC:%s=", key);
    for (size_t i = 0U; i < len; i++) {
        printf("%02x", (unsigned int)buf[i]);
    }
    printf("\n");
}

static void dump_sha3_256(const char *key, const void *buf, size_t len) {
    if (!g_dump_vectors) return;
    uint8_t dig[32];
    if (openqpep_sha3_256((const uint8_t *)buf, len, dig) == OPENQPEP_OK) {
        dump_hex(key, dig, sizeof(dig));
    }
}

static void pack_i32_le(const int32_t *src, size_t count, uint8_t *dst) {
    for (size_t i = 0U; i < count; i++) {
        uint32_t u = (uint32_t)src[i];
        dst[4U * i + 0U] = (uint8_t)(u & 0xFFU);
        dst[4U * i + 1U] = (uint8_t)((u >> 8) & 0xFFU);
        dst[4U * i + 2U] = (uint8_t)((u >> 16) & 0xFFU);
        dst[4U * i + 3U] = (uint8_t)((u >> 24) & 0xFFU);
    }
}

static void pack_u16_le(const uint16_t *src, size_t count, uint8_t *dst) {
    for (size_t i = 0U; i < count; i++) {
        dst[2U * i + 0U] = (uint8_t)(src[i] & 0xFFU);
        dst[2U * i + 1U] = (uint8_t)((src[i] >> 8) & 0xFFU);
    }
}

/* ========================================================================= */
/* Suite 1: ABI & Capability Introspection (3 symbols)                       */
/* ========================================================================= */
static int test_suite_01_abi(void) {
    uint32_t abi = openqpep_abi_version();
    const char *ver = openqpep_version_string();
    uint32_t info = openqpep_native_abi_info();

    QPEP_CHECK(abi == OPENQPEP_ABI_VERSION, "openqpep_abi_version matches header");
    QPEP_CHECK(ver != NULL && strcmp(ver, OPENQPEP_VERSION_STRING) == 0, "openqpep_version_string matches header");
    QPEP_CHECK((info & OPENQPEP_ABI_FLAG_C99) != 0U, "C99 capability flag set");
    return 0;
}

/* ========================================================================= */
/* Suite 2: Constant-Time Helpers, GF(256) & Zeroization (10 symbols)        */
/* ========================================================================= */
static int test_suite_02_consttime_gf256(void) {
    /* Exhaustive GF(256) inversion & multiplication identities */
    QPEP_CHECK(openqpep_gf256_inv(0U) == 0U, "gf256_inv(0) == 0");
    QPEP_CHECK(openqpep_gf256_mul(0x57U, 0x83U) == 0xC1U, "AES GF(256) KAT 0x57*0x83==0xC1");
    for (uint32_t a = 1U; a < 256U; a++) {
        uint8_t inv = openqpep_gf256_inv((uint8_t)a);
        QPEP_CHECK(openqpep_gf256_mul((uint8_t)a, inv) == 1U, "a * gf256_inv(a) == 1");
        QPEP_CHECK(openqpep_gf256_mul(inv, (uint8_t)a) == 1U, "gf256_inv(a) * a == 1");
    }

    uint8_t a[32], b[32], out[32], acc[32];
    for (size_t i = 0U; i < 32U; i++) {
        a[i] = (uint8_t)(i + 1U);
        b[i] = (uint8_t)(0xF0U - i);
        acc[i] = a[i];
    }
    openqpep_xor_accum_bytes(acc, b, 32U);
    for (size_t i = 0U; i < 32U; i++) {
        QPEP_CHECK(acc[i] == (uint8_t)(a[i] ^ b[i]), "xor_accum_bytes exact");
    }

    QPEP_CHECK(openqpep_ct_select_u32(0U, 0x12345678U, 0x9ABCDEF0U) == 0x9ABCDEF0U, "ct_select_u32 false");
    QPEP_CHECK(openqpep_ct_select_u32(0x80000000U, 0x12345678U, 0x9ABCDEF0U) == 0x12345678U, "ct_select_u32 true");

    QPEP_CHECK(openqpep_ct_mem_bounds_ok(0U, 0U, 0U) == 1, "bounds(0,0,0)");
    QPEP_CHECK(openqpep_ct_mem_bounds_ok(SIZE_MAX, 0U, SIZE_MAX) == 1, "bounds(SIZE_MAX,0,SIZE_MAX)");
    QPEP_CHECK(openqpep_ct_mem_bounds_ok(SIZE_MAX, 1U, SIZE_MAX) == 0, "bounds overflow rejected");
    QPEP_CHECK(openqpep_ct_mem_bounds_ok(56U, 100U, 156U) == 1, "bounds exact boundary");
    QPEP_CHECK(openqpep_ct_mem_bounds_ok(56U, 101U, 156U) == 0, "bounds 1-past-end rejected");

    openqpep_ct_cmov(1, out, a, b, 32U);
    QPEP_CHECK(openqpep_ct_eq(out, a, 32U) == 1, "ct_cmov true selects a");
    openqpep_ct_cmov(0, out, a, b, 32U);
    QPEP_CHECK(openqpep_ct_eq(out, b, 32U) == 1, "ct_cmov false selects b");
    QPEP_CHECK(openqpep_ct_eq(a, b, 32U) == 0, "ct_eq unequal returns 0");

    uint8_t sa[32], sb[32];
    memcpy(sa, a, 32U);
    memcpy(sb, b, 32U);
    openqpep_ct_cswap(0, sa, sb, 32U);
    QPEP_CHECK(openqpep_ct_eq(sa, a, 32U) && openqpep_ct_eq(sb, b, 32U), "ct_cswap false no-op");
    openqpep_ct_cswap(-3, sa, sb, 32U);
    QPEP_CHECK(openqpep_ct_eq(sa, b, 32U) && openqpep_ct_eq(sb, a, 32U), "ct_cswap true swaps");

    QPEP_CHECK(openqpep_is_zeroed(sa, 32U) == 0, "is_zeroed non-zero buffer");
    openqpep_explicit_bzero(sa, 32U);
    QPEP_CHECK(openqpep_is_zeroed(sa, 32U) == 1, "explicit_bzero + is_zeroed");
    dump_hex("CT_XOR_ACC", acc, 32U);
    return 0;
}

/* ========================================================================= */
/* Suite 3: Keccak-f[1600] / FIPS 202 (14 symbols)                           */
/* ========================================================================= */
static int test_suite_03_keccak(void) {
    /* Raw permutation sanity */
    uint64_t perm[25];
    memset(perm, 0, sizeof(perm));
    openqpep_keccak_f1600(perm);
    QPEP_CHECK(perm[0] == 0xF1258F7940E1DDE7ULL, "Keccak-f[1600](0) lane 0 NIST KAT");

    /* Official NIST FIPS 202 empty-string SHA3-256 & SHA3-512 vectors */
    static const uint8_t NIST_SHA3_256_EMPTY[32] = {
        0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
        0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a
    };
    static const uint8_t NIST_SHA3_512_EMPTY[64] = {
        0xa6,0x9f,0x73,0xcc,0xa2,0x3a,0x9a,0xc5,0xc8,0xb5,0x67,0xdc,0x18,0x5a,0x75,0x6e,
        0x97,0xc9,0x82,0x16,0x4f,0xe2,0x58,0x59,0xe0,0xd1,0xdc,0xc1,0x47,0x5c,0x80,0xa6,
        0x15,0xb2,0x12,0x3a,0xf1,0xf5,0xf9,0x4c,0x11,0xe3,0xe9,0x40,0x2c,0x3a,0xc5,0x58,
        0xf5,0x00,0x19,0x9d,0x95,0xb6,0xd3,0xe3,0x01,0x75,0x85,0x86,0x28,0x1d,0xcd,0x26
    };

    uint8_t d256[32], d512[64], x256[200], x128[200];
    QPEP_CHECK(openqpep_sha3_256(NULL, 0U, d256) == OPENQPEP_OK, "sha3_256 empty");
    QPEP_CHECK(openqpep_ct_eq(d256, NIST_SHA3_256_EMPTY, 32U) == 1, "sha3_256 empty NIST match");
    QPEP_CHECK(openqpep_qsponge_512(NULL, 0U, d512) == OPENQPEP_OK, "qsponge_512 empty");
    QPEP_CHECK(openqpep_ct_eq(d512, NIST_SHA3_512_EMPTY, 64U) == 1, "qsponge_512 empty NIST match");

    /* Incremental streaming parity across all 4 init functions + generic keccak_init */
    uint8_t msg[300];
    for (size_t i = 0U; i < sizeof(msg); i++) msg[i] = (uint8_t)(i * 37U + 11U);

    openqpep_keccak_ctx_t ctx;
    uint8_t s512[64], s256[32], sx256[200], sx128[200], sgen[64];

    QPEP_CHECK(openqpep_qsponge_512(msg, sizeof(msg), d512) == OPENQPEP_OK, "oneshot qsponge_512");
    QPEP_CHECK(openqpep_sha3_512_init(&ctx) == OPENQPEP_OK, "sha3_512_init");
    QPEP_CHECK(openqpep_keccak_absorb(&ctx, msg, 71U) == OPENQPEP_OK, "absorb chunk 1");
    QPEP_CHECK(openqpep_keccak_absorb(&ctx, msg + 71U, 137U) == OPENQPEP_OK, "absorb chunk 2");
    QPEP_CHECK(openqpep_keccak_absorb(&ctx, msg + 208U, 92U) == OPENQPEP_OK, "absorb chunk 3");
    QPEP_CHECK(openqpep_keccak_finalize(&ctx) == OPENQPEP_OK, "finalize");
    QPEP_CHECK(openqpep_keccak_squeeze(&ctx, s512, 64U) == OPENQPEP_OK, "squeeze 64");
    QPEP_CHECK(openqpep_ct_eq(d512, s512, 64U) == 1, "incremental sha3_512 == oneshot");
    openqpep_keccak_wipe(&ctx);
    QPEP_CHECK(openqpep_is_zeroed((const uint8_t *)&ctx, sizeof(ctx)) == 1, "keccak_wipe zeroes ctx");

    QPEP_CHECK(openqpep_sha3_256(msg, sizeof(msg), d256) == OPENQPEP_OK, "oneshot sha3_256");
    QPEP_CHECK(openqpep_sha3_256_init(&ctx) == OPENQPEP_OK, "sha3_256_init");
    QPEP_CHECK(openqpep_keccak_absorb(&ctx, msg, sizeof(msg)) == OPENQPEP_OK, "absorb sha3_256");
    QPEP_CHECK(openqpep_keccak_squeeze(&ctx, s256, 32U) == OPENQPEP_OK, "squeeze sha3_256");
    QPEP_CHECK(openqpep_ct_eq(d256, s256, 32U) == 1, "incremental sha3_256 == oneshot");
    openqpep_keccak_wipe(&ctx);

    QPEP_CHECK(openqpep_qsponge_var(msg, sizeof(msg), x256, sizeof(x256)) == OPENQPEP_OK, "oneshot shake256");
    QPEP_CHECK(openqpep_shake256_init(&ctx) == OPENQPEP_OK, "shake256_init");
    QPEP_CHECK(openqpep_keccak_absorb(&ctx, msg, sizeof(msg)) == OPENQPEP_OK, "absorb shake256");
    QPEP_CHECK(openqpep_keccak_squeeze(&ctx, sx256, 53U) == OPENQPEP_OK, "squeeze shake256 part 1");
    QPEP_CHECK(openqpep_keccak_squeeze(&ctx, sx256 + 53U, 147U) == OPENQPEP_OK, "squeeze shake256 part 2");
    QPEP_CHECK(openqpep_ct_eq(x256, sx256, sizeof(x256)) == 1, "multi-squeeze shake256 == oneshot");
    openqpep_keccak_wipe(&ctx);

    QPEP_CHECK(openqpep_shake128(msg, sizeof(msg), x128, sizeof(x128)) == OPENQPEP_OK, "oneshot shake128");
    QPEP_CHECK(openqpep_shake128_init(&ctx) == OPENQPEP_OK, "shake128_init");
    QPEP_CHECK(openqpep_keccak_absorb(&ctx, msg, sizeof(msg)) == OPENQPEP_OK, "absorb shake128");
    QPEP_CHECK(openqpep_keccak_squeeze(&ctx, sx128, sizeof(sx128)) == OPENQPEP_OK, "squeeze shake128");
    QPEP_CHECK(openqpep_ct_eq(x128, sx128, sizeof(x128)) == 1, "incremental shake128 == oneshot");
    openqpep_keccak_wipe(&ctx);

    QPEP_CHECK(openqpep_keccak_init(&ctx, OPENQPEP_SHA3_512_RATE, OPENQPEP_SHA3_DOMAIN_SEP) == OPENQPEP_OK, "keccak_init");
    QPEP_CHECK(openqpep_keccak_absorb(&ctx, msg, sizeof(msg)) == OPENQPEP_OK, "generic absorb");
    QPEP_CHECK(openqpep_keccak_squeeze(&ctx, sgen, 64U) == OPENQPEP_OK, "generic squeeze");
    QPEP_CHECK(openqpep_ct_eq(d512, sgen, 64U) == 1, "keccak_init matches sha3_512");
    openqpep_keccak_wipe(&ctx);

    dump_hex("KECCAK_SHA3_512", d512, 64U);
    dump_hex("KECCAK_SHA3_256", d256, 32U);
    dump_sha3_256("KECCAK_SHAKE256_200", x256, sizeof(x256));
    dump_sha3_256("KECCAK_SHAKE128_200", x128, sizeof(x128));
    return 0;
}

/* ========================================================================= */
/* Suite 4: QLX NTT mod 3329, Codecs, Samplers & MatVec (13 symbols)         */
/* ========================================================================= */
static int test_suite_04_qlx_3329(void) {
    int32_t a[256], b[256], a_hat[256], b_hat[256], prod[256], acc[256], sum[256], diff[256];
    for (int i = 0; i < 256; i++) {
        a[i] = (i * 137 + 19) % OPENQPEP_QLX_Q;
        b[i] = (i * 251 + 7) % OPENQPEP_QLX_Q;
        a_hat[i] = a[i];
        b_hat[i] = b[i];
    }
    openqpep_poly_add_3329(a, b, sum);
    openqpep_poly_sub_3329(sum, b, diff);
    for (int i = 0; i < 256; i++) {
        QPEP_CHECK(diff[i] == a[i], "poly_add/sub_3329 round-trip");
    }

    openqpep_ntt_3329(a_hat);
    openqpep_ntt_3329(b_hat);
    openqpep_ntt_base_mul_3329(a_hat, b_hat, prod);
    memset(acc, 0, sizeof(acc));
    openqpep_ntt_base_mul_acc_3329(acc, a_hat, b_hat);
    for (int i = 0; i < 256; i++) {
        QPEP_CHECK(acc[i] == prod[i], "ntt_base_mul_acc_3329 == ntt_base_mul_3329");
    }
    openqpep_inv_ntt_3329(prod);

    /* Direct negacyclic schoolbook check mod (X^256 + 1, 3329) */
    for (int i = 0; i < 256; i++) {
        int64_t expected = 0;
        for (int j = 0; j < 256; j++) {
            int k = i - j;
            if (k >= 0) expected += (int64_t)a[j] * (int64_t)b[k];
            else expected -= (int64_t)a[j] * (int64_t)b[k + 256];
        }
        int32_t exp_mod = (int32_t)(((expected % OPENQPEP_QLX_Q) + OPENQPEP_QLX_Q) % OPENQPEP_QLX_Q);
        QPEP_CHECK(prod[i] == exp_mod, "NTT_3329 multiplication matches schoolbook");
    }

    /* 12-bit byte encode/decode + compress/decompress d=1..12 */
    uint8_t enc384[384];
    int32_t dec256[256];
    QPEP_CHECK(openqpep_byte_encode_12(a, enc384) == OPENQPEP_OK, "byte_encode_12");
    QPEP_CHECK(openqpep_byte_decode_12(enc384, dec256) == OPENQPEP_OK, "byte_decode_12");
    for (int i = 0; i < 256; i++) QPEP_CHECK(dec256[i] == a[i], "byte_encode/decode_12 round-trip");

    uint8_t cmp_buf[384];
    int32_t dcmp[256];
    for (uint32_t d = 1U; d <= 12U; d++) {
        QPEP_CHECK(openqpep_poly_compress_3329(a, d, cmp_buf, (size_t)d * 32U) == OPENQPEP_OK, "compress_3329");
        QPEP_CHECK(openqpep_poly_decompress_3329(cmp_buf, (size_t)d * 32U, d, dcmp) == OPENQPEP_OK, "decompress_3329");
        if (d == 12U) {
            for (int i = 0; i < 256; i++) QPEP_CHECK(dcmp[i] == a[i], "d=12 lossless");
        }
    }

    /* QLX sample_ntt + streaming matvec (normal & transposed) + inner_prod (k=3) */
    uint8_t rho[32];
    for (size_t i = 0U; i < 32U; i++) rho[i] = (uint8_t)(0x10U + i);
    int32_t s_poly[256];
    QPEP_CHECK(openqpep_qlx_sample_ntt_3329(rho, 1U, 2U, s_poly) == OPENQPEP_OK, "qlx_sample_ntt_3329");

    int32_t vec[3 * 256], add_v[3 * 256], mv_out[3 * 256], mvt_out[3 * 256], ip_out[256];
    for (int j = 0; j < 3; j++) {
        for (int i = 0; i < 256; i++) {
            vec[j * 256 + i] = ((j + 1) * 53 + i * 17) % OPENQPEP_QLX_Q;
            add_v[j * 256 + i] = ((j + 2) * 29 + i * 11) % OPENQPEP_QLX_Q;
        }
        openqpep_ntt_3329(vec + j * 256);
        openqpep_ntt_3329(add_v + j * 256);
    }
    QPEP_CHECK(openqpep_qlx_matvec_3329(rho, 3U, 0, vec, add_v, mv_out) == OPENQPEP_OK, "qlx_matvec_3329 normal");
    QPEP_CHECK(openqpep_qlx_matvec_3329(rho, 3U, 1, vec, NULL, mvt_out) == OPENQPEP_OK, "qlx_matvec_3329 transpose");
    QPEP_CHECK(openqpep_qlx_inner_prod_3329(mv_out, mvt_out, 3U, ip_out) == OPENQPEP_OK, "qlx_inner_prod_3329");

    /* Emit canonical differential vectors */
    uint8_t p_bytes[256 * 4];
    pack_i32_le(prod, 256U, p_bytes);
    dump_sha3_256("QLX_NTT_PROD", p_bytes, sizeof(p_bytes));
    QPEP_CHECK(openqpep_poly_compress_3329(a, 10U, cmp_buf, 320U) == OPENQPEP_OK, "compress d=10");
    dump_sha3_256("QLX_CMP_D10", cmp_buf, 320U);
    pack_i32_le(s_poly, 256U, p_bytes);
    dump_sha3_256("QLX_SAMPLE_1_2", p_bytes, sizeof(p_bytes));
    pack_i32_le(ip_out, 256U, p_bytes);
    dump_sha3_256("QLX_MATVEC_INNER", p_bytes, sizeof(p_bytes));
    return 0;
}

/* ========================================================================= */
/* Suite 5: QVS Division-Free Solinas NTT mod 8380417 & MatVec (15 symbols)  */
/* ========================================================================= */
static int test_suite_05_qvs_8380417(void) {
    int32_t a[256], b[256], ah[256], bh[256], m1[256], m2[256], add_r[256], sub_r[256];
    for (int i = 0; i < 256; i++) {
        a[i] = (int32_t)(((uint32_t)i * 65521U + 12345U) % (uint32_t)OPENQPEP_QVS_Q);
        b[i] = (int32_t)(((uint32_t)i * 31337U + 777U) % (uint32_t)OPENQPEP_QVS_Q);
        ah[i] = a[i];
        bh[i] = b[i];
    }
    openqpep_poly_add_qvs(a, b, add_r);
    openqpep_poly_sub_qvs(add_r, b, sub_r);
    for (int i = 0; i < 256; i++) QPEP_CHECK(sub_r[i] == a[i], "poly_add/sub_qvs round-trip");

    openqpep_ntt_qvs(ah);
    openqpep_ntt_qvs(bh);
    openqpep_ntt_mul_qvs(ah, bh, m1);
    openqpep_ntt_base_mul_8380417(ah, bh, m2);
    for (int i = 0; i < 256; i++) QPEP_CHECK(m1[i] == m2[i], "ntt_mul_qvs == ntt_base_mul_8380417");
    openqpep_inv_ntt_qvs(m1);

    /* QVS HighBits/LowBits decomposition identity */
    int32_t r1[256], r0[256];
    QPEP_CHECK(openqpep_qvs_decompose_poly(a, r1, r0) == OPENQPEP_OK, "qvs_decompose_poly");
    const int64_t gamma2 = (OPENQPEP_QVS_Q - 1) / 32;
    const int64_t alpha = 2 * gamma2;
    for (int i = 0; i < 256; i++) {
        int64_t recon = ((int64_t)r1[i] * alpha + (int64_t)r0[i]) % OPENQPEP_QVS_Q;
        if (recon < 0) recon += OPENQPEP_QVS_Q;
        QPEP_CHECK(recon == (int64_t)a[i], "qvs_decompose_poly reconstruction identity");
    }

    /* 24-bit pack/unpack round-trip */
    uint8_t p768[768];
    int32_t up256[256];
    QPEP_CHECK(openqpep_qvs_pack_poly24(a, p768) == OPENQPEP_OK, "qvs_pack_poly24");
    QPEP_CHECK(openqpep_qvs_unpack_poly24(p768, up256) == OPENQPEP_OK, "qvs_unpack_poly24");
    for (int i = 0; i < 256; i++) QPEP_CHECK(up256[i] == a[i], "qvs_pack/unpack_poly24 round-trip");

    /* Samplers + expand_matrix + precomputed vs streaming matvec */
    uint8_t rho[32], c_tilde[64];
    for (size_t i = 0U; i < 32U; i++) rho[i] = (uint8_t)(0x20U + i);
    for (size_t i = 0U; i < 64U; i++) c_tilde[i] = (uint8_t)(0x80U + i);

    int32_t a00[256], mask_y[256], ball_c[256];
    QPEP_CHECK(openqpep_qvs_sample_ntt(rho, 0U, 0U, a00) == OPENQPEP_OK, "qvs_sample_ntt");
    QPEP_CHECK(openqpep_qvs_sample_mask_y(rho, 32U, 7U, mask_y) == OPENQPEP_OK, "qvs_sample_mask_y");
    QPEP_CHECK(openqpep_qvs_sample_in_ball(c_tilde, 64U, 24U, ball_c) == OPENQPEP_OK, "qvs_sample_in_ball");

    /* Verify ball_c Hamming weight == 24 */
    int nz_cnt = 0;
    for (int i = 0; i < 256; i++) {
        if (ball_c[i] != 0) {
            QPEP_CHECK(ball_c[i] == 1 || ball_c[i] == OPENQPEP_QVS_Q - 1, "ball_c coeff in {1, Q-1}");
            nz_cnt++;
        }
    }
    QPEP_CHECK(nz_cnt == 24, "qvs_sample_in_ball weight == tau");

    /* 3x2 QVS matrix-vector parity between precomputed & streaming */
    int32_t *a_flat = (int32_t *)calloc(3U * 2U * 256U, sizeof(int32_t));
    QPEP_CHECK(a_flat != NULL, "calloc QVS A_hat");
    QPEP_CHECK(openqpep_qvs_expand_matrix(rho, 3U, 2U, a_flat) == OPENQPEP_OK, "qvs_expand_matrix");
    int32_t vec_l[2 * 256], out_pre[3 * 256], out_str[3 * 256];
    memcpy(vec_l, ah, sizeof(ah));
    memcpy(vec_l + 256, bh, sizeof(bh));
    QPEP_CHECK(openqpep_qvs_matvec_precomputed(a_flat, 3U, 2U, vec_l, out_pre) == OPENQPEP_OK, "qvs_matvec_precomputed");
    QPEP_CHECK(openqpep_qvs_matvec(rho, 3U, 2U, vec_l, NULL, 0, out_str) == OPENQPEP_OK, "qvs_matvec streaming");
    for (int i = 0; i < 3 * 256; i++) QPEP_CHECK(out_pre[i] == out_str[i], "qvs precomputed == streaming");
    free(a_flat);

    uint8_t p_bytes[256 * 4];
    pack_i32_le(m1, 256U, p_bytes);
    dump_sha3_256("QVS_NTT_PROD", p_bytes, sizeof(p_bytes));
    pack_i32_le(r1, 256U, p_bytes);
    dump_sha3_256("QVS_DECOMP_R1", p_bytes, sizeof(p_bytes));
    pack_i32_le(mask_y, 256U, p_bytes);
    dump_sha3_256("QVS_MASK_Y", p_bytes, sizeof(p_bytes));
    pack_i32_le(ball_c, 256U, p_bytes);
    dump_sha3_256("QVS_BALL_C", p_bytes, sizeof(p_bytes));
    return 0;
}

/* ========================================================================= */
/* Suite 6: Centered Binomial Distribution Samplers (3 symbols)              */
/* ========================================================================= */
static int test_suite_06_cbd(void) {
    uint8_t buf128[128];
    for (size_t i = 0U; i < 128U; i++) buf128[i] = (uint8_t)(i * 29U + 5U);

    int32_t c1[256], c2[256], cq[256];
    openqpep_cbd1_3329(buf128, c1);
    openqpep_cbd2_3329(buf128, c2);
    openqpep_cbd2_qvs(buf128, cq);

    for (int i = 0; i < 256; i++) {
        QPEP_CHECK(c1[i] == 0 || c1[i] == 1 || c1[i] == OPENQPEP_QLX_Q - 1, "cbd1_3329 in {-1,0,1}");
        QPEP_CHECK(c2[i] <= 2 || c2[i] >= OPENQPEP_QLX_Q - 2, "cbd2_3329 in {-2..2}");
        QPEP_CHECK(cq[i] <= 2 || cq[i] >= OPENQPEP_QVS_Q - 2, "cbd2_qvs in {-2..2}");
    }

    uint8_t bytes[256 * 4];
    pack_i32_le(c1, 256U, bytes); dump_sha3_256("CBD1_3329", bytes, sizeof(bytes));
    pack_i32_le(c2, 256U, bytes); dump_sha3_256("CBD2_3329", bytes, sizeof(bytes));
    pack_i32_le(cq, 256U, bytes); dump_sha3_256("CBD2_QVS", bytes, sizeof(bytes));
    return 0;
}

/* ========================================================================= */
/* Suite 7: Plain-LWE Row-Streamed Accelerator (9 symbols, stack + heap)     */
/* ========================================================================= */
static int test_suite_07_plain_lwe(void) {
    /* Low-level row ops */
    uint16_t dst[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint16_t row[8] = {10, 20, 30, 40, 50, 60, 70, 80};
    openqpep_plain_lwe_row_accum_u16(dst, row, 3U, 8U);
    QPEP_CHECK(dst[0] == 31U && dst[7] == 248U, "plain_lwe_row_accum_u16");

    uint16_t b_row[2], e_row[2] = {5U, 7U}, a_row[4] = {1U, 2U, 3U, 4U};
    uint16_t s_flat[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    openqpep_plain_lwe_keygen_row_u16(b_row, e_row, a_row, s_flat, 4U, 2U);
    QPEP_CHECK(b_row[0] == (uint16_t)(5U + 1U*1U + 2U*3U + 3U*5U + 4U*7U), "plain_lwe_keygen_row_u16[0]");

    uint8_t seed_a[32], seed_s[32], seed_z[32], msg16[16], coins32[32];
    for (size_t i = 0U; i < 32U; i++) {
        seed_a[i] = (uint8_t)(0x30U + i);
        seed_s[i] = (uint8_t)(0x50U + i);
        seed_z[i] = (uint8_t)(0x70U + i);
        coins32[i] = (uint8_t)(0x90U + i);
    }
    for (size_t i = 0U; i < 16U; i++) msg16[i] = (uint8_t)(0xA0U + i);

    /* Noise sampler + row expansion + keygen_matrix */
    uint16_t noise[64], erow[64];
    static const uint8_t dom[] = "CALYX-PLWE-TEST|";
    QPEP_CHECK(openqpep_plain_lwe_sample_noise(dom, sizeof(dom) - 1U, seed_s, 32U, 64U, noise) == OPENQPEP_OK, "sample_noise");
    QPEP_CHECK(openqpep_plain_lwe_expand_row(seed_a, 3U, 64U, erow) == OPENQPEP_OK, "expand_row");

    uint16_t s64[64 * 8], e64[64 * 8], b64[64 * 8];
    QPEP_CHECK(openqpep_plain_lwe_sample_noise(dom, sizeof(dom) - 1U, seed_s, 32U, 64U * 8U, s64) == OPENQPEP_OK, "sample S");
    QPEP_CHECK(openqpep_plain_lwe_sample_noise(dom, sizeof(dom) - 1U, seed_z, 32U, 64U * 8U, e64) == OPENQPEP_OK, "sample E");
    QPEP_CHECK(openqpep_plain_lwe_keygen_matrix(seed_a, s64, e64, 64U, 8U, b64) == OPENQPEP_OK, "keygen_matrix");

    /* Full FO KEM round-trip on BOTH stack path (n=64) and multi-tile heap path (n=300) */
    const uint32_t test_ns[2] = {64U, 300U};
    for (int ti = 0; ti < 2; ti++) {
        uint32_t n = test_ns[ti];
        uint32_t nbar = 8U;
        size_t pk_len = 36U + 2U * (size_t)n * (size_t)nbar;
        size_t sk_len = 36U + pk_len + 2U * (size_t)n * (size_t)nbar;
        size_t ct_len = 2U * (size_t)nbar * (size_t)n + 2U * (size_t)nbar * (size_t)nbar;

        uint8_t *pk = (uint8_t *)malloc(pk_len);
        uint8_t *sk = (uint8_t *)malloc(sk_len);
        uint8_t *ct = (uint8_t *)malloc(ct_len);
        uint8_t *ct_cpa = (uint8_t *)malloc(ct_len);
        QPEP_CHECK(pk && sk && ct && ct_cpa, "malloc Plain-LWE buffers");

        uint8_t ss1[32], ss2[32], ss_bad[32];
        QPEP_CHECK(openqpep_plain_lwe_keygen_from_seeds(n, nbar, seed_a, seed_s, seed_z, pk, pk_len, sk, sk_len) == OPENQPEP_OK, "plain_lwe keygen");
        QPEP_CHECK(openqpep_plain_lwe_indcpa_enc(pk, pk_len, msg16, coins32, ct_cpa, ct_len) == OPENQPEP_OK, "plain_lwe indcpa_enc");
        QPEP_CHECK(openqpep_plain_lwe_encaps(pk, pk_len, msg16, ct, ct_len, ss1) == OPENQPEP_OK, "plain_lwe encaps");
        QPEP_CHECK(openqpep_plain_lwe_decaps(sk, sk_len, ct, ct_len, ss2) == OPENQPEP_OK, "plain_lwe decaps");
        QPEP_CHECK(openqpep_ct_eq(ss1, ss2, 32U) == 1, "Plain-LWE FO shared secret match");

        /* 1-bit tamper -> implicit rejection */
        ct[0] ^= 0x01U;
        QPEP_CHECK(openqpep_plain_lwe_decaps(sk, sk_len, ct, ct_len, ss_bad) == OPENQPEP_OK, "plain_lwe tampered decaps");
        QPEP_CHECK(openqpep_ct_eq(ss1, ss_bad, 32U) == 0, "Plain-LWE FO implicit rejection differs");
        ct[0] ^= 0x01U;

        if (n == 64U) {
            dump_sha3_256("PLWE64_PK", pk, pk_len);
            dump_sha3_256("PLWE64_CT", ct, ct_len);
            dump_hex("PLWE64_SS", ss1, 32U);
            dump_hex("PLWE64_REJ", ss_bad, 32U);
        }

        openqpep_explicit_bzero(sk, sk_len);
        free(pk); free(sk); free(ct); free(ct_cpa);
    }
    return 0;
}

/* ========================================================================= */
/* Suite 8: Binary Goppa GF(2^10) & Patterson Decoding (11 symbols)          */
/* ========================================================================= */
static int test_suite_08_goppa(void) {
    /* Exhaustive GF(2^10) mul, sq, inv, sqrt identities across all 1024 elements */
    QPEP_CHECK(openqpep_gf2m10_inv(0U) == 0U, "gf2m10_inv(0)==0");
    QPEP_CHECK(openqpep_gf2m10_sqrt(0U) == 0U, "gf2m10_sqrt(0)==0");
    for (uint16_t a = 1U; a < 1024U; a++) {
        uint16_t sq = openqpep_gf2m10_sq(a);
        uint16_t m = openqpep_gf2m10_mul(a, a);
        uint16_t inv = openqpep_gf2m10_inv(a);
        uint16_t sr = openqpep_gf2m10_sqrt(a);
        QPEP_CHECK(sq == m, "gf2m10_sq == gf2m10_mul(a,a)");
        QPEP_CHECK(openqpep_gf2m10_mul(a, inv) == 1U, "a * gf2m10_inv(a) == 1");
        QPEP_CHECK(openqpep_gf2m10_sq(sr) == a, "sq(sqrt(a)) == a");
    }

    /* Deterministic irreducible degree-32 monic Goppa polynomial + support */
    uint16_t g[33];
    uint16_t support[1024];
    uint8_t *t_mat = (uint8_t *)malloc(OPENQPEP_GOPPA_T_BYTES);
    QPEP_CHECK(t_mat != NULL, "malloc Goppa T");

    int built = 0;
    for (uint32_t ctr = 0U; ctr < 2000U && !built; ctr++) {
        uint8_t seed[36];
        for (size_t i = 0U; i < 32U; i++) seed[i] = (uint8_t)(0x42U + i);
        seed[32] = (uint8_t)((ctr >> 24) & 0xFFU);
        seed[33] = (uint8_t)((ctr >> 16) & 0xFFU);
        seed[34] = (uint8_t)((ctr >> 8) & 0xFFU);
        seed[35] = (uint8_t)(ctr & 0xFFU);
        uint8_t raw[64];
        QPEP_CHECK(openqpep_qsponge_var(seed, sizeof(seed), raw, sizeof(raw)) == OPENQPEP_OK, "goppa seed XOF");
        for (int i = 0; i < 32; i++) {
            g[i] = (uint16_t)(((uint16_t)raw[2 * i] | ((uint16_t)raw[2 * i + 1] << 8)) & 0x3FFU);
        }
        g[0] |= 1U;
        g[32] = 1U;
        if (!openqpep_goppa_is_irreducible(g, 32U)) continue;
        for (uint16_t i = 0U; i < 1024U; i++) support[i] = i;
        if (openqpep_goppa_build_systematic_t(g, support, t_mat) == OPENQPEP_OK) {
            built = 1;
        }
    }
    QPEP_CHECK(built == 1, "found irreducible degree-32 Goppa poly & systematic T");

    /* poly_eval vs poly_eval_batch parity */
    uint16_t evals[1024];
    QPEP_CHECK(openqpep_goppa_poly_eval_batch(g, 33U, support, 1024U, evals) == OPENQPEP_OK, "goppa_poly_eval_batch");
    for (int i = 0; i < 32; i++) {
        QPEP_CHECK(evals[i] == openqpep_goppa_poly_eval(g, 33U, support[i]), "poly_eval == poly_eval_batch");
        QPEP_CHECK(evals[i] != 0U, "irreducible g has no roots in GF(2^10)");
    }

    /* Syndrome + Patterson decode + Chien search on weight-32 error vector */
    uint8_t err128[128], syn40[40], rec128[128];
    memset(err128, 0, sizeof(err128));
    for (uint32_t k = 0U; k < 32U; k++) {
        uint32_t pos = k * 31U + 5U;
        err128[pos >> 3] |= (uint8_t)(1U << (pos & 7U));
    }
    QPEP_CHECK(openqpep_goppa_syndrome(t_mat, OPENQPEP_GOPPA_T_BYTES, err128, syn40) == OPENQPEP_OK, "goppa_syndrome");
    uint32_t wt = 0U;
    QPEP_CHECK(openqpep_goppa_patterson_decode(g, support, syn40, rec128, &wt) == OPENQPEP_OK, "goppa_patterson_decode");
    QPEP_CHECK(wt == 32U && openqpep_ct_eq(err128, rec128, 128U) == 1, "Patterson recovered exact 32-bit error");

    /* Standalone Chien search sanity on linear factor (x + support[7]) */
    uint16_t lin_sig[2] = {support[7], 1U};
    uint8_t ch_err[128];
    uint32_t ch_wt = 0U;
    QPEP_CHECK(openqpep_goppa_chien_search(lin_sig, 2U, support, ch_err, &ch_wt) == OPENQPEP_OK, "goppa_chien_search");
    QPEP_CHECK(ch_wt == 1U && (ch_err[0] & (1U << 7)) != 0U, "Chien search located root 7");

    uint8_t g_bytes[33 * 2];
    pack_u16_le(g, 33U, g_bytes);
    dump_hex("GOPPA_G", g_bytes, sizeof(g_bytes));
    dump_sha3_256("GOPPA_T", t_mat, OPENQPEP_GOPPA_T_BYTES);
    dump_hex("GOPPA_SYN", syn40, 40U);
    dump_hex("GOPPA_REC", rec128, 128U);

    openqpep_explicit_bzero(t_mat, OPENQPEP_GOPPA_T_BYTES);
    free(t_mat);
    return 0;
}

/* ========================================================================= */
/* Suite 9: Rank-Metric GF(2^127) & LRPC Ring (5 symbols)                    */
/* ========================================================================= */
static int test_suite_09_rank_lrpc(void) {
    uint8_t a16[16], b16[16], sq1[16], sq2[16], inv16[16], prod16[16];
    for (size_t i = 0U; i < 16U; i++) {
        a16[i] = (uint8_t)(i * 19U + 5U);
        b16[i] = (uint8_t)(i * 23U + 11U);
    }
    a16[15] &= 0x7FU;
    b16[15] &= 0x7FU;

    QPEP_CHECK(openqpep_gf2_127_sq(a16, sq1) == OPENQPEP_OK, "gf2_127_sq");
    QPEP_CHECK(openqpep_gf2_127_mul(a16, a16, sq2) == OPENQPEP_OK, "gf2_127_mul(a,a)");
    QPEP_CHECK(openqpep_ct_eq(sq1, sq2, 16U) == 1, "gf2_127_sq == mul(a,a)");

    QPEP_CHECK(openqpep_gf2_127_inv(a16, inv16) == OPENQPEP_OK, "gf2_127_inv");
    QPEP_CHECK(openqpep_gf2_127_mul(a16, inv16, prod16) == OPENQPEP_OK, "a * inv(a)");
    uint8_t one16[16];
    memset(one16, 0, sizeof(one16));
    one16[0] = 1U;
    QPEP_CHECK(openqpep_ct_eq(prod16, one16, 16U) == 1, "a * gf2_127_inv(a) == 1");

    /* LRPC ring mul & inv mod (X^47 + X^5 + 1) */
    uint8_t p1[OPENQPEP_LRPC_POLY_BYTES], p_inv[OPENQPEP_LRPC_POLY_BYTES], p_prod[OPENQPEP_LRPC_POLY_BYTES];
    uint8_t p_zero[OPENQPEP_LRPC_POLY_BYTES];
    memset(p_zero, 0, sizeof(p_zero));
    for (size_t i = 0U; i < sizeof(p1); i++) p1[i] = (uint8_t)((i * 31U + 7U) & 0xFFU);
    for (size_t j = 0U; j < OPENQPEP_LRPC_N; j++) p1[j * 16U + 15U] &= 0x7FU;

    QPEP_CHECK(openqpep_lrpc_ring_inv(p_zero, p_inv) == OPENQPEP_ERR_SINGULAR, "lrpc_ring_inv(0) singular");
    QPEP_CHECK(openqpep_lrpc_ring_inv(p1, p_inv) == OPENQPEP_OK, "lrpc_ring_inv");
    QPEP_CHECK(openqpep_lrpc_ring_mul(p1, p_inv, p_prod) == OPENQPEP_OK, "lrpc_ring_mul(p1, inv)");
    QPEP_CHECK(openqpep_ct_eq(p_prod, one16, 16U) == 1, "lrpc ring prod coeff 0 == 1");
    QPEP_CHECK(openqpep_is_zeroed(p_prod + 16U, sizeof(p_prod) - 16U) == 1, "lrpc ring prod coeffs 1..46 == 0");

    QPEP_CHECK(openqpep_gf2_127_mul(a16, b16, prod16) == OPENQPEP_OK, "gf2_127_mul(a,b)");
    dump_hex("GF2_127_MUL", prod16, 16U);
    dump_hex("GF2_127_INV", inv16, 16U);
    dump_sha3_256("LRPC_INV", p_inv, sizeof(p_inv));
    return 0;
}

/* ========================================================================= */
/* Suite 10: UOV Multivariate Quadratic over GF(256) (4 symbols)             */
/* ========================================================================= */
static int test_suite_10_uov(void) {
    /* Constant-time Gauss-Jordan solver on cyclic zero-diagonal + singular matrix */
    uint8_t cyc[16] = {
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
        1, 0, 0, 0
    };
    uint8_t rhs[4] = {0x11U, 0x22U, 0x33U, 0x44U}, sol[4];
    QPEP_CHECK(openqpep_uov_solve_gf256_linear(cyc, rhs, 4U, sol) == OPENQPEP_OK, "uov_solve cyclic");
    QPEP_CHECK(sol[0] == 0x44U && sol[1] == 0x11U && sol[2] == 0x22U && sol[3] == 0x33U, "cyclic sol exact");

    uint8_t sing[16];
    memset(sing, 0, sizeof(sing));
    QPEP_CHECK(openqpep_uov_solve_gf256_linear(sing, rhs, 4U, sol) == OPENQPEP_ERR_SINGULAR, "singular rejected");

    /* Full UOV v=64, m=32 P_3 keygen + sign_core + eval_public_map */
    const uint32_t v = 64U, m = 32U;
    const size_t p3_len = (size_t)m * (((size_t)m * ((size_t)m + 1U)) / 2U);
    uint8_t *p3 = (uint8_t *)malloc(p3_len);
    QPEP_CHECK(p3 != NULL, "malloc UOV P3");

    uint8_t seed_pk[32], seed_sk[32], salt[16], target[32], sv[64], so[32], eval_out[32];
    for (size_t i = 0U; i < 32U; i++) {
        seed_pk[i] = (uint8_t)(0xA1U + i);
        seed_sk[i] = (uint8_t)(0xB1U + i);
        target[i]  = (uint8_t)(0xC1U + i);
    }
    for (size_t i = 0U; i < 16U; i++) salt[i] = (uint8_t)(0xD1U + i);

    QPEP_CHECK(openqpep_uov_compute_p3(seed_pk, seed_sk, v, m, p3, p3_len) == OPENQPEP_OK, "uov_compute_p3");
    QPEP_CHECK(openqpep_uov_sign_core(seed_pk, seed_sk, salt, target, v, m, sv, so) == OPENQPEP_OK, "uov_sign_core");
    QPEP_CHECK(openqpep_uov_eval_public_map(seed_pk, p3, p3_len, v, m, sv, so, eval_out) == OPENQPEP_OK, "uov_eval_public_map");
    QPEP_CHECK(openqpep_ct_eq(eval_out, target, m) == 1, "P(sv, so) == target");

    dump_sha3_256("UOV_P3", p3, p3_len);
    dump_hex("UOV_SV", sv, v);
    dump_hex("UOV_SO", so, m);

    free(p3);
    return 0;
}

/* ========================================================================= */
/* Suite 11: Wire v5/v5.1 Framing, TLV & CC-512 CMT-4/SIV (12 symbols)       */
/* ========================================================================= */
static int test_suite_11_wire_cc512(void) {
    static const uint8_t m_v5[6]   = {0x89U, 'Q', 'P', 'E', 0x05U, 0x00U};
    static const uint8_t m_v51[6]  = {0x89U, 'Q', 'P', 'E', 0x05U, 0x01U};
    static const uint8_t m_rc[6]   = {0x89U, 'Q', 'P', 'E', 0x04U, 0x00U};
    static const uint8_t m_pc[6]   = {0x89U, 'Q', 'P', 'E', 0x03U, 0x00U};
    static const uint8_t m_beta[6] = {0x89U, 'Q', 'P', 'E', 0x01U, 0x01U};
    QPEP_CHECK(openqpep_verify_wire_v5_magic(m_v5, 6U) == OPENQPEP_WIRE_V5_FULL, "magic v5");
    QPEP_CHECK(openqpep_verify_wire_v5_magic(m_v51, 6U) == OPENQPEP_WIRE_V5_1_COMPACT, "magic v5.1");
    QPEP_CHECK(openqpep_verify_wire_v5_magic(m_rc, 6U) == OPENQPEP_WIRE_ERR_LEGACY_RC, "magic legacy rc");
    QPEP_CHECK(openqpep_verify_wire_v5_magic(m_pc, 6U) == OPENQPEP_WIRE_ERR_LEGACY_PC, "magic legacy pc");
    QPEP_CHECK(openqpep_verify_wire_v5_magic(m_beta, 6U) == OPENQPEP_WIRE_ERR_LEGACY_BETA, "magic legacy beta");

    static const uint8_t label[] = "OPENQPEP-C99-SELFTEST";
    size_t lbl_len = sizeof(label) - 1U;
    uint8_t nonce16[16], body[300], frame[300 + OPENQPEP_WIRE_V5_OVERHEAD], unp[300], mac32[32];
    for (size_t i = 0U; i < 16U; i++) nonce16[i] = (uint8_t)(i + 1U);
    for (size_t i = 0U; i < 300U; i++) body[i] = (uint8_t)(i * 7U + 3U);

    QPEP_CHECK(openqpep_wire_v5_pack(body, 300U, label, lbl_len, 0x01U, 0x00U, nonce16, 0, frame, sizeof(frame)) == OPENQPEP_OK, "wire_v5_pack");
    size_t out_len = 0U;
    uint8_t ptype = 0U, flags = 0xFFU;
    QPEP_CHECK(openqpep_wire_v5_unpack(frame, sizeof(frame), label, lbl_len, 0, unp, sizeof(unp), &out_len, &ptype, &flags) == OPENQPEP_OK, "wire_v5_unpack");
    QPEP_CHECK(out_len == 300U && ptype == 0x01U && flags == 0x00U && openqpep_ct_eq(unp, body, 300U), "wire v5 round-trip");

    /* Standalone whiten_xor + compute_mac */
    uint8_t wh[300];
    QPEP_CHECK(openqpep_wire_whiten_xor(frame, nonce16, label, lbl_len, 0, body, wh, 300U) == OPENQPEP_OK, "wire_whiten_xor");
    QPEP_CHECK(openqpep_ct_eq(wh, frame + 24, 300U) == 1, "whiten matches packed slice");
    QPEP_CHECK(openqpep_wire_compute_mac(frame, nonce16, label, lbl_len, 0, wh, 300U, mac32) == OPENQPEP_OK, "wire_compute_mac");
    QPEP_CHECK(openqpep_ct_eq(mac32, frame + 24 + 300, 32U) == 1, "mac matches packed slice");

    /* Authenticate-then-unwhiten leaves output untouched on MAC tamper */
    memset(unp, 0x5AU, sizeof(unp));
    frame[sizeof(frame) - 1U] ^= 0x01U;
    QPEP_CHECK(openqpep_wire_v5_unpack(frame, sizeof(frame), label, lbl_len, 0, unp, sizeof(unp), &out_len, &ptype, &flags) == OPENQPEP_ERR_AUTH_FAIL, "tamper rejected");
    for (size_t i = 0U; i < sizeof(unp); i++) QPEP_CHECK(unp[i] == 0x5AU, "output untouched on auth fail");
    frame[sizeof(frame) - 1U] ^= 0x01U;

    /* Compact TLV v5.1 validator */
    static const uint8_t tlv_ok[] = {0x01U, 0, 0, 0, 2, 'H', 'I', 0x09U, 0, 0, 0, 1, 'Z'};
    static const uint8_t tlv_ovf[] = {0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 'A'};
    uint32_t fcnt = 0U;
    QPEP_CHECK(openqpep_wire_validate_tlv(tlv_ok, sizeof(tlv_ok), 1, 256U, &fcnt) == OPENQPEP_OK && fcnt == 2U, "tlv valid");
    QPEP_CHECK(openqpep_wire_validate_tlv(tlv_ovf, sizeof(tlv_ovf), 1, 256U, &fcnt) == OPENQPEP_ERR_WIRE_FORMAT, "tlv overflow rejected");

    /* CC-512 CMT-4 & SIV */
    uint8_t key64[64], nonce24[24], sub96[96], tag32[32], mst128[128], siv32[32], mk88[88];
    for (size_t i = 0U; i < 64U; i++) key64[i] = (uint8_t)(0x11U + i);
    for (size_t i = 0U; i < 24U; i++) nonce24[i] = (uint8_t)(0x61U + i);
    QPEP_CHECK(openqpep_cc512_derive_cmt4_subkeys(key64, nonce24, sub96) == OPENQPEP_OK, "cc512_derive_cmt4_subkeys");
    QPEP_CHECK(openqpep_cc512_cmt4_tag(sub96 + 64, nonce24, label, lbl_len, body, 300U, tag32) == OPENQPEP_OK, "cc512_cmt4_tag");
    QPEP_CHECK(openqpep_cc512_verify_cmt4_tag(sub96 + 64, nonce24, label, lbl_len, body, 300U, tag32) == OPENQPEP_OK, "cc512_verify_cmt4_tag ok");
    tag32[0] ^= 0x80U;
    QPEP_CHECK(openqpep_cc512_verify_cmt4_tag(sub96 + 64, nonce24, label, lbl_len, body, 300U, tag32) == OPENQPEP_ERR_AUTH_FAIL, "cc512_verify_cmt4_tag fail");
    tag32[0] ^= 0x80U;
    QPEP_CHECK(openqpep_cc512_siv_master_subkeys(key64, mst128) == OPENQPEP_OK, "cc512_siv_master_subkeys");
    QPEP_CHECK(openqpep_cc512_siv_synth(mst128, nonce16, 16U, label, lbl_len, body, 300U, siv32) == OPENQPEP_OK, "cc512_siv_synth");
    QPEP_CHECK(openqpep_cc512_siv_msg_keys(mst128 + 64, siv32, mk88) == OPENQPEP_OK, "cc512_siv_msg_keys");

    dump_sha3_256("WIRE_V5_FRAME", frame, sizeof(frame));
    dump_hex("CC512_CMT4_TAG", tag32, 32U);
    dump_hex("CC512_SIV32", siv32, 32U);
    dump_hex("CC512_SIV_MK88", mk88, 88U);
    return 0;
}

/* ========================================================================= */
/* Suite 12: QHS-512 4-Way SIMD WOTS+ & XMSS Merkle TreeHash (9 symbols)     */
/* ========================================================================= */
static int test_suite_12_qhs512(void) {
    uint8_t sk_seed[32], pub_seed[32], rnd32[32], dig32[32];
    for (size_t i = 0U; i < 32U; i++) {
        sk_seed[i]  = (uint8_t)(0x05U + i);
        pub_seed[i] = (uint8_t)(0x45U + i);
        rnd32[i]    = (uint8_t)(0x85U + i);
        dig32[i]    = (uint8_t)(0xC5U + i);
    }

    uint8_t ch1[32], ch2[32];
    QPEP_CHECK(openqpep_qhs_wots_chain(dig32, 0U, 15U, pub_seed, 3U, 17U, ch1) == OPENQPEP_OK, "qhs_wots_chain full");
    QPEP_CHECK(openqpep_qhs_wots_chain(dig32, 0U, 6U, pub_seed, 3U, 17U, ch2) == OPENQPEP_OK, "qhs_wots_chain part 1");
    QPEP_CHECK(openqpep_qhs_wots_chain(ch2, 6U, 9U, pub_seed, 3U, 17U, ch2) == OPENQPEP_OK, "qhs_wots_chain part 2");
    QPEP_CHECK(openqpep_ct_eq(ch1, ch2, 32U) == 1, "WOTS chain composition");

    uint8_t wsig[OPENQPEP_QHS_WOTS_SIG_BYTES], lpk1[32], lpk2[32];
    QPEP_CHECK(openqpep_qhs_wots_pk_from_sk_seed(sk_seed, pub_seed, 5U, lpk1) == OPENQPEP_OK, "qhs_wots_pk_from_sk_seed");
    QPEP_CHECK(openqpep_qhs_wots_sign(sk_seed, pub_seed, 5U, dig32, wsig) == OPENQPEP_OK, "qhs_wots_sign");
    QPEP_CHECK(openqpep_qhs_wots_pk_from_sig(wsig, dig32, pub_seed, 5U, lpk2) == OPENQPEP_OK, "qhs_wots_pk_from_sig");
    QPEP_CHECK(openqpep_ct_eq(lpk1, lpk2, 32U) == 1, "WOTS sign/recover exact");

    uint8_t pk[OPENQPEP_QHS_PK_BYTES], sk[OPENQPEP_QHS_SK_BYTES];
    QPEP_CHECK(openqpep_qhs_keygen_from_seeds(4U, sk_seed, pub_seed, pk, sk) == OPENQPEP_OK, "qhs_keygen_from_seeds");

    uint8_t sub_roots[4 * 32], folded[32], top_auth[2 * 32];
    for (uint32_t s = 0U; s < 4U; s++) {
        QPEP_CHECK(
            openqpep_qhs_treehash_subtree(sk_seed, pub_seed, s * 4U, 2U, 0U, 0, NULL, sub_roots + s * 32U) == OPENQPEP_OK,
            "qhs_treehash_subtree"
        );
    }
    QPEP_CHECK(openqpep_qhs_fold_subtrees(pub_seed, sub_roots, 2U, 2U, 1, top_auth, folded) == OPENQPEP_OK, "qhs_fold_subtrees");
    QPEP_CHECK(openqpep_ct_eq(folded, pk + 33U, 32U) == 1, "split TreeHash + fold == keygen root");

    static const uint8_t msg[] = "OpenQPEP QHS-512 C99 Self-Test Message";
    size_t msg_len = sizeof(msg) - 1U;
    uint8_t sig_det[OPENQPEP_QHS_SIG_FIXED_BYTES + 4U * 32U];
    uint8_t sig_hed[OPENQPEP_QHS_SIG_FIXED_BYTES + 4U * 32U];

    QPEP_CHECK(openqpep_qhs_sign_core(sk, msg, msg_len, 0, NULL, sig_det, sizeof(sig_det)) == OPENQPEP_OK, "qhs_sign_core det");
    QPEP_CHECK(openqpep_qhs_sign_core(sk, msg, msg_len, 1, rnd32, sig_hed, sizeof(sig_hed)) == OPENQPEP_OK, "qhs_sign_core hedged");
    QPEP_CHECK(openqpep_qhs_verify(pk, msg, msg_len, sig_det, sizeof(sig_det)) == OPENQPEP_OK, "qhs_verify det");
    QPEP_CHECK(openqpep_qhs_verify(pk, msg, msg_len, sig_hed, sizeof(sig_hed)) == OPENQPEP_OK, "qhs_verify hedged");

    /* Tamper check + Fault-Guard check */
    sig_hed[36] ^= 0x01U;
    QPEP_CHECK(openqpep_qhs_verify(pk, msg, msg_len, sig_hed, sizeof(sig_hed)) == OPENQPEP_ERR_AUTH_FAIL, "qhs_verify tamper fail");
    sig_hed[36] ^= 0x01U;

    uint8_t sk_bad[OPENQPEP_QHS_SK_BYTES], sig_bad[OPENQPEP_QHS_SIG_FIXED_BYTES + 4U * 32U];
    memcpy(sk_bad, sk, sizeof(sk));
    sk_bad[96] ^= 0x40U;
    QPEP_CHECK(openqpep_qhs_sign_core(sk_bad, msg, msg_len, 0, NULL, sig_bad, sizeof(sig_bad)) == OPENQPEP_ERR_FAULT_GUARD, "qhs fault guard");
    QPEP_CHECK(openqpep_is_zeroed(sig_bad, sizeof(sig_bad)) == 1, "qhs fault guard zeroes sig_out");

    dump_hex("QHS_PK", pk, sizeof(pk));
    dump_sha3_256("QHS_SIG_DET", sig_det, sizeof(sig_det));
    dump_sha3_256("QHS_SIG_HED", sig_hed, sizeof(sig_hed));
    openqpep_explicit_bzero(sk, sizeof(sk));
    openqpep_explicit_bzero(sk_bad, sizeof(sk_bad));
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dump-vectors") == 0) {
            g_dump_vectors = 1;
        }
    }

    int rc = 0;
    rc |= test_suite_01_abi();
    rc |= test_suite_02_consttime_gf256();
    rc |= test_suite_03_keccak();
    rc |= test_suite_04_qlx_3329();
    rc |= test_suite_05_qvs_8380417();
    rc |= test_suite_06_cbd();
    rc |= test_suite_07_plain_lwe();
    rc |= test_suite_08_goppa();
    rc |= test_suite_09_rank_lrpc();
    rc |= test_suite_10_uov();
    rc |= test_suite_11_wire_cc512();
    rc |= test_suite_12_qhs512();

    if (rc != 0 || g_checks_failed != 0) {
        fprintf(stderr, "[ERROR] OpenQPEP C99 Self-Test Harness FAILED (%d/%d checks failed).\n",
                g_checks_failed, g_checks_run);
        return 1;
    }
    printf("[OK] OpenQPEP v%s Standalone C99 Self-Test Harness PASSED: 12/12 suites, 108/108 APIs, %d checks.\n",
           openqpep_version_string(), g_checks_run);
    return 0;
}
