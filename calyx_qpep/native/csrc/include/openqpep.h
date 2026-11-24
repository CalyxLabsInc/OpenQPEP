/*
 * OpenQPEP Official Release 1.2.1 (v1.2.1) — Public C99/SIMD SDK ABI Header
 * Project: OpenQPEP by Calyx Labs Inc. (Creator: Tristen Martinez)
 * Repository: https://github.com/CalyxLabsInc/OpenQPEP
 * License: Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0)
 *
 * Stable versioned C99 ABI for libopenqpep (shared .so/.dylib/.dll and static .a).
 * All exported functions are annotated with OPENQPEP_API; internal helpers remain
 * hidden under -fvisibility=hidden. Safe for inclusion from ISO C99+ and C++11+.
 */
#ifndef OPENQPEP_H
#define OPENQPEP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Version & Monotonic ABI Identification                                    */
/* ------------------------------------------------------------------------- */
#define OPENQPEP_VERSION_MAJOR 1
#define OPENQPEP_VERSION_MINOR 2
#define OPENQPEP_VERSION_PATCH 1
#define OPENQPEP_VERSION_STRING "1.2.1"

#define OPENQPEP_ABI_CURRENT  1
#define OPENQPEP_ABI_REVISION 2
#define OPENQPEP_ABI_AGE      0

#define OPENQPEP_MAKE_ABI_VERSION(maj, min, pat) \
    ((((uint32_t)(maj) & 0xFFU) << 16) |         \
     (((uint32_t)(min) & 0xFFU) << 8)  |         \
     (((uint32_t)(pat) & 0xFFU)))

#define OPENQPEP_ABI_VERSION \
    OPENQPEP_MAKE_ABI_VERSION(OPENQPEP_VERSION_MAJOR, OPENQPEP_VERSION_MINOR, OPENQPEP_VERSION_PATCH)

/* ------------------------------------------------------------------------- */
/* Cross-Platform Symbol Visibility Macros                                   */
/* ------------------------------------------------------------------------- */
#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(OPENQPEP_STATIC)
#    define OPENQPEP_API
#  elif defined(OPENQPEP_BUILDING_DLL)
#    define OPENQPEP_API __declspec(dllexport)
#  else
#    define OPENQPEP_API __declspec(dllimport)
#  endif
#  define OPENQPEP_LOCAL
#elif (defined(__GNUC__) && (__GNUC__ >= 4)) || defined(__clang__)
#  define OPENQPEP_API   __attribute__((visibility("default")))
#  define OPENQPEP_LOCAL __attribute__((visibility("hidden")))
#else
#  define OPENQPEP_API
#  define OPENQPEP_LOCAL
#endif

/* ------------------------------------------------------------------------- */
/* Cryptographic Parameters, Capability Bitflags & Wire Status Codes         */
/* ------------------------------------------------------------------------- */
#define OPENQPEP_QLX_Q 3329
#define OPENQPEP_QLX_N 256
#define OPENQPEP_QVS_Q 8380417
#define OPENQPEP_QVS_N 256
#define OPENQPEP_WIRE_V5_MAGIC_LEN 6

/* Keccak-f[1600] / NIST FIPS 202 Sponge Constants */
#define OPENQPEP_SHA3_256_RATE     136U
#define OPENQPEP_SHA3_512_RATE     72U
#define OPENQPEP_SHAKE128_RATE     168U
#define OPENQPEP_SHAKE256_RATE     136U
#define OPENQPEP_SHA3_256_BYTES    32U
#define OPENQPEP_QSPONGE_512_BYTES 64U
#define OPENQPEP_SHA3_DOMAIN_SEP   0x06U
#define OPENQPEP_SHAKE_DOMAIN_SEP  0x1FU

/** Incremental Keccak-f[1600] sponge state context (zero heap allocations). */
typedef struct {
    uint64_t state[25];
    uint32_t rate;
    uint32_t pos;
    uint8_t  domain_sep;
    uint8_t  squeezing;
    uint8_t  reserved[2];
} openqpep_keccak_ctx_t;

/* Bitflags returned by openqpep_native_abi_info() */
#define OPENQPEP_ABI_FLAG_C99  0x01U
#define OPENQPEP_ABI_FLAG_AVX2 0x02U
#define OPENQPEP_ABI_FLAG_NEON 0x04U

/* Standard C API status codes */
#define OPENQPEP_OK              0
#define OPENQPEP_ERR_NULL_PTR   -1
#define OPENQPEP_ERR_INVALID_LEN -2
#define OPENQPEP_ERR_AUTH_FAIL  -3
#define OPENQPEP_ERR_LEGACY     -4
#define OPENQPEP_ERR_FAULT_GUARD -5

/* Wire Format v5 / v5.1 magic verification return codes */
#define OPENQPEP_WIRE_V5_FULL        50
#define OPENQPEP_WIRE_V5_1_COMPACT   51
#define OPENQPEP_WIRE_ERR_LEGACY_RC -40
#define OPENQPEP_WIRE_ERR_LEGACY_PC -30
#define OPENQPEP_WIRE_ERR_LEGACY_BETA -10
#define OPENQPEP_WIRE_ERR_INVALID    -1

/* ------------------------------------------------------------------------- */
/* Runtime ABI & Capability Introspection                                    */
/* ------------------------------------------------------------------------- */

/** Returns the compiled monotonic ABI version (OPENQPEP_ABI_VERSION). */
OPENQPEP_API uint32_t openqpep_abi_version(void);

/** Returns the null-terminated semantic version string (OPENQPEP_VERSION_STRING). */
OPENQPEP_API const char *openqpep_version_string(void);

/** Returns SIMD/architecture capability bitmask (OPENQPEP_ABI_FLAG_*). */
OPENQPEP_API uint32_t openqpep_native_abi_info(void);

/* ------------------------------------------------------------------------- */
/* QLX Module-LWE 7-Layer NTT & Polynomial Arithmetic over Z_3329[X]/(X^256+1) */
/* ------------------------------------------------------------------------- */

/** Forward 7-layer Cooley-Tukey NTT mod 3329 (in-place on 256 int32_t coefficients). */
OPENQPEP_API void openqpep_ntt_3329(int32_t *p);

/** Inverse 7-layer Gentleman-Sande NTT mod 3329 (in-place on 256 int32_t coefficients). */
OPENQPEP_API void openqpep_inv_ntt_3329(int32_t *p);

/** Base-ring degree-2 multiplication in Z_3329 NTT domain (256-coeff a_hat, b_hat -> out). */
OPENQPEP_API void openqpep_ntt_base_mul_3329(const int32_t *a_hat, const int32_t *b_hat, int32_t *out);

/** Branchless polynomial addition mod 3329 (256 coefficients). */
OPENQPEP_API void openqpep_poly_add_3329(const int32_t *a, const int32_t *b, int32_t *out);

/** Branchless polynomial subtraction mod 3329 (256 coefficients). */
OPENQPEP_API void openqpep_poly_sub_3329(const int32_t *a, const int32_t *b, int32_t *out);

/* ------------------------------------------------------------------------- */
/* QVS Module-SIS/LWE 8-Layer Complete NTT over Z_8380417[X]/(X^256+1)       */
/* ------------------------------------------------------------------------- */

/** Forward 8-layer complete NTT mod 8380417 (in-place on 256 int32_t coefficients). */
OPENQPEP_API void openqpep_ntt_qvs(int32_t *p);

/** Inverse 8-layer complete NTT mod 8380417 (in-place on 256 int32_t coefficients). */
OPENQPEP_API void openqpep_inv_ntt_qvs(int32_t *p);

/** Pointwise multiplication in Z_8380417 NTT domain (256 coefficients). */
OPENQPEP_API void openqpep_ntt_mul_qvs(const int32_t *a_hat, const int32_t *b_hat, int32_t *out);

/* ------------------------------------------------------------------------- */
/* Centered Binomial Distribution (CBD) & Plain-LWE Accelerators             */
/* ------------------------------------------------------------------------- */

/** Branchless CBD_2 sampler mod 3329 (128 input bytes -> 256 int32_t coefficients). */
OPENQPEP_API void openqpep_cbd2_3329(const uint8_t *buf, int32_t *out);

/** Branchless CBD_1 sampler mod 3329 (64 input bytes -> 256 int32_t coefficients). */
OPENQPEP_API void openqpep_cbd1_3329(const uint8_t *buf, int32_t *out);

/** Branchless CBD_2 sampler mod 8380417 (128 input bytes -> 256 int32_t coefficients). */
OPENQPEP_API void openqpep_cbd2_qvs(const uint8_t *buf, int32_t *out);

/** Unstructured Plain-LWE row multiply-accumulate mod 65536: dst[j] += scalar * row[j]. */
OPENQPEP_API void openqpep_plain_lwe_row_accum_u16(
    uint16_t *dst,
    const uint16_t *row,
    uint16_t scalar,
    uint32_t n
);

/** Unstructured Plain-LWE keygen row dot product mod 65536. */
OPENQPEP_API void openqpep_plain_lwe_keygen_row_u16(
    uint16_t *b_row,
    const uint16_t *e_row,
    const uint16_t *a_row,
    const uint16_t *s_flat,
    uint32_t n,
    uint32_t nbar
);

/* ------------------------------------------------------------------------- */
/* Constant-Time Primitives, Zeroization, GF(256) & Wire v5 Verification     */
/* ------------------------------------------------------------------------- */

/** Branchless constant-time GF(256) multiplication modulo x^8 + x^4 + x^3 + x + 1 (0x11B). */
OPENQPEP_API uint8_t openqpep_gf256_mul(uint8_t a, uint8_t b);

/** Byte-wise XOR accumulate: dst[i] ^= src[i] for i in [0, len). */
OPENQPEP_API void openqpep_xor_accum_bytes(uint8_t *dst, const uint8_t *src, uint32_t len);

/** Constant-time buffer equality check: returns 1 if equal, 0 otherwise. */
OPENQPEP_API int openqpep_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);

/** Branchless constant-time conditional select: out[i] = cond ? a[i] : b[i]. */
OPENQPEP_API void openqpep_ct_cmov(int cond, uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len);

/** Compiler-barrier explicit memory zeroization resistant to dead-store elimination. */
OPENQPEP_API void openqpep_explicit_bzero(void *ptr, size_t len);

/** Constant-time volatile verification that a buffer is all 0x00 bytes (1 = zeroed, 0 = non-zero). */
OPENQPEP_API int openqpep_is_zeroed(const uint8_t *ptr, size_t len);

/** Constant-time Wire Format v5 (\x89QPE\x05\x00) / v5.1 (\x89QPE\x05\x01) magic validator. */
OPENQPEP_API int openqpep_verify_wire_v5_magic(const uint8_t *hdr, size_t len);

/* ------------------------------------------------------------------------- */
/* Zero-Dependency Constant-Time Keccak-f[1600] (qSponge-512 / SHA3 / SHAKE) */
/* ------------------------------------------------------------------------- */

/** Unrolled 24-round constant-time Keccak-f[1600] permutation over 25 uint64 lanes. */
OPENQPEP_API void openqpep_keccak_f1600(uint64_t state[25]);

/** Initializes a generic Keccak-f[1600] sponge context with given rate and domain separator. */
OPENQPEP_API int openqpep_keccak_init(openqpep_keccak_ctx_t *ctx, uint32_t rate, uint8_t domain_sep);

/** Initializes an incremental SHA3-512 (qSponge-512) context. */
OPENQPEP_API int openqpep_sha3_512_init(openqpep_keccak_ctx_t *ctx);

/** Initializes an incremental SHA3-256 context. */
OPENQPEP_API int openqpep_sha3_256_init(openqpep_keccak_ctx_t *ctx);

/** Initializes an incremental SHAKE-256 (qSponge-XOF) context. */
OPENQPEP_API int openqpep_shake256_init(openqpep_keccak_ctx_t *ctx);

/** Initializes an incremental SHAKE-128 context. */
OPENQPEP_API int openqpep_shake128_init(openqpep_keccak_ctx_t *ctx);

/** Incrementally absorbs `in_len` bytes into an active sponge context. */
OPENQPEP_API int openqpep_keccak_absorb(openqpep_keccak_ctx_t *ctx, const uint8_t *in, size_t in_len);

/** Finalizes sponge absorption with NIST FIPS 202 pad10*1 padding. */
OPENQPEP_API int openqpep_keccak_finalize(openqpep_keccak_ctx_t *ctx);

/** Incrementally squeezes `out_len` output bytes (auto-finalizes if needed). */
OPENQPEP_API int openqpep_keccak_squeeze(openqpep_keccak_ctx_t *ctx, uint8_t *out, size_t out_len);

/** Compiler-barrier wipes all state inside `ctx` via openqpep_explicit_bzero. */
OPENQPEP_API void openqpep_keccak_wipe(openqpep_keccak_ctx_t *ctx);

/** One-shot qSponge-512 (NIST FIPS 202 SHA3-512): 64-byte fixed digest. */
OPENQPEP_API int openqpep_qsponge_512(const uint8_t *in, size_t in_len, uint8_t out64[64]);

/** One-shot NIST FIPS 202 SHA3-256: 32-byte fixed digest. */
OPENQPEP_API int openqpep_sha3_256(const uint8_t *in, size_t in_len, uint8_t out32[32]);

/** One-shot qSponge-XOF (NIST FIPS 202 SHAKE-256): variable `out_len`-byte output. */
OPENQPEP_API int openqpep_qsponge_var(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

/** One-shot NIST FIPS 202 SHAKE-128: variable `out_len`-byte output. */
OPENQPEP_API int openqpep_shake128(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* OPENQPEP_H */
