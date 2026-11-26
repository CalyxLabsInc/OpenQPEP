/*
 * OpenQPEP Official Release 1.2.9 (v1.2.9) — Native C99 / SIMD Accelerators for
 * Calyx Sovereign-Pentad GF(256) / XOR, Branchless Constant-Time Helpers
 * (openqpep_ct_eq, openqpep_ct_cmov, openqpep_ct_cswap, openqpep_ct_select_u32,
 * openqpep_ct_mem_bounds_ok, openqpep_is_zeroed), and Compiler-Barrier Zeroization
 * (openqpep_explicit_bzero).
 *
 * Note: openqpep_verify_wire_v5_magic was relocated to wire_c.c in v1.2.9 and
 * upgraded to a fully branchless constant-time implementation alongside zero-heap
 * Wire v5/v5.1 framing and CC-512 CMT-4/SIV streaming helpers.
 *
 * Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
 */
#include "openqpep.h"

/* Branchless unsigned 64-bit less-than: returns 1 if a < b, else 0 (zero branches) */
static uint32_t ct_lt_u64(uint64_t a, uint64_t b) {
    return (uint32_t)((((~a) & b) | ((~(a ^ b)) & (a - b))) >> 63);
}

/* Branchless constant-time GF(256) multiplication modulo 0x11B */
OPENQPEP_API uint8_t openqpep_gf256_mul(uint8_t a, uint8_t b) {
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

OPENQPEP_API void openqpep_xor_accum_bytes(uint8_t *dst, const uint8_t *src, uint32_t len) {
    if (!dst || !src) return;
    for (uint32_t i = 0U; i < len; i++) {
        dst[i] ^= src[i];
    }
}

/* Branchless 32-bit constant-time select: returns a if cond != 0 else b */
OPENQPEP_API uint32_t openqpep_ct_select_u32(uint32_t cond, uint32_t a, uint32_t b) {
    uint32_t nz = (cond | (0U - cond)) >> 31;
    uint32_t mask = 0U - nz;
    return (a & mask) | (b & (~mask));
}

/* Branchless overflow-safe constant-time bounds check: returns 1 iff offset <= total && span <= total - offset */
OPENQPEP_API int openqpep_ct_mem_bounds_ok(size_t offset, size_t span, size_t total) {
    uint64_t off64 = (uint64_t)offset;
    uint64_t span64 = (uint64_t)span;
    uint64_t tot64 = (uint64_t)total;
    uint32_t ok1 = 1U ^ ct_lt_u64(tot64, off64);
    uint64_t rem = (tot64 - off64) & (0ULL - (uint64_t)ok1);
    uint32_t ok2 = 1U ^ ct_lt_u64(rem, span64);
    return (int)(ok1 & ok2);
}

/* Constant-time byte-buffer comparison: returns 1 if equal, 0 otherwise */
OPENQPEP_API int openqpep_ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) return 0;
    volatile uint8_t diff = 0U;
    for (size_t i = 0U; i < len; i++) {
        diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
    }
    uint32_t x = (uint32_t)diff;
    return (int)(1U ^ ((x | (0U - x)) >> 31));
}

/* Branchless constant-time conditional copy: out[i] = cond ? a[i] : b[i] */
OPENQPEP_API void openqpep_ct_cmov(int cond, uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len) {
    if (!out || !a || !b) return;
    uint32_t u = (uint32_t)cond;
    uint32_t nz = (u | (0U - u)) >> 31;
    uint8_t mask = (uint8_t)(0U - nz);
    uint8_t inv = (uint8_t)(~mask);
    for (size_t i = 0U; i < len; i++) {
        out[i] = (uint8_t)((a[i] & mask) | (b[i] & inv));
    }
}

/* Branchless constant-time conditional in-place swap of equal-length byte buffers */
OPENQPEP_API void openqpep_ct_cswap(int cond, uint8_t *a, uint8_t *b, size_t len) {
    if (!a || !b) return;
    uint32_t u = (uint32_t)cond;
    uint32_t nz = (u | (0U - u)) >> 31;
    uint8_t mask = (uint8_t)(0U - nz);
    for (size_t i = 0U; i < len; i++) {
        uint8_t diff = (uint8_t)((a[i] ^ b[i]) & mask);
        a[i] ^= diff;
        b[i] ^= diff;
    }
}

/* Compiler-barrier explicit memory zeroization */
OPENQPEP_API void openqpep_explicit_bzero(void *ptr, size_t len) {
    if (!ptr || len == 0U) return;
    volatile uint8_t *vptr = (volatile uint8_t *)ptr;
    for (size_t i = 0U; i < len; i++) {
        vptr[i] = 0U;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

/* Constant-time volatile check that a buffer is completely zeroed: returns 1 if all bytes == 0, 0 otherwise */
OPENQPEP_API int openqpep_is_zeroed(const uint8_t *ptr, size_t len) {
    if (!ptr) return (len == 0U) ? 1 : 0;
    volatile const uint8_t *vptr = (volatile const uint8_t *)ptr;
    volatile uint8_t acc = 0U;
    for (size_t i = 0U; i < len; i++) {
        acc = (uint8_t)(acc | vptr[i]);
    }
    uint32_t x = (uint32_t)acc;
    return (int)(1U ^ ((x | (0U - x)) >> 31));
}
