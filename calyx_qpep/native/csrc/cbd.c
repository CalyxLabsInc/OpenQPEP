/*
 * OpenQPEP Native C99 Centered Binomial Distribution (CBD_1 / CBD_2) Samplers and ABI Probe.
 * Official Release 1.2.4 — Calyx Labs Inc. (CPOSLS-1.0)
 */
#include "openqpep.h"

#define QLX_Q OPENQPEP_QLX_Q
#define QVS_Q OPENQPEP_QVS_Q

OPENQPEP_API uint32_t openqpep_abi_version(void) {
    return OPENQPEP_ABI_VERSION;
}

OPENQPEP_API const char *openqpep_version_string(void) {
    return OPENQPEP_VERSION_STRING;
}

OPENQPEP_API uint32_t openqpep_native_abi_info(void) {
    uint32_t flags = OPENQPEP_ABI_FLAG_C99;
#if defined(__AVX2__)
    flags |= OPENQPEP_ABI_FLAG_AVX2;
#endif
#if defined(__ARM_NEON) || defined(__aarch64__)
    flags |= OPENQPEP_ABI_FLAG_NEON;
#endif
    return flags;
}

static inline int32_t ct_caddq_cbd(int32_t a, int32_t q) {
    return a + ((a >> 31) & q);
}

OPENQPEP_API void openqpep_cbd2_3329(const uint8_t *buf, int32_t *out) {
    if (!buf || !out) return;
    for (int i = 0; i < 128; i++) {
        uint8_t b = buf[i];
        int32_t a0 = (b & 1) + ((b >> 1) & 1);
        int32_t b0 = ((b >> 2) & 1) + ((b >> 3) & 1);
        int32_t a1 = ((b >> 4) & 1) + ((b >> 5) & 1);
        int32_t b1 = ((b >> 6) & 1) + ((b >> 7) & 1);
        int32_t d0 = a0 - b0;
        int32_t d1 = a1 - b1;
        out[2 * i] = ct_caddq_cbd(d0, QLX_Q);
        out[2 * i + 1] = ct_caddq_cbd(d1, QLX_Q);
    }
}

OPENQPEP_API void openqpep_cbd1_3329(const uint8_t *buf, int32_t *out) {
    if (!buf || !out) return;
    for (int i = 0; i < 64; i++) {
        uint8_t b = buf[i];
        for (int j = 0; j < 4; j++) {
            int32_t a = (b >> (2 * j)) & 1;
            int32_t c = (b >> (2 * j + 1)) & 1;
            int32_t d = a - c;
            out[4 * i + j] = ct_caddq_cbd(d, QLX_Q);
        }
    }
}

OPENQPEP_API void openqpep_cbd2_qvs(const uint8_t *buf, int32_t *out) {
    if (!buf || !out) return;
    for (int i = 0; i < 128; i++) {
        uint8_t b = buf[i];
        int32_t a0 = (b & 1) + ((b >> 1) & 1);
        int32_t b0 = ((b >> 2) & 1) + ((b >> 3) & 1);
        int32_t a1 = ((b >> 4) & 1) + ((b >> 5) & 1);
        int32_t b1 = ((b >> 6) & 1) + ((b >> 7) & 1);
        int32_t d0 = a0 - b0;
        int32_t d1 = a1 - b1;
        out[2 * i] = ct_caddq_cbd(d0, QVS_Q);
        out[2 * i + 1] = ct_caddq_cbd(d1, QVS_Q);
    }
}
