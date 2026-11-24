/*
 * OpenQPEP Official Release 1.2.1 (v1.2.1) — Zero-Dependency Constant-Time C99 Keccak-f[1600]
 * Implements NIST FIPS 202 SHA3-512 (qSponge-512), SHA3-256, SHAKE-256 (qSponge-XOF),
 * and SHAKE-128 with fully unrolled 2-round-per-iteration Keccak-f[1600] permutation,
 * endian-independent little-endian lane marshaling, incremental absorb/squeeze streaming,
 * and compiler-barrier state zeroization (`openqpep_keccak_wipe`).
 *
 * Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
 */
#include "openqpep.h"
#include <string.h>

#define KECCAK_STATE_BYTES 200U

#define ROTL64(x, s) (((uint64_t)(x) << (s)) | ((uint64_t)(x) >> (64U - (s))))

static const uint64_t KECCAKF_ROUND_CONSTANTS[24] = {
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

static inline uint64_t load64_le(const uint8_t *p) {
    return ((uint64_t)p[0])       |
           ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
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

static inline void xor_byte_into_state(uint64_t state[25], uint32_t byte_pos, uint8_t val) {
    uint32_t lane = byte_pos >> 3;
    uint32_t shift = (byte_pos & 7U) << 3;
    state[lane] ^= ((uint64_t)val << shift);
}

static inline uint8_t read_byte_from_state(const uint64_t state[25], uint32_t byte_pos) {
    uint32_t lane = byte_pos >> 3;
    uint32_t shift = (byte_pos & 7U) << 3;
    return (uint8_t)((state[lane] >> shift) & 0xFFU);
}

/*
 * Constant-time, fully register-unrolled 24-round Keccak-f[1600] permutation
 * (2 rounds per loop iteration, 12 iterations total, zero secret-dependent branches).
 */
OPENQPEP_API void openqpep_keccak_f1600(uint64_t state[25]) {
    if (!state) return;

    uint64_t Aba = state[ 0], Abe = state[ 1], Abi = state[ 2], Abo = state[ 3], Abu = state[ 4];
    uint64_t Aga = state[ 5], Age = state[ 6], Agi = state[ 7], Ago = state[ 8], Agu = state[ 9];
    uint64_t Aka = state[10], Ake = state[11], Aki = state[12], Ako = state[13], Aku = state[14];
    uint64_t Ama = state[15], Ame = state[16], Ami = state[17], Amo = state[18], Amu = state[19];
    uint64_t Asa = state[20], Ase = state[21], Asi = state[22], Aso = state[23], Asu = state[24];

    for (int round = 0; round < 24; round += 2) {
        uint64_t BCa, BCe, BCi, BCo, BCu;
        uint64_t Da, De, Di, Do, Du;
        uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        uint64_t Ega, Ege, Egi, Ego, Egu;
        uint64_t Eka, Eke, Eki, Eko, Eku;
        uint64_t Ema, Eme, Emi, Emo, Emu;
        uint64_t Esa, Ese, Esi, Eso, Esu;

        /* Round (round + 0): A -> E */
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        Da = BCu ^ ROTL64(BCe, 1);
        De = BCa ^ ROTL64(BCi, 1);
        Di = BCe ^ ROTL64(BCo, 1);
        Do = BCi ^ ROTL64(BCu, 1);
        Du = BCo ^ ROTL64(BCa, 1);

        Aba ^= Da; BCa = Aba;
        Age ^= De; BCe = ROTL64(Age, 44);
        Aki ^= Di; BCi = ROTL64(Aki, 43);
        Amo ^= Do; BCo = ROTL64(Amo, 21);
        Asu ^= Du; BCu = ROTL64(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= KECCAKF_ROUND_CONSTANTS[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do; BCa = ROTL64(Abo, 28);
        Agu ^= Du; BCe = ROTL64(Agu, 20);
        Aka ^= Da; BCi = ROTL64(Aka,  3);
        Ame ^= De; BCo = ROTL64(Ame, 45);
        Asi ^= Di; BCu = ROTL64(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De; BCa = ROTL64(Abe,  1);
        Agi ^= Di; BCe = ROTL64(Agi,  6);
        Ako ^= Do; BCi = ROTL64(Ako, 25);
        Amu ^= Du; BCo = ROTL64(Amu,  8);
        Asa ^= Da; BCu = ROTL64(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du; BCa = ROTL64(Abu, 27);
        Aga ^= Da; BCe = ROTL64(Aga, 36);
        Ake ^= De; BCi = ROTL64(Ake, 10);
        Ami ^= Di; BCo = ROTL64(Ami, 15);
        Aso ^= Do; BCu = ROTL64(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di; BCa = ROTL64(Abi, 62);
        Ago ^= Do; BCe = ROTL64(Ago, 55);
        Aku ^= Du; BCi = ROTL64(Aku, 39);
        Ama ^= Da; BCo = ROTL64(Ama, 41);
        Ase ^= De; BCu = ROTL64(Ase,  2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        /* Round (round + 1): E -> A */
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        Da = BCu ^ ROTL64(BCe, 1);
        De = BCa ^ ROTL64(BCi, 1);
        Di = BCe ^ ROTL64(BCo, 1);
        Do = BCi ^ ROTL64(BCu, 1);
        Du = BCo ^ ROTL64(BCa, 1);

        Eba ^= Da; BCa = Eba;
        Ege ^= De; BCe = ROTL64(Ege, 44);
        Eki ^= Di; BCi = ROTL64(Eki, 43);
        Emo ^= Do; BCo = ROTL64(Emo, 21);
        Esu ^= Du; BCu = ROTL64(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= KECCAKF_ROUND_CONSTANTS[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do; BCa = ROTL64(Ebo, 28);
        Egu ^= Du; BCe = ROTL64(Egu, 20);
        Eka ^= Da; BCi = ROTL64(Eka,  3);
        Eme ^= De; BCo = ROTL64(Eme, 45);
        Esi ^= Di; BCu = ROTL64(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De; BCa = ROTL64(Ebe,  1);
        Egi ^= Di; BCe = ROTL64(Egi,  6);
        Eko ^= Do; BCi = ROTL64(Eko, 25);
        Emu ^= Du; BCo = ROTL64(Emu,  8);
        Esa ^= Da; BCu = ROTL64(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du; BCa = ROTL64(Ebu, 27);
        Ega ^= Da; BCe = ROTL64(Ega, 36);
        Eke ^= De; BCi = ROTL64(Eke, 10);
        Emi ^= Di; BCo = ROTL64(Emi, 15);
        Eso ^= Do; BCu = ROTL64(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di; BCa = ROTL64(Ebi, 62);
        Ego ^= Do; BCe = ROTL64(Ego, 55);
        Eku ^= Du; BCi = ROTL64(Eku, 39);
        Ema ^= Da; BCo = ROTL64(Ema, 41);
        Ese ^= De; BCu = ROTL64(Ese,  2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    state[ 0] = Aba; state[ 1] = Abe; state[ 2] = Abi; state[ 3] = Abo; state[ 4] = Abu;
    state[ 5] = Aga; state[ 6] = Age; state[ 7] = Agi; state[ 8] = Ago; state[ 9] = Agu;
    state[10] = Aka; state[11] = Ake; state[12] = Aki; state[13] = Ako; state[14] = Aku;
    state[15] = Ama; state[16] = Ame; state[17] = Ami; state[18] = Amo; state[19] = Amu;
    state[20] = Asa; state[21] = Ase; state[22] = Asi; state[23] = Aso; state[24] = Asu;
}

static int validate_keccak_rate(uint32_t rate) {
    return (rate > 0U && rate < KECCAK_STATE_BYTES && (rate & 7U) == 0U);
}

OPENQPEP_API int openqpep_keccak_init(openqpep_keccak_ctx_t *ctx, uint32_t rate, uint8_t domain_sep) {
    if (!ctx) return OPENQPEP_ERR_NULL_PTR;
    if (!validate_keccak_rate(rate)) return OPENQPEP_ERR_INVALID_LEN;
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = rate;
    ctx->pos = 0U;
    ctx->domain_sep = domain_sep;
    ctx->squeezing = 0U;
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_sha3_512_init(openqpep_keccak_ctx_t *ctx) {
    return openqpep_keccak_init(ctx, OPENQPEP_SHA3_512_RATE, OPENQPEP_SHA3_DOMAIN_SEP);
}

OPENQPEP_API int openqpep_sha3_256_init(openqpep_keccak_ctx_t *ctx) {
    return openqpep_keccak_init(ctx, OPENQPEP_SHA3_256_RATE, OPENQPEP_SHA3_DOMAIN_SEP);
}

OPENQPEP_API int openqpep_shake256_init(openqpep_keccak_ctx_t *ctx) {
    return openqpep_keccak_init(ctx, OPENQPEP_SHAKE256_RATE, OPENQPEP_SHAKE_DOMAIN_SEP);
}

OPENQPEP_API int openqpep_shake128_init(openqpep_keccak_ctx_t *ctx) {
    return openqpep_keccak_init(ctx, OPENQPEP_SHAKE128_RATE, OPENQPEP_SHAKE_DOMAIN_SEP);
}

OPENQPEP_API int openqpep_keccak_absorb(openqpep_keccak_ctx_t *ctx, const uint8_t *in, size_t in_len) {
    if (!ctx) return OPENQPEP_ERR_NULL_PTR;
    if (!validate_keccak_rate(ctx->rate) || ctx->pos >= ctx->rate || ctx->squeezing != 0U) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    if (in_len == 0U) return OPENQPEP_OK;
    if (!in) return OPENQPEP_ERR_NULL_PTR;

    uint32_t rate = ctx->rate;
    uint32_t pos = ctx->pos;

    /* Absorb unaligned head until pos == 0 or input exhausted */
    if (pos != 0U) {
        while (in_len > 0U && pos < rate) {
            xor_byte_into_state(ctx->state, pos, *in++);
            pos++;
            in_len--;
        }
        if (pos == rate) {
            openqpep_keccak_f1600(ctx->state);
            pos = 0U;
        }
    }

    /* Fast full-rate lane-wise absorb loop */
    uint32_t rate_lanes = rate >> 3;
    while (in_len >= (size_t)rate) {
        for (uint32_t i = 0U; i < rate_lanes; i++) {
            ctx->state[i] ^= load64_le(in + ((size_t)i << 3));
        }
        openqpep_keccak_f1600(ctx->state);
        in += rate;
        in_len -= rate;
    }

    /* Absorb trailing partial block */
    while (in_len >= 8U) {
        ctx->state[pos >> 3] ^= load64_le(in);
        pos += 8U;
        in += 8U;
        in_len -= 8U;
    }
    while (in_len > 0U) {
        xor_byte_into_state(ctx->state, pos, *in++);
        pos++;
        in_len--;
    }

    ctx->pos = pos;
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_keccak_finalize(openqpep_keccak_ctx_t *ctx) {
    if (!ctx) return OPENQPEP_ERR_NULL_PTR;
    if (!validate_keccak_rate(ctx->rate) || ctx->pos >= ctx->rate) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    if (ctx->squeezing != 0U) {
        return OPENQPEP_OK;
    }

    /* NIST FIPS 202 pad10*1 domain-separated padding */
    xor_byte_into_state(ctx->state, ctx->pos, ctx->domain_sep);
    xor_byte_into_state(ctx->state, ctx->rate - 1U, 0x80U);
    openqpep_keccak_f1600(ctx->state);

    ctx->pos = 0U;
    ctx->squeezing = 1U;
    return OPENQPEP_OK;
}

OPENQPEP_API int openqpep_keccak_squeeze(openqpep_keccak_ctx_t *ctx, uint8_t *out, size_t out_len) {
    if (!ctx) return OPENQPEP_ERR_NULL_PTR;
    if (!validate_keccak_rate(ctx->rate)) return OPENQPEP_ERR_INVALID_LEN;
    if (out_len > 0U && !out) return OPENQPEP_ERR_NULL_PTR;

    if (ctx->squeezing == 0U) {
        int rc = openqpep_keccak_finalize(ctx);
        if (rc != OPENQPEP_OK) return rc;
    }
    if (out_len == 0U) return OPENQPEP_OK;

    uint32_t rate = ctx->rate;
    uint32_t pos = ctx->pos;

    /* Drain remaining bytes from current squeezed block */
    if (pos != 0U) {
        while (out_len > 0U && pos < rate) {
            *out++ = read_byte_from_state(ctx->state, pos);
            pos++;
            out_len--;
        }
        if (pos == rate) {
            openqpep_keccak_f1600(ctx->state);
            pos = 0U;
        }
    }

    /* Fast full-rate lane-wise squeeze loop */
    uint32_t rate_lanes = rate >> 3;
    while (out_len >= (size_t)rate) {
        for (uint32_t i = 0U; i < rate_lanes; i++) {
            store64_le(out + ((size_t)i << 3), ctx->state[i]);
        }
        openqpep_keccak_f1600(ctx->state);
        out += rate;
        out_len -= rate;
    }

    /* Squeeze trailing partial block */
    while (out_len >= 8U) {
        store64_le(out, ctx->state[pos >> 3]);
        pos += 8U;
        out += 8U;
        out_len -= 8U;
    }
    while (out_len > 0U) {
        *out++ = read_byte_from_state(ctx->state, pos);
        pos++;
        out_len--;
    }

    ctx->pos = pos;
    return OPENQPEP_OK;
}

OPENQPEP_API void openqpep_keccak_wipe(openqpep_keccak_ctx_t *ctx) {
    if (!ctx) return;
    openqpep_explicit_bzero(ctx, sizeof(*ctx));
}

static int keccak_oneshot(
    uint32_t rate,
    uint8_t domain_sep,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len
) {
    if (in_len > 0U && !in) return OPENQPEP_ERR_NULL_PTR;
    if (out_len > 0U && !out) return OPENQPEP_ERR_NULL_PTR;

    openqpep_keccak_ctx_t ctx;
    int rc = openqpep_keccak_init(&ctx, rate, domain_sep);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, in, in_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_finalize(&ctx);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, out, out_len);
    openqpep_keccak_wipe(&ctx);
    return rc;
}

OPENQPEP_API int openqpep_qsponge_512(const uint8_t *in, size_t in_len, uint8_t out64[64]) {
    if (!out64) return OPENQPEP_ERR_NULL_PTR;
    return keccak_oneshot(OPENQPEP_SHA3_512_RATE, OPENQPEP_SHA3_DOMAIN_SEP, in, in_len, out64, OPENQPEP_QSPONGE_512_BYTES);
}

OPENQPEP_API int openqpep_sha3_256(const uint8_t *in, size_t in_len, uint8_t out32[32]) {
    if (!out32) return OPENQPEP_ERR_NULL_PTR;
    return keccak_oneshot(OPENQPEP_SHA3_256_RATE, OPENQPEP_SHA3_DOMAIN_SEP, in, in_len, out32, OPENQPEP_SHA3_256_BYTES);
}

OPENQPEP_API int openqpep_qsponge_var(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    return keccak_oneshot(OPENQPEP_SHAKE256_RATE, OPENQPEP_SHAKE_DOMAIN_SEP, in, in_len, out, out_len);
}

OPENQPEP_API int openqpep_shake128(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    return keccak_oneshot(OPENQPEP_SHAKE128_RATE, OPENQPEP_SHAKE_DOMAIN_SEP, in, in_len, out, out_len);
}
