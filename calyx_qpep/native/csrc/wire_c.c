/*
 * OpenQPEP Official Release 1.2.9 (v1.2.9) — Native C99 Zero-Heap Wire Format v5/v5.1 Framing,
 * Constant-Time Magic Validator, Compact TLV v5.1 Validator & CC-512 CMT-4/SIV Streaming Engine.
 *
 * Security & Performance Guarantees:
 *   - 100% Zero Heap Allocations (stack-only streaming over openqpep_keccak_ctx_t).
 *   - Branchless constant-time Wire v5 (\x89QPE\x05\x00) / v5.1 (\x89QPE\x05\x01) magic & legacy
 *     classification (strictly rejecting -rc, -pc, and -beta frames).
 *   - Overflow-safe constant-time bounds verification (openqpep_ct_mem_bounds_ok).
 *   - Authenticate-then-unwhiten Wire v5/v5.1 unpack (constant-time MAC checked via openqpep_ct_eq
 *     BEFORE unwhitening or writing to output buffer).
 *   - Streaming zero-copy CC-512 CMT-4 key derivation/tagging and CC-512-SIV synthetic IV synthesis
 *     with deterministic compiler-barrier scrubbing (openqpep_explicit_bzero / openqpep_keccak_wipe).
 *
 * Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
 */
#include "openqpep.h"
#include <string.h>

/* Immutable cryptographic domain-separation tags (NEVER modify across v1.x releases) */
static const uint8_t DOMAIN_WIRE_WHITEN_V5[]   = "CALYX-WIRE-WHITEN-v5-1.0.0|";
static const uint8_t DOMAIN_WIRE_MAC_V5[]      = "CALYX-WIRE-MAC-v5-1.0.0|";
static const uint8_t DOMAIN_WIRE_WHITEN_V51[]  = "CALYX-WIRE-WHITEN-v51-1.0.0|";
static const uint8_t DOMAIN_WIRE_MAC_V51[]     = "CALYX-WIRE-MAC-v51-1.0.0|";

static const uint8_t DOMAIN_CC512_CMT4_KEYS[]  = "CALYX-CC512-CMT4-KEYS-v1.0.0|";
static const uint8_t DOMAIN_CC512_CMT4_TAG[]   = "CALYX-CC512-CMT4-TAG-v1.0.0|";
static const uint8_t DOMAIN_CC512_SIV_MASTER[] = "CALYX-CC512-SIV-MASTER-v1.1.3|";
static const uint8_t DOMAIN_CC512_SIV_SYNTH[]  = "CALYX-CC512-SIV-SYNTH-v1.1.3|";
static const uint8_t DOMAIN_CC512_SIV_MSGKEY[] = "CALYX-CC512-SIV-MSGKEY-v1.1.3|";

static uint32_t ct_eq_u8(uint8_t a, uint8_t b) {
    uint32_t d = (uint32_t)(a ^ b);
    return 1U ^ ((d | (0U - d)) >> 31);
}

static void store_be64(uint8_t out[8], uint64_t val) {
    out[0] = (uint8_t)((val >> 56) & 0xFFU);
    out[1] = (uint8_t)((val >> 48) & 0xFFU);
    out[2] = (uint8_t)((val >> 40) & 0xFFU);
    out[3] = (uint8_t)((val >> 32) & 0xFFU);
    out[4] = (uint8_t)((val >> 24) & 0xFFU);
    out[5] = (uint8_t)((val >> 16) & 0xFFU);
    out[6] = (uint8_t)((val >> 8) & 0xFFU);
    out[7] = (uint8_t)(val & 0xFFU);
}

/* Branchless printable-ASCII label check: 1..128 bytes, every byte in [0x20, 0x7E] */
static int validate_label_ascii(const uint8_t *label, size_t label_len) {
    if (!label) return OPENQPEP_ERR_NULL_PTR;
    if (label_len == 0U || label_len > (size_t)OPENQPEP_WIRE_MAX_LABEL_BYTES) {
        return OPENQPEP_ERR_WIRE_FORMAT;
    }
    uint32_t bad = 0U;
    for (size_t i = 0U; i < label_len; i++) {
        uint32_t c = (uint32_t)label[i];
        uint32_t shifted = c - 0x20U;
        uint32_t lt_lo = shifted >> 31;           /* 1 iff c < 0x20 */
        uint32_t gt_hi = (0x5EU - shifted) >> 31; /* 1 iff c > 0x7E (for c >= 0x20) */
        bad |= lt_lo | gt_hi;
    }
    return bad ? OPENQPEP_ERR_WIRE_FORMAT : OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* Branchless Constant-Time Wire Format v5 / v5.1 Magic Validator            */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_verify_wire_v5_magic(const uint8_t *hdr, size_t len) {
    if (!hdr || !openqpep_ct_mem_bounds_ok(0U, (size_t)OPENQPEP_WIRE_V5_MAGIC_LEN, len)) {
        return OPENQPEP_WIRE_ERR_INVALID;
    }
    uint32_t pfx = ct_eq_u8(hdr[0], 0x89U)
                 & ct_eq_u8(hdr[1], 0x51U)
                 & ct_eq_u8(hdr[2], 0x50U)
                 & ct_eq_u8(hdr[3], 0x45U);
    uint8_t v_maj = hdr[4];
    uint8_t v_min = hdr[5];

    uint32_t is_v5_full  = pfx & ct_eq_u8(v_maj, 0x05U) & ct_eq_u8(v_min, 0x00U);
    uint32_t is_v51_comp = pfx & ct_eq_u8(v_maj, 0x05U) & ct_eq_u8(v_min, 0x01U);
    uint32_t is_rc       = pfx & ct_eq_u8(v_maj, 0x04U) & (ct_eq_u8(v_min, 0x00U) | ct_eq_u8(v_min, 0x01U));
    uint32_t is_pc       = pfx & ct_eq_u8(v_maj, 0x03U) & (ct_eq_u8(v_min, 0x00U) | ct_eq_u8(v_min, 0x01U));
    uint32_t is_beta     = pfx & (
        (ct_eq_u8(v_maj, 0x01U) & (ct_eq_u8(v_min, 0x01U) | ct_eq_u8(v_min, 0x09U))) |
        (ct_eq_u8(v_maj, 0x02U) & ct_eq_u8(v_min, 0x00U))
    );

    /* Bias by +64 so every intermediate selection stays non-negative in uint32_t */
    uint32_t res = (uint32_t)(OPENQPEP_WIRE_ERR_INVALID + 64);
    res = openqpep_ct_select_u32(is_beta,     (uint32_t)(OPENQPEP_WIRE_ERR_LEGACY_BETA + 64), res);
    res = openqpep_ct_select_u32(is_pc,       (uint32_t)(OPENQPEP_WIRE_ERR_LEGACY_PC + 64),   res);
    res = openqpep_ct_select_u32(is_rc,       (uint32_t)(OPENQPEP_WIRE_ERR_LEGACY_RC + 64),   res);
    res = openqpep_ct_select_u32(is_v51_comp, (uint32_t)(OPENQPEP_WIRE_V5_1_COMPACT + 64),    res);
    res = openqpep_ct_select_u32(is_v5_full,  (uint32_t)(OPENQPEP_WIRE_V5_FULL + 64),         res);
    return (int)res - 64;
}

/* ------------------------------------------------------------------------- */
/* Zero-Heap Wire Format v5 / v5.1 Streaming Whitening, MAC & Pack/Unpack    */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_wire_whiten_xor(
    const uint8_t hdr8[8],
    const uint8_t nonce16[16],
    const uint8_t *label,
    size_t label_len,
    int is_v51,
    const uint8_t *in,
    uint8_t *out,
    size_t body_len
) {
    if (!hdr8 || !nonce16) return OPENQPEP_ERR_NULL_PTR;
    if (body_len > 0U && (!in || !out)) return OPENQPEP_ERR_NULL_PTR;
    int lrc = validate_label_ascii(label, label_len);
    if (lrc != OPENQPEP_OK) return lrc;
    if (!openqpep_ct_mem_bounds_ok((size_t)OPENQPEP_WIRE_V5_OVERHEAD, body_len, (size_t)OPENQPEP_WIRE_MAX_FRAME_BYTES)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    if (body_len == 0U) return OPENQPEP_OK;

    openqpep_keccak_ctx_t ctx;
    uint8_t ks[OPENQPEP_SHAKE256_RATE];
    int rc = openqpep_shake256_init(&ctx);
    if (rc != OPENQPEP_OK) return rc;

    const uint8_t *dom = is_v51 ? DOMAIN_WIRE_WHITEN_V51 : DOMAIN_WIRE_WHITEN_V5;
    size_t dom_len = is_v51 ? (sizeof(DOMAIN_WIRE_WHITEN_V51) - 1U) : (sizeof(DOMAIN_WIRE_WHITEN_V5) - 1U);

    rc = openqpep_keccak_absorb(&ctx, dom, dom_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, hdr8, (size_t)OPENQPEP_WIRE_V5_HDR_LEN);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, nonce16, (size_t)OPENQPEP_WIRE_V5_NONCE_LEN);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, label, label_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_finalize(&ctx);

    size_t off = 0U;
    while (rc == OPENQPEP_OK && off < body_len) {
        size_t rem = body_len - off;
        size_t chunk = (rem < sizeof(ks)) ? rem : sizeof(ks);
        rc = openqpep_keccak_squeeze(&ctx, ks, chunk);
        if (rc != OPENQPEP_OK) break;
        const uint8_t *src = in + off;
        uint8_t *dst = out + off;
        for (size_t i = 0U; i < chunk; i++) {
            dst[i] = (uint8_t)(src[i] ^ ks[i]);
        }
        off += chunk;
    }

    openqpep_explicit_bzero(ks, sizeof(ks));
    openqpep_keccak_wipe(&ctx);
    return rc;
}

OPENQPEP_API int openqpep_wire_compute_mac(
    const uint8_t hdr8[8],
    const uint8_t nonce16[16],
    const uint8_t *label,
    size_t label_len,
    int is_v51,
    const uint8_t *whitened,
    size_t whitened_len,
    uint8_t mac32_out[32]
) {
    if (!hdr8 || !nonce16 || !mac32_out) return OPENQPEP_ERR_NULL_PTR;
    if (whitened_len > 0U && !whitened) return OPENQPEP_ERR_NULL_PTR;
    int lrc = validate_label_ascii(label, label_len);
    if (lrc != OPENQPEP_OK) return lrc;
    if (!openqpep_ct_mem_bounds_ok((size_t)OPENQPEP_WIRE_V5_OVERHEAD, whitened_len, (size_t)OPENQPEP_WIRE_MAX_FRAME_BYTES)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    openqpep_keccak_ctx_t ctx;
    uint8_t digest[OPENQPEP_QSPONGE_512_BYTES];
    int rc = openqpep_sha3_512_init(&ctx);
    if (rc != OPENQPEP_OK) return rc;

    const uint8_t *dom = is_v51 ? DOMAIN_WIRE_MAC_V51 : DOMAIN_WIRE_MAC_V5;
    size_t dom_len = is_v51 ? (sizeof(DOMAIN_WIRE_MAC_V51) - 1U) : (sizeof(DOMAIN_WIRE_MAC_V5) - 1U);

    rc = openqpep_keccak_absorb(&ctx, dom, dom_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, hdr8, (size_t)OPENQPEP_WIRE_V5_HDR_LEN);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, nonce16, (size_t)OPENQPEP_WIRE_V5_NONCE_LEN);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, label, label_len);
    if (rc == OPENQPEP_OK && whitened_len > 0U) {
        rc = openqpep_keccak_absorb(&ctx, whitened, whitened_len);
    }
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, digest, sizeof(digest));
    if (rc == OPENQPEP_OK) {
        memcpy(mac32_out, digest, (size_t)OPENQPEP_WIRE_V5_MAC_LEN);
    }

    openqpep_explicit_bzero(digest, sizeof(digest));
    openqpep_keccak_wipe(&ctx);
    return rc;
}

OPENQPEP_API int openqpep_wire_v5_pack(
    const uint8_t *body,
    size_t body_len,
    const uint8_t *label,
    size_t label_len,
    uint8_t packet_type,
    uint8_t flags,
    const uint8_t nonce16[16],
    int is_v51,
    uint8_t *frame_out,
    size_t frame_out_len
) {
    if (!nonce16 || !frame_out) return OPENQPEP_ERR_NULL_PTR;
    if (body_len > 0U && !body) return OPENQPEP_ERR_NULL_PTR;
    int lrc = validate_label_ascii(label, label_len);
    if (lrc != OPENQPEP_OK) return lrc;

    if (is_v51) {
        if (flags != 0U) return OPENQPEP_ERR_WIRE_FORMAT;
    } else {
        if ((flags & (uint8_t)(~OPENQPEP_WIRE_FLAG_BUCKET_PADDED)) != 0U) {
            return OPENQPEP_ERR_WIRE_FORMAT;
        }
    }

    if (!openqpep_ct_mem_bounds_ok((size_t)OPENQPEP_WIRE_V5_OVERHEAD, body_len, (size_t)OPENQPEP_WIRE_MAX_FRAME_BYTES)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    size_t total_len = body_len + (size_t)OPENQPEP_WIRE_V5_OVERHEAD;
    if (!openqpep_ct_mem_bounds_ok(0U, total_len, frame_out_len)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    frame_out[0] = 0x89U;
    frame_out[1] = 0x51U;
    frame_out[2] = 0x50U;
    frame_out[3] = 0x45U;
    frame_out[4] = 0x05U;
    frame_out[5] = is_v51 ? 0x01U : 0x00U;
    frame_out[6] = packet_type;
    frame_out[7] = flags;
    memcpy(frame_out + 8, nonce16, (size_t)OPENQPEP_WIRE_V5_NONCE_LEN);

    int rc = openqpep_wire_whiten_xor(
        frame_out,
        frame_out + 8,
        label,
        label_len,
        is_v51,
        body,
        frame_out + 24,
        body_len
    );
    if (rc != OPENQPEP_OK) return rc;

    return openqpep_wire_compute_mac(
        frame_out,
        frame_out + 8,
        label,
        label_len,
        is_v51,
        frame_out + 24,
        body_len,
        frame_out + 24 + body_len
    );
}

OPENQPEP_API int openqpep_wire_v5_unpack(
    const uint8_t *frame,
    size_t frame_len,
    const uint8_t *label,
    size_t label_len,
    int expect_v51,
    uint8_t *body_out,
    size_t body_out_cap,
    size_t *body_len_out,
    uint8_t *packet_type_out,
    uint8_t *flags_out
) {
    if (!frame || !body_len_out) return OPENQPEP_ERR_NULL_PTR;
    int lrc = validate_label_ascii(label, label_len);
    if (lrc != OPENQPEP_OK) return lrc;

    if (!openqpep_ct_mem_bounds_ok(0U, frame_len, (size_t)OPENQPEP_WIRE_MAX_FRAME_BYTES)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    if (!openqpep_ct_mem_bounds_ok((size_t)OPENQPEP_WIRE_V5_MAGIC_LEN, 0U, frame_len)) {
        return OPENQPEP_ERR_WIRE_FORMAT;
    }

    int magic_rc = openqpep_verify_wire_v5_magic(frame, frame_len);
    if (magic_rc == OPENQPEP_WIRE_ERR_LEGACY_RC ||
        magic_rc == OPENQPEP_WIRE_ERR_LEGACY_PC ||
        magic_rc == OPENQPEP_WIRE_ERR_LEGACY_BETA) {
        return OPENQPEP_ERR_LEGACY;
    }
    int expected_magic = expect_v51 ? OPENQPEP_WIRE_V5_1_COMPACT : OPENQPEP_WIRE_V5_FULL;
    if (magic_rc != expected_magic) {
        return OPENQPEP_ERR_WIRE_FORMAT;
    }
    if (!openqpep_ct_mem_bounds_ok((size_t)OPENQPEP_WIRE_V5_OVERHEAD, 0U, frame_len)) {
        return OPENQPEP_ERR_WIRE_FORMAT;
    }

    uint8_t ptype = frame[6];
    uint8_t flags = frame[7];
    if (expect_v51) {
        if (flags != 0U) return OPENQPEP_ERR_WIRE_FORMAT;
    } else {
        if ((flags & (uint8_t)(~OPENQPEP_WIRE_FLAG_BUCKET_PADDED)) != 0U) {
            return OPENQPEP_ERR_WIRE_FORMAT;
        }
    }

    size_t body_len = frame_len - (size_t)OPENQPEP_WIRE_V5_OVERHEAD;
    if (body_len > 0U && !body_out) return OPENQPEP_ERR_NULL_PTR;
    if (!openqpep_ct_mem_bounds_ok(0U, body_len, body_out_cap)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    uint8_t expected_mac[OPENQPEP_WIRE_V5_MAC_LEN];
    int rc = openqpep_wire_compute_mac(
        frame,
        frame + 8,
        label,
        label_len,
        expect_v51,
        frame + 24,
        body_len,
        expected_mac
    );
    if (rc != OPENQPEP_OK) {
        openqpep_explicit_bzero(expected_mac, sizeof(expected_mac));
        return rc;
    }

    int mac_ok = openqpep_ct_eq(frame + 24 + body_len, expected_mac, sizeof(expected_mac));
    openqpep_explicit_bzero(expected_mac, sizeof(expected_mac));
    if (!mac_ok) {
        return OPENQPEP_ERR_AUTH_FAIL;
    }

    rc = openqpep_wire_whiten_xor(
        frame,
        frame + 8,
        label,
        label_len,
        expect_v51,
        frame + 24,
        body_out,
        body_len
    );
    if (rc != OPENQPEP_OK) return rc;

    *body_len_out = body_len;
    if (packet_type_out) *packet_type_out = ptype;
    if (flags_out) *flags_out = flags;
    return OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* Zero-Heap Compact Binary TLV v5.1 Structural Validator                    */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_wire_validate_tlv(
    const uint8_t *raw,
    size_t raw_len,
    int require_canonical_order,
    uint32_t max_fields,
    uint32_t *field_count_out
) {
    if (raw_len > 0U && !raw) return OPENQPEP_ERR_NULL_PTR;
    if (max_fields == 0U || max_fields > OPENQPEP_WIRE_MAX_TLV_FIELDS) {
        return OPENQPEP_ERR_INVALID_LEN;
    }
    size_t max_payload = (size_t)OPENQPEP_WIRE_MAX_FRAME_BYTES - (size_t)OPENQPEP_WIRE_V5_OVERHEAD;
    if (!openqpep_ct_mem_bounds_ok(0U, raw_len, max_payload)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    uint64_t seen[4] = {0ULL, 0ULL, 0ULL, 0ULL};
    int prev_tag = -1;
    uint32_t count = 0U;
    size_t idx = 0U;

    while (idx < raw_len) {
        if (count >= max_fields) {
            return OPENQPEP_ERR_WIRE_FORMAT;
        }
        if (!openqpep_ct_mem_bounds_ok(idx, 5U, raw_len)) {
            return OPENQPEP_ERR_WIRE_FORMAT;
        }
        uint8_t tag = raw[idx];
        uint64_t bit = 1ULL << (tag & 63U);
        if ((seen[tag >> 6] & bit) != 0ULL) {
            return OPENQPEP_ERR_WIRE_FORMAT;
        }
        if (require_canonical_order && (int)tag <= prev_tag) {
            return OPENQPEP_ERR_WIRE_FORMAT;
        }
        seen[tag >> 6] |= bit;
        prev_tag = (int)tag;

        uint32_t val_len = ((uint32_t)raw[idx + 1U] << 24)
                         | ((uint32_t)raw[idx + 2U] << 16)
                         | ((uint32_t)raw[idx + 3U] << 8)
                         | ((uint32_t)raw[idx + 4U]);
        idx += 5U;
        if (!openqpep_ct_mem_bounds_ok(idx, (size_t)val_len, raw_len)) {
            return OPENQPEP_ERR_WIRE_FORMAT;
        }
        idx += (size_t)val_len;
        count++;
    }

    if (field_count_out) *field_count_out = count;
    return OPENQPEP_OK;
}

/* ------------------------------------------------------------------------- */
/* Zero-Heap CC-512 CMT-4 & CC-512-SIV Streaming Key Derivation & MACs       */
/* ------------------------------------------------------------------------- */

OPENQPEP_API int openqpep_cc512_derive_cmt4_subkeys(
    const uint8_t key64[64],
    const uint8_t nonce24[24],
    uint8_t out96[96]
) {
    if (!key64 || !nonce24 || !out96) return OPENQPEP_ERR_NULL_PTR;
    openqpep_keccak_ctx_t ctx;
    int rc = openqpep_shake256_init(&ctx);
    if (rc != OPENQPEP_OK) return rc;

    rc = openqpep_keccak_absorb(&ctx, DOMAIN_CC512_CMT4_KEYS, sizeof(DOMAIN_CC512_CMT4_KEYS) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, key64, (size_t)OPENQPEP_CC512_KEY_BYTES);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, nonce24, (size_t)OPENQPEP_CC512_NONCE_BYTES);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, out96, 96U);

    openqpep_keccak_wipe(&ctx);
    return rc;
}

OPENQPEP_API int openqpep_cc512_cmt4_tag(
    const uint8_t k_commit32[32],
    const uint8_t nonce24[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ct_outer,
    size_t ct_outer_len,
    uint8_t tag32_out[32]
) {
    if (!k_commit32 || !nonce24 || !tag32_out) return OPENQPEP_ERR_NULL_PTR;
    if (aad_len > 0U && !aad) return OPENQPEP_ERR_NULL_PTR;
    if (ct_outer_len > 0U && !ct_outer) return OPENQPEP_ERR_NULL_PTR;

    openqpep_keccak_ctx_t ctx;
    uint8_t digest[OPENQPEP_QSPONGE_512_BYTES];
    uint8_t len_be[8];
    store_be64(len_be, (uint64_t)aad_len);

    int rc = openqpep_sha3_512_init(&ctx);
    if (rc != OPENQPEP_OK) return rc;

    rc = openqpep_keccak_absorb(&ctx, DOMAIN_CC512_CMT4_TAG, sizeof(DOMAIN_CC512_CMT4_TAG) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, k_commit32, 32U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, nonce24, (size_t)OPENQPEP_CC512_NONCE_BYTES);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, len_be, sizeof(len_be));
    if (rc == OPENQPEP_OK && aad_len > 0U) rc = openqpep_keccak_absorb(&ctx, aad, aad_len);
    if (rc == OPENQPEP_OK && ct_outer_len > 0U) rc = openqpep_keccak_absorb(&ctx, ct_outer, ct_outer_len);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, digest, sizeof(digest));
    if (rc == OPENQPEP_OK) {
        memcpy(tag32_out, digest, (size_t)OPENQPEP_CC512_CMT_TAG_BYTES);
    }

    openqpep_explicit_bzero(digest, sizeof(digest));
    openqpep_keccak_wipe(&ctx);
    return rc;
}

OPENQPEP_API int openqpep_cc512_verify_cmt4_tag(
    const uint8_t k_commit32[32],
    const uint8_t nonce24[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ct_outer,
    size_t ct_outer_len,
    const uint8_t expected_tag32[32]
) {
    if (!expected_tag32) return OPENQPEP_ERR_NULL_PTR;
    uint8_t calc[OPENQPEP_CC512_CMT_TAG_BYTES];
    int rc = openqpep_cc512_cmt4_tag(k_commit32, nonce24, aad, aad_len, ct_outer, ct_outer_len, calc);
    if (rc != OPENQPEP_OK) {
        openqpep_explicit_bzero(calc, sizeof(calc));
        return rc;
    }
    int eq = openqpep_ct_eq(calc, expected_tag32, sizeof(calc));
    openqpep_explicit_bzero(calc, sizeof(calc));
    return eq ? OPENQPEP_OK : OPENQPEP_ERR_AUTH_FAIL;
}

OPENQPEP_API int openqpep_cc512_siv_master_subkeys(
    const uint8_t key64[64],
    uint8_t out128[128]
) {
    if (!key64 || !out128) return OPENQPEP_ERR_NULL_PTR;
    openqpep_keccak_ctx_t ctx;
    int rc = openqpep_shake256_init(&ctx);
    if (rc != OPENQPEP_OK) return rc;

    rc = openqpep_keccak_absorb(&ctx, DOMAIN_CC512_SIV_MASTER, sizeof(DOMAIN_CC512_SIV_MASTER) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, key64, (size_t)OPENQPEP_CC512_KEY_BYTES);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, out128, 128U);

    openqpep_keccak_wipe(&ctx);
    return rc;
}

OPENQPEP_API int openqpep_cc512_siv_synth(
    const uint8_t k_siv_mac64[64],
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t pt_len,
    uint8_t siv32_out[32]
) {
    if (!k_siv_mac64 || !siv32_out) return OPENQPEP_ERR_NULL_PTR;
    if (nonce_len > 0U && !nonce) return OPENQPEP_ERR_NULL_PTR;
    if (aad_len > 0U && !aad) return OPENQPEP_ERR_NULL_PTR;
    if (pt_len > 0U && !plaintext) return OPENQPEP_ERR_NULL_PTR;
    if (!openqpep_ct_mem_bounds_ok(0U, nonce_len, (size_t)OPENQPEP_CC512_SIV_MAX_NONCE)) {
        return OPENQPEP_ERR_INVALID_LEN;
    }

    openqpep_keccak_ctx_t ctx;
    uint8_t digest[OPENQPEP_QSPONGE_512_BYTES];
    uint8_t len_be[8];

    int rc = openqpep_sha3_512_init(&ctx);
    if (rc != OPENQPEP_OK) return rc;

    rc = openqpep_keccak_absorb(&ctx, DOMAIN_CC512_SIV_SYNTH, sizeof(DOMAIN_CC512_SIV_SYNTH) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, k_siv_mac64, 64U);

    if (rc == OPENQPEP_OK) {
        store_be64(len_be, (uint64_t)nonce_len);
        rc = openqpep_keccak_absorb(&ctx, len_be, sizeof(len_be));
    }
    if (rc == OPENQPEP_OK && nonce_len > 0U) rc = openqpep_keccak_absorb(&ctx, nonce, nonce_len);

    if (rc == OPENQPEP_OK) {
        store_be64(len_be, (uint64_t)aad_len);
        rc = openqpep_keccak_absorb(&ctx, len_be, sizeof(len_be));
    }
    if (rc == OPENQPEP_OK && aad_len > 0U) rc = openqpep_keccak_absorb(&ctx, aad, aad_len);

    if (rc == OPENQPEP_OK) {
        store_be64(len_be, (uint64_t)pt_len);
        rc = openqpep_keccak_absorb(&ctx, len_be, sizeof(len_be));
    }
    if (rc == OPENQPEP_OK && pt_len > 0U) rc = openqpep_keccak_absorb(&ctx, plaintext, pt_len);

    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, digest, sizeof(digest));
    if (rc == OPENQPEP_OK) {
        memcpy(siv32_out, digest, (size_t)OPENQPEP_CC512_SIV_BYTES);
    }

    openqpep_explicit_bzero(digest, sizeof(digest));
    openqpep_keccak_wipe(&ctx);
    return rc;
}

OPENQPEP_API int openqpep_cc512_siv_msg_keys(
    const uint8_t k_enc_root64[64],
    const uint8_t siv32[32],
    uint8_t out88[88]
) {
    if (!k_enc_root64 || !siv32 || !out88) return OPENQPEP_ERR_NULL_PTR;
    openqpep_keccak_ctx_t ctx;
    int rc = openqpep_shake256_init(&ctx);
    if (rc != OPENQPEP_OK) return rc;

    rc = openqpep_keccak_absorb(&ctx, DOMAIN_CC512_SIV_MSGKEY, sizeof(DOMAIN_CC512_SIV_MSGKEY) - 1U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, k_enc_root64, 64U);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_absorb(&ctx, siv32, (size_t)OPENQPEP_CC512_SIV_BYTES);
    if (rc == OPENQPEP_OK) rc = openqpep_keccak_squeeze(&ctx, out88, 88U);

    openqpep_keccak_wipe(&ctx);
    return rc;
}
