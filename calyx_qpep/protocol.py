"""
OpenQPEP by Calyx Labs Inc. — Official Release 1.2.6 (v1.2.6)
Canonical Post-Quantum Hybrid Protocol Reference Engine.
Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).

Official Release 1.2.6 Architecture:
  - Wire Format: Strict Official Wire Format v5 (\\x89QPE\\x05\\x00) & Compact TLV v5.1 (\\x89QPE\\x05\\x01).
  - KDF Envelope: Mandatory kdf_version: 4 (RFC 9106 QPKD-Argon2id + qSponge-512, "OpenQPEP/1.0.0").
  - Symmetric AEAD: CMT-4 Key-Committing Calyx-Cascade-512 (AES-256-GCM + ChaCha20-Poly1305 + qSponge-512).
  - Zero Backwards Compatibility: ALL legacy Release Candidate (-rc), Production Candidate (-pc),
    and Beta (-beta) wire frames, streams, and kdf_version < 4 key rings are strictly rejected
    with QPEPLegacyProtocolError.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import unicodedata
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .beyond_lwe_bridge import (
    BEYOND_LWE_SUITES,
    decrypt_beyond_lwe,
    encrypt_beyond_lwe,
    generate_beyond_lwe_material,
    sign_beyond_lwe,
    verify_beyond_lwe,
)
from .constants import (
    ALL_LEGACY_WIRE_MAGICS,
    APP_NAME,
    CALYX_HYPER_TESSERACT_HARDWARE_WARNING,
    CHUNK_SIZE,
    DEFAULT_SUITE,
    LEGACY_BETA_WIRE_MAGICS,
    LEGACY_PC_WIRE_MAGICS,
    LEGACY_RC_WIRE_MAGICS,
    MANDATORY_KDF_VERSION,
    MAX_ARMOR_BYTES,
    MAX_DECOMPRESSED_BYTES,
    MAX_WIRE_FRAME_BYTES,
    PACKET_TYPE_KEYRING,
    PACKET_TYPE_SIGNATURE,
    PACKET_TYPE_SINGLE,
    PROJECT_NAME,
    PROTOCOL_VERSION,
    QPKRF_EXTENSION,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    WIRE_MAGIC_V5 as WIRE_MAGIC,
)
from .exceptions import (
    OpenQPEPError,
    QPEPFaultGuardError,
    QPEPKeyRingError,
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPPassphrasePolicyError,
    QPEPSuiteError,
    QPEPTruncationError,
    QPEPWireFormatError,
)
from .kdf.argon2id_cascade import derive_qpkrf_keys_v4
from .passphrase import analyze_passphrase, enforce_passphrase_policy
from .primitives.cc512_aead import cc512_decrypt as _cc512_decrypt_mod
from .primitives.cc512_aead import cc512_encrypt as _cc512_encrypt_mod
from .primitives.consttime import ct_eq, ct_eq_str
from .primitives.hgc448 import (
    ed448_keygen,
    ed448_sign,
    ed448_verify,
    strict_ed448_verify,
    validate_ed448_point,
    validate_x448_public_key,
    x448_exchange,
    x448_keygen,
)
from .primitives.zeroize import SecretBuffer, zeroize_bytes, zeroize_secret_dict
from .qlx_lattice import QLX_TIERS, QVS_TIERS, QLXEngine, QVSEngine, qsponge_512, qsponge_var
from .wire.armor import (
    FORBIDDEN_ARMOR_HEADERS,
    MAX_ARMOR_BLANK_LINES,
    MAX_ARMOR_BODY_LINE_LEN,
    MAX_ARMOR_HEADER_COUNT,
    MAX_ARMOR_HEADER_LINE_LEN,
    MAX_ARMOR_LINES,
    _compute_armor_crc,
    _has_forbidden_control_or_bidi,
    _validate_header_token,
    _verify_armor_crc_strict,
    safe_zlib_decompress,
    strict_b64decode,
    strict_json_loads,
)
from .wire.file_registry import SUPPORTED_FILE_EXTENSIONS, detect_file_extension_and_mime
from .wire.framing import pack_wire_frame, unpack_wire_frame

MAX_PACKET_CHUNKS = 2048  # 2048 x 64 KiB = 128 MiB max chunks per packet (CPU-DoS ceiling)

# Hardened Post-Quantum & AI-Cryptanalysis Immunity Profile for OpenQPEP Official Release 1.2.6
QUANTUM_IMMUNITY_MATRIX: Dict[str, Dict[str, str]] = {
    "JVG_AND_SHOR": {
        "threat": "Hybrid QNTT Factorization & Shor's Algorithm",
        "mitigation": (
            "Anchors key encapsulation and signatures in 4096-dimensional Module-LWE (QLX-4096, k=16, n=256, q=3329) "
            "and (8x7) Module-SIS/LWE (QVS-256, Q=8380417) fused with HGC-448 via 512-bit qSponge-512, "
            "plus 5 genuine Beyond-LWE post-quantum families (Binary Goppa Patterson, LRPC Rank-Metric, CSIDH-512, UOV, QHS-512)."
        ),
    },
    "GROVER_ENHANCED_BKZ_SIEVING": {
        "threat": "Quantum-Accelerated Lattice Sieving (Grover-Enhanced BKZ-beta)",
        "mitigation": (
            "Scales module rank to k=16 (4,096 dimensions in QLX-4096) and k=64 (16,384 dimensions in QLX-16384), "
            "pushing required BKZ block sizes to beta > 1650 (>512-bit post-quantum work factor)."
        ),
    },
    "DIHEDRAL_COSET_PROBLEM_DCP": {
        "threat": "Quantum Algorithms for the Dihedral Coset Problem (DCP)",
        "mitigation": (
            "Applies Fujisaki-Okamoto (FO) IND-CCA2 re-encryption verification with H_ek transcript binding, lossy compression, "
            "and branchless constant-time implicit rejection (ct_cmov)."
        ),
    },
    "MULTI_KEY_AEAD_COLLISIONS": {
        "threat": "Invisible Salamanders / Non-Key-Committing AEAD Multi-Key Forgery",
        "mitigation": (
            "Upgrades Calyx-Cascade-512 (CC-512) to provably CMT-4 Key-Committing Cascade AEAD combining AES-256-GCM, "
            "ChaCha20-Poly1305, and a 256-bit qSponge-512 key+nonce+AAD+ciphertext commitment tag verified before decryption."
        ),
    },
    "GROVER_SYMMETRIC_AND_HASH": {
        "threat": "Grover's Algorithm on Symmetric Ciphers & Hash Primitives",
        "mitigation": (
            "Enforces 512-bit qSponge-512 (SHA3-512) and qSponge-XOF (SHAKE-256) over a 1600-bit Keccak state "
            "together with 512-bit cascaded CMT-4 CC-512 payload encryption."
        ),
    },
    "SIDE_CHANNEL_AND_FAULT_INJECTION": {
        "threat": "Side-Channel Timing & Glitch/Rowhammer Fault Injection Attacks",
        "mitigation": (
            "Enforces FIPS 204-style hedged deterministic signing and mandatory Verify-Before-Emit Fault-Guard "
            "across all 10 suites (QVS, Ed448, QHS-512, QMQ-512, CIF-SQI-512, CSP-Omega), compile-time thread-safe "
            "C99 NTT tables, constant-time ct_eq/ct_cmov checks, OS mlock/MADV_DONTDUMP guard-page arenas, and "
            "compiler-barrier openqpep_explicit_bzero + openqpep_is_zeroed verification."
        ),
    },
}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return strict_b64decode(text)


def _safe_zlib_decompress(data: bytes, max_bytes: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decompresses zlib payload with dual byte-ceiling and zip-bomb ratio defenses."""
    return safe_zlib_decompress(data, max_bytes=max_bytes)


def _canonical_blwe_digest(public_bundle: Dict[str, Any]) -> bytes:
    """Computes canonical 512-bit binding digest of beyond_lwe_public (empty marker for lattice suites)."""
    blwe = public_bundle.get("beyond_lwe_public")
    if not blwe:
        return b"NONE"
    return qsponge_512(
        b"CALYX-QPEP-BLWE-BIND-v1.0.0|" + json.dumps(blwe, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _compute_key_hash(
    suite_id: str,
    hgc_pk_bytes: bytes,
    qlx_pk: bytes,
    hgc_sig_pk_bytes: bytes,
    qvs_pk: bytes,
    blwe_digest: bytes,
) -> str:
    """Computes the canonical 64-char Key Hash cryptographically binding suite_id, lattice/HGC keys, and Beyond-LWE keys."""
    return qsponge_512(
        b"CALYX-QPEP-KEY-HASH-v1.0.0|"
        + suite_id.encode("ascii")
        + b"|"
        + hgc_pk_bytes
        + qlx_pk
        + hgc_sig_pk_bytes
        + qvs_pk
        + blwe_digest
    ).hex().upper()[:64]


def _compute_keyring_integrity_mac(
    key_hash: str,
    created_at: str,
    name: str,
    email: str,
    public_bundle: Dict[str, Any],
) -> str:
    mac_input = json.dumps(
        {
            "key_hash": key_hash,
            "created_at": created_at,
            "name": name,
            "email": email,
            "public_bundle": public_bundle,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return qsponge_512(b"CALYX-QPKRF-INTEGRITY-v1.0.0|" + mac_input).hex().upper()


def _armor_wrap(
    header_label: str,
    metadata: Dict[str, str],
    payload_bytes: bytes,
    *,
    packet_type: int = PACKET_TYPE_SINGLE,
) -> str:
    """
    Encapsulates payload_bytes into Official Wire Format v5 (\\x89QPE\\x05\\x00) and zero-metadata
    ASCII armor with mandatory 48-bit qSponge checksum (`={crc}`).
    Filters forbidden cleartext identity headers on non-keyring blocks.
    """
    wire_frame = pack_wire_frame(payload_bytes, header_label, packet_type=packet_type)
    b64_raw = _b64e(wire_frame)
    lines = [b64_raw[i : i + 64] for i in range(0, len(b64_raw), 64)]
    crc_digest = _compute_armor_crc(wire_frame)

    is_keyring = "KEY RING" in header_label.upper()
    meta_lines = []
    for k, v in metadata.items():
        if not is_keyring and k.lower() in FORBIDDEN_ARMOR_HEADERS:
            continue
        _validate_header_token(str(k), str(v))
        meta_lines.append(f"{k}: {v}")

    body = "\n".join(
        [f"-----BEGIN {header_label}-----"]
        + meta_lines
        + [""]
        + lines
        + [f"={crc_digest}", f"-----END {header_label}-----"]
    )
    return body + "\n"


def _armor_unwrap(armored_text: str, expected_label: Optional[str] = None) -> Tuple[str, Dict[str, str], bytes]:
    if not isinstance(armored_text, str) or not armored_text or len(armored_text) > MAX_ARMOR_BYTES:
        raise QPEPWireFormatError("ASCII armor input missing or exceeds maximum allowed size.")
    if armored_text.count("\n") > MAX_ARMOR_LINES:
        raise QPEPWireFormatError(f"ASCII armor exceeds maximum allowed line count ({MAX_ARMOR_LINES}).")
    lines = [line.strip() for line in armored_text.strip().splitlines()]
    if len(lines) > MAX_ARMOR_LINES:
        raise QPEPWireFormatError(f"ASCII armor exceeds maximum allowed line count ({MAX_ARMOR_LINES}).")
    if not lines or not lines[0].startswith("-----BEGIN ") or not lines[-1].startswith("-----END "):
        raise QPEPWireFormatError("Invalid OpenQPEP armor header/footer.")
    begin_label = lines[0][len("-----BEGIN ") : -len("-----")]
    end_label = lines[-1][len("-----END ") : -len("-----")]
    if begin_label != end_label:
        raise QPEPWireFormatError(f"Mismatched armor labels: {begin_label} vs {end_label}")
    if expected_label and begin_label != expected_label:
        norm_begin = begin_label.replace("OPENQPEP", "CALYX QPEP").replace("CALYX QPEP QPKRF", "CALYX QPKRF")
        norm_exp = expected_label.replace("OPENQPEP", "CALYX QPEP").replace("CALYX QPEP QPKRF", "CALYX QPKRF")
        if norm_begin != norm_exp:
            raise QPEPWireFormatError(f"Expected armor label '{expected_label}', got '{begin_label}'")

    metadata: Dict[str, str] = {}
    seen_meta_keys = set()
    b64_chunks: List[str] = []
    checksum_line: Optional[str] = None
    in_body = False
    blank_lines = 0

    for line in lines[1:-1]:
        if not in_body:
            if line == "":
                in_body = True
                blank_lines += 1
                continue
            if ":" in line:
                if len(line) > MAX_ARMOR_HEADER_LINE_LEN:
                    raise QPEPWireFormatError("OpenQPEP armor header line exceeds maximum allowed length.")
                k, v = line.split(":", 1)
                ks, vs = k.strip(), v.strip()
                _validate_header_token(ks, vs)
                k_low = ks.lower()
                if k_low in seen_meta_keys:
                    raise QPEPWireFormatError(f"Duplicate OpenQPEP armor header '{ks}' rejected.")
                seen_meta_keys.add(k_low)
                if len(seen_meta_keys) > MAX_ARMOR_HEADER_COUNT:
                    raise QPEPWireFormatError("Too many OpenQPEP armor header lines.")
                metadata[ks] = vs
            else:
                in_body = True
                if line.startswith("="):
                    checksum_line = line[1:].strip()
                else:
                    if len(line) > MAX_ARMOR_BODY_LINE_LEN:
                        raise QPEPWireFormatError(
                            f"OpenQPEP armor body line exceeds maximum allowed length ({MAX_ARMOR_BODY_LINE_LEN} chars)."
                        )
                    b64_chunks.append(line)
        else:
            if not line:
                blank_lines += 1
                if blank_lines > MAX_ARMOR_BLANK_LINES:
                    raise QPEPWireFormatError("Excessive blank lines inside OpenQPEP ASCII armor payload.")
                continue
            if line.startswith("="):
                if checksum_line is not None:
                    raise QPEPWireFormatError("Duplicate OpenQPEP armor checksum line.")
                checksum_line = line[1:].strip()
                continue
            if checksum_line is not None:
                raise QPEPWireFormatError("Unexpected Base64 body line after OpenQPEP armor checksum line.")
            if len(line) > MAX_ARMOR_BODY_LINE_LEN:
                raise QPEPWireFormatError(
                    f"OpenQPEP armor body line exceeds maximum allowed length ({MAX_ARMOR_BODY_LINE_LEN} chars)."
                )
            b64_chunks.append(line)

    if not b64_chunks:
        raise QPEPWireFormatError("Empty OpenQPEP ASCII armor payload.")

    raw_frame = strict_b64decode("".join(b64_chunks))

    # Reject ALL legacy pre-release magics (-rc, -pc, -beta) deterministically with QPEPLegacyProtocolError
    if len(raw_frame) >= 6 and raw_frame[:6] in ALL_LEGACY_WIRE_MAGICS:
        raise QPEPLegacyProtocolError(
            "Legacy pre-release (-rc / -pc / -beta) wire format is strictly rejected in "
            "OpenQPEP Official Release 1.2.6 (zero backwards compatibility). Official Wire Format v5 (\\x89QPE\\x05\\x00) is required."
        )
    if not raw_frame.startswith(WIRE_MAGIC):
        raise QPEPLegacyProtocolError(
            "Unsupported or legacy wire format. OpenQPEP Official Release 1.2.6 requires Official Wire Format v5 (\\x89QPE\\x05\\x00)."
        )

    # Strictly enforce mandatory canonical 8-char Base64 armor CRC verification in constant time
    _verify_armor_crc_strict(checksum_line, raw_frame)

    payload_bytes, _ptype = unpack_wire_frame(raw_frame, begin_label)
    return begin_label, metadata, payload_bytes


def _cc512_encrypt(plaintext: bytes, k_s1: bytes, k_s2: bytes, aad: bytes) -> Tuple[bytes, bytes, bytes]:
    """Routes protocol CC-512 encryption through CMT-4 Key-Committing CC-512 AEAD."""
    n1 = os.urandom(12)
    n2 = os.urandom(12)
    with SecretBuffer(k_s1 + k_s2) as kbuf:
        ct = _cc512_encrypt_mod(kbuf.as_bytes(), n1 + n2, plaintext, aad)
    return n1, n2, ct


def _cc512_decrypt(outer_ct: bytes, k_s1: bytes, k_s2: bytes, n1: bytes, n2: bytes, aad: bytes) -> bytes:
    """Routes protocol CC-512 decryption through CMT-4 Key-Committing CC-512 AEAD."""
    with SecretBuffer(k_s1 + k_s2) as kbuf:
        return _cc512_decrypt_mod(kbuf.as_bytes(), n1 + n2, outer_ct, aad)


@dataclass
class QPEPKeyRing:
    key_hash: str
    created_at: str
    name: str
    email: str
    qlx_tier: str
    qvs_tier: str
    comment: str
    public_bundle: Dict[str, Any]
    encrypted_private_bundle: Optional[Dict[str, Any]]
    integrity_mac: str

    @property
    def has_private_key(self) -> bool:
        return self.encrypted_private_bundle is not None


_HEX_UPPER_CHARS = frozenset("0123456789ABCDEF")
_CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK"})


def _strict_json_loads(raw: bytes | str) -> Any:
    """Parses JSON strictly with recursion-depth, node-count, duplicate-key, and NaN/Infinity defenses."""
    return strict_json_loads(raw)


def _classify_confusable_script(ch: str) -> Optional[str]:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    for script in _CONFUSABLE_SCRIPTS:
        if name.startswith(script + " ") or (" " + script + " ") in name:
            return script
    return None


def _validate_identity_field(field_name: str, value: Any, max_len: int, allow_empty: bool = False) -> str:
    """
    Strictly validates keyring UID fields against non-string inputs, oversizing, ASCII/Unicode
    control & bidi-override characters, zero-width spoofing, non-NFC normalization, and
    mixed-script Unicode homograph spoofing (Latin/Cyrillic/Greek).
    """
    if not isinstance(value, str):
        raise QPEPWireFormatError(f"Keyring '{field_name}' must be a string.")
    if not allow_empty and not value.strip():
        raise QPEPWireFormatError(f"Keyring '{field_name}' must not be empty.")
    if len(value) > max_len:
        raise QPEPWireFormatError(f"Keyring '{field_name}' exceeds maximum allowed length of {max_len} characters.")
    if _has_forbidden_control_or_bidi(value):
        raise QPEPWireFormatError(f"Keyring '{field_name}' contains prohibited control, format, or Bidi-override characters.")
    if unicodedata.normalize("NFC", value) != value:
        raise QPEPWireFormatError(f"Keyring '{field_name}' must be in Unicode NFC canonical form.")
    if field_name == "email" and any(ord(ch) > 127 for ch in value):
        raise QPEPWireFormatError("Keyring 'email' must contain strictly ASCII printable characters (homograph defense).")
    scripts_seen = set()
    for ch in value:
        sc = _classify_confusable_script(ch)
        if sc is not None:
            scripts_seen.add(sc)
            if len(scripts_seen) > 1:
                raise QPEPWireFormatError(
                    f"Keyring '{field_name}' rejected: mixed-script Unicode homograph spoofing detected ({sorted(scripts_seen)})."
                )
    return value


class CalyxQPEPProtocol:
    """
    Official Reference Implementation of OpenQPEP by Calyx Labs Inc. (Official Release 1.2.6).
    """

    @staticmethod
    def generate_keypair(
        name: str,
        email: str,
        passphrase: str,
        qlx_tier: str = "QLX-4096",
        comment: str = "OpenQPEP by Calyx Labs Inc.",
    ) -> QPEPKeyRing:
        _validate_identity_field("name", name, 256, allow_empty=False)
        _validate_identity_field("email", email, 320, allow_empty=False)
        _validate_identity_field("comment", comment, 512, allow_empty=True)
        policy_witness = enforce_passphrase_policy(passphrase)
        requested_suite = qlx_tier
        is_beyond_lwe = requested_suite in BEYOND_LWE_SUITES
        if qlx_tier not in QLX_TIERS:
            if not is_beyond_lwe:
                raise QPEPSuiteError(f"Unsupported OpenQPEP suite: {requested_suite}")
            qlx_tier = "QLX-4096"
        qvs_tier = QLX_TIERS[qlx_tier]["qvs_tier"]
        suite_id = requested_suite if is_beyond_lwe else qlx_tier

        blwe_pub, blwe_priv = (
            generate_beyond_lwe_material(requested_suite, allow_low_ram_override=True)
            if is_beyond_lwe
            else (None, None)
        )

        hgc_pk_bytes, hgc_sk_bytes = x448_keygen()
        hgc_sig_pk_bytes, hgc_sig_sk_bytes = ed448_keygen()
        qlx_pk, qlx_sk = QLXEngine.keygen(tier=qlx_tier, policy_witness=policy_witness)
        qvs_pk, qvs_sk = QVSEngine.keygen(tier=qvs_tier, policy_witness=policy_witness)

        public_bundle: Dict[str, Any] = {
            "suite_id": suite_id,
            "qlx_tier": qlx_tier,
            "qvs_tier": qvs_tier,
            "hgc_448_public_b64": _b64e(hgc_pk_bytes),
            "qlx_public_b64": _b64e(qlx_pk),
            "hgc_sig_public_b64": _b64e(hgc_sig_pk_bytes),
            "qvs_public_b64": _b64e(qvs_pk),
        }
        if is_beyond_lwe and blwe_pub is not None:
            public_bundle["beyond_lwe_public"] = blwe_pub

        blwe_digest = _canonical_blwe_digest(public_bundle)
        key_hash = _compute_key_hash(suite_id, hgc_pk_bytes, qlx_pk, hgc_sig_pk_bytes, qvs_pk, blwe_digest)
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        cert_transcript = (
            f"CALYX-QPEP-SELFCERT-v1.0.0|{suite_id}|{key_hash}|{created_at}|{name}|{email}|{qlx_tier}|{qvs_tier}|{comment}".encode("utf-8")
            + hgc_pk_bytes
            + qlx_pk
            + hgc_sig_pk_bytes
            + qvs_pk
            + blwe_digest
        )

        with (
            SecretBuffer(hgc_sk_bytes) as hgc_sk_buf,
            SecretBuffer(hgc_sig_sk_bytes) as sig_sk_buf,
            SecretBuffer(qlx_sk) as qlx_sk_buf,
            SecretBuffer(qvs_sk) as qvs_sk_buf,
        ):
            sig_part1 = ed448_sign(sig_sk_buf.as_bytes(), cert_transcript)
            sig_part2 = QVSEngine.sign(qvs_sk_buf.as_bytes(), qvs_pk, cert_transcript, tier=qvs_tier)
            public_bundle["self_signature_b64"] = _b64e(sig_part1 + sig_part2)

            kdf_salt = os.urandom(32)
            k_s1, k_s2, k_mac, kdf_v4_params = derive_qpkrf_keys_v4(passphrase, kdf_salt, qlx_tier=qlx_tier)

            with SecretBuffer(k_s1) as ks1_buf, SecretBuffer(k_s2) as ks2_buf, SecretBuffer(k_mac) as kmac_buf:
                with SecretBuffer(
                    qsponge_var(
                        b"CALYX-QPEP-SK-MASK-v1.0.0|" + kmac_buf.as_bytes() + key_hash.encode("ascii"),
                        len(qlx_sk_buf),
                    )
                ) as mask_buf:
                    masked_qlx_ba = bytearray(len(qlx_sk_buf))
                    try:
                        with qlx_sk_buf.view() as qlx_mv, mask_buf.view() as mask_mv:
                            for idx in range(len(qlx_sk_buf)):
                                masked_qlx_ba[idx] = qlx_mv[idx] ^ mask_mv[idx]
                        priv_payload_obj: Dict[str, Any] = {
                            "hgc_448_private_b64": _b64e(hgc_sk_buf.as_bytes()),
                            "qlx_masked_private_b64": _b64e(bytes(masked_qlx_ba)),
                            "hgc_sig_private_b64": _b64e(sig_sk_buf.as_bytes()),
                            "qvs_private_b64": _b64e(qvs_sk_buf.as_bytes()),
                        }
                        if is_beyond_lwe and blwe_priv is not None:
                            priv_payload_obj["beyond_lwe_private"] = blwe_priv
                        try:
                            with SecretBuffer(json.dumps(priv_payload_obj, separators=(",", ":")).encode("utf-8")) as priv_raw_buf:
                                aad = f"CALYX-QPEP-PRIVRING-v1.0.0|{suite_id}|{key_hash}".encode("utf-8")
                                n1, n2, ct_priv = _cc512_encrypt(
                                    priv_raw_buf.as_bytes(), ks1_buf.as_bytes(), ks2_buf.as_bytes(), aad
                                )
                        finally:
                            zeroize_secret_dict(priv_payload_obj)
                    finally:
                        zeroize_bytes(masked_qlx_ba)

        encrypted_private_bundle = {
            "kdf_version": MANDATORY_KDF_VERSION,
            "kdf_salt_b64": _b64e(kdf_salt),
            "kdf_params": kdf_v4_params,
            "cc512_n1_b64": _b64e(n1),
            "cc512_n2_b64": _b64e(n2),
            "ciphertext_b64": _b64e(ct_priv),
        }

        integrity_mac = _compute_keyring_integrity_mac(key_hash, created_at, name, email, public_bundle)

        return QPEPKeyRing(
            key_hash=key_hash,
            created_at=created_at,
            name=name,
            email=email,
            qlx_tier=qlx_tier,
            qvs_tier=qvs_tier,
            comment=comment,
            public_bundle=public_bundle,
            encrypted_private_bundle=encrypted_private_bundle,
            integrity_mac=integrity_mac,
        )

    @staticmethod
    def verify_public_keyring_self_signature(keyring: QPEPKeyRing) -> bool:
        try:
            if not isinstance(keyring, QPEPKeyRing) or not isinstance(keyring.public_bundle, dict):
                return False
            _validate_identity_field("name", keyring.name, 256, allow_empty=False)
            _validate_identity_field("email", keyring.email, 320, allow_empty=False)
            _validate_identity_field("comment", keyring.comment, 512, allow_empty=True)
            if (
                not isinstance(keyring.created_at, str)
                or not keyring.created_at.strip()
                or len(keyring.created_at) > 64
                or _has_forbidden_control_or_bidi(keyring.created_at)
            ):
                return False
            if (
                not isinstance(keyring.key_hash, str)
                or len(keyring.key_hash) != 64
                or any(ch not in _HEX_UPPER_CHARS for ch in keyring.key_hash)
            ):
                return False
            if (
                not isinstance(keyring.integrity_mac, str)
                or len(keyring.integrity_mac) != 128
                or any(ch not in _HEX_UPPER_CHARS for ch in keyring.integrity_mac)
            ):
                return False

            if keyring.qlx_tier not in QLX_TIERS:
                return False
            if keyring.qvs_tier != QLX_TIERS[keyring.qlx_tier]["qvs_tier"]:
                return False

            expected_mac = _compute_keyring_integrity_mac(
                keyring.key_hash,
                keyring.created_at,
                keyring.name,
                keyring.email,
                keyring.public_bundle,
            )
            if not ct_eq_str(keyring.integrity_mac, expected_mac):
                return False

            suite_id = CalyxQPEPProtocol.get_keyring_suite_id(keyring)
            if suite_id not in QLX_TIERS and suite_id not in BEYOND_LWE_SUITES:
                return False

            hgc_pk_bytes = _b64d(keyring.public_bundle["hgc_448_public_b64"])
            qlx_pk = _b64d(keyring.public_bundle["qlx_public_b64"])
            hgc_sig_pk_bytes = _b64d(keyring.public_bundle["hgc_sig_public_b64"])
            qvs_pk = _b64d(keyring.public_bundle["qvs_public_b64"])
            self_sig_blob = _b64d(keyring.public_bundle["self_signature_b64"])
            blwe_digest = _canonical_blwe_digest(keyring.public_bundle)

            # Strict public-key size, canonical encoding & low-order/small-order rejection
            if not validate_x448_public_key(hgc_pk_bytes, strict_canonical=True):
                return False
            if not validate_ed448_point(hgc_sig_pk_bytes, reject_small_order=True):
                return False
            if len(qlx_pk) != QLX_TIERS[keyring.qlx_tier]["pk_bytes"]:
                return False
            if len(qvs_pk) != QVS_TIERS[keyring.qvs_tier]["pk_bytes"]:
                return False

            expected_hash = _compute_key_hash(suite_id, hgc_pk_bytes, qlx_pk, hgc_sig_pk_bytes, qvs_pk, blwe_digest)
            if not ct_eq_str(keyring.key_hash, expected_hash):
                return False

            qvs_tier = keyring.qvs_tier
            expected_sig_len = 114 + QVS_TIERS[qvs_tier]["sig_bytes"]
            if len(self_sig_blob) != expected_sig_len:
                return False
            sig1 = self_sig_blob[:114]
            sig2 = self_sig_blob[114:]

            cert_transcript = (
                f"CALYX-QPEP-SELFCERT-v1.0.0|{suite_id}|{keyring.key_hash}|{keyring.created_at}|{keyring.name}|{keyring.email}|{keyring.qlx_tier}|{keyring.qvs_tier}|{keyring.comment}".encode("utf-8")
                + hgc_pk_bytes
                + qlx_pk
                + hgc_sig_pk_bytes
                + qvs_pk
                + blwe_digest
            )
            if not strict_ed448_verify(hgc_sig_pk_bytes, sig1, cert_transcript):
                return False
            return QVSEngine.verify(qvs_pk, cert_transcript, sig2, tier=qvs_tier)
        except (OpenQPEPError, ValueError, TypeError, KeyError, IndexError, binascii.Error, UnicodeDecodeError):
            return False

    @staticmethod
    def unlock_private_keys(keyring: QPEPKeyRing, passphrase: str) -> Dict[str, Any]:
        enforce_passphrase_policy(passphrase)
        if not isinstance(keyring, QPEPKeyRing) or not keyring.encrypted_private_bundle:
            raise QPEPKeyRingError("This QPKRF key ring contains only a public key.")

        priv_enc = keyring.encrypted_private_bundle
        if not isinstance(priv_enc, dict):
            raise QPEPWireFormatError("Malformed QPKRF encrypted_private_bundle structure.")
        try:
            kdf_salt = _b64d(priv_enc["kdf_salt_b64"])
        except (KeyError, ValueError, TypeError, binascii.Error) as exc:
            raise QPEPWireFormatError("Missing or malformed QPKRF kdf_salt_b64.") from exc
        kdf_params = priv_enc.get("kdf_params")
        if kdf_params is None:
            kdf_params = {}
        if not isinstance(kdf_params, dict):
            raise QPEPWireFormatError("Malformed QPKRF kdf_params object.")
        raw_kdf_ver = priv_enc.get("kdf_version")
        if raw_kdf_ver is None:
            raw_kdf_ver = kdf_params.get("kdf_version", 0)
        if isinstance(raw_kdf_ver, bool) or not isinstance(raw_kdf_ver, int):
            raise QPEPWireFormatError("Invalid QPKRF kdf_version field (must be integer).")
        kdf_version = raw_kdf_ver
        if kdf_version < MANDATORY_KDF_VERSION:
            raise QPEPLegacyProtocolError(
                f"Legacy pre-release key ring (kdf_version: {kdf_version} from -rc / -pc / -beta) is strictly rejected "
                f"in OpenQPEP Official Release 1.2.6 (zero backwards compatibility; mandatory kdf_version: {MANDATORY_KDF_VERSION})."
            )

        k_s1, k_s2, k_mac, _ = derive_qpkrf_keys_v4(passphrase, kdf_salt, kdf_params=kdf_params)
        suite_id = CalyxQPEPProtocol.get_keyring_suite_id(keyring)
        aad = f"CALYX-QPEP-PRIVRING-v1.0.0|{suite_id}|{keyring.key_hash}".encode("utf-8")

        with SecretBuffer(k_s1) as ks1_buf, SecretBuffer(k_s2) as ks2_buf, SecretBuffer(k_mac) as kmac_buf:
            try:
                decrypted_json = _cc512_decrypt(
                    outer_ct=_b64d(priv_enc["ciphertext_b64"]),
                    k_s1=ks1_buf.as_bytes(),
                    k_s2=ks2_buf.as_bytes(),
                    n1=_b64d(priv_enc["cc512_n1_b64"]),
                    n2=_b64d(priv_enc["cc512_n2_b64"]),
                    aad=aad,
                )
            except (OpenQPEPError, ValueError, TypeError, KeyError, binascii.Error) as exc:
                raise QPEPMacVerificationError("Invalid passphrase or tampered QPKRF private key ring.") from exc

            with SecretBuffer(decrypted_json) as dj_buf:
                parsed = _strict_json_loads(dj_buf.as_bytes())
                if not isinstance(parsed, dict):
                    raise QPEPMacVerificationError("Corrupted QPKRF private bundle JSON structure.")
                try:
                    with SecretBuffer(_b64d(parsed["qlx_masked_private_b64"])) as masked_buf:
                        with SecretBuffer(
                            qsponge_var(
                                b"CALYX-QPEP-SK-MASK-v1.0.0|" + kmac_buf.as_bytes() + keyring.key_hash.encode("ascii"),
                                len(masked_buf),
                            )
                        ) as mask_buf:
                            qlx_sk_ba = bytearray(len(masked_buf))
                            try:
                                with masked_buf.view() as m_mv, mask_buf.view() as k_mv:
                                    for idx in range(len(masked_buf)):
                                        qlx_sk_ba[idx] = m_mv[idx] ^ k_mv[idx]
                                qlx_sk = bytes(qlx_sk_ba)
                            finally:
                                zeroize_bytes(qlx_sk_ba)

                    out_keys: Dict[str, Any] = {
                        "hgc_448_private": _b64d(parsed["hgc_448_private_b64"]),
                        "qlx_private": qlx_sk,
                        "hgc_sig_private": _b64d(parsed["hgc_sig_private_b64"]),
                        "qvs_private": _b64d(parsed["qvs_private_b64"]),
                    }
                    if "beyond_lwe_private" in parsed:
                        out_keys["beyond_lwe_private"] = parsed["beyond_lwe_private"]
                    return out_keys
                finally:
                    parsed.clear()

    @staticmethod
    def export_qpkrf(
        keyring: QPEPKeyRing,
        passphrase: Optional[str] = None,
        include_private: bool = False,
        output_path: Optional[str | Path] = None,
    ) -> str:
        if include_private:
            if not passphrase:
                raise QPEPPassphrasePolicyError("Exporting a private .qpkrf key ring requires the key's mandatory passphrase.")
            verified_priv = CalyxQPEPProtocol.unlock_private_keys(keyring, passphrase)
            zeroize_secret_dict(verified_priv)

        suite_id = CalyxQPEPProtocol.get_keyring_suite_id(keyring)
        ring_type = "PRIVATE_KEY_RING" if include_private else "PUBLIC_KEY_RING"
        suite_desc = (
            f"{suite_id} (Beyond-LWE) / CMT-4 CC-512"
            if suite_id in BEYOND_LWE_SUITES
            else f"{keyring.qlx_tier}+HGC-448 / {keyring.qvs_tier}+qSponge-512 / CMT-4 CC-512"
        )
        envelope: Dict[str, Any] = {
            "magic": "QPKRF-v1.0.0",
            "protocol": PROJECT_NAME,
            "version": UNIVERSAL_VERSION,
            "ring_type": ring_type,
            "suite_id": suite_id,
            "suite": suite_desc,
            "key_hash": keyring.key_hash,
            "created_at": keyring.created_at,
            "identity": {
                "name": keyring.name,
                "email": keyring.email,
                "comment": keyring.comment,
            },
            "public_bundle": keyring.public_bundle,
            "integrity_mac": keyring.integrity_mac,
        }
        if include_private:
            envelope["encrypted_private_bundle"] = keyring.encrypted_private_bundle

        payload_bytes = json.dumps(envelope, indent=2).encode("utf-8")
        label = (
            "CALYX QPKRF PRIVATE KEY RING"
            if include_private
            else "CALYX QPKRF PUBLIC KEY RING"
        )
        metadata = {
            "Protocol": PROJECT_NAME,
            "Version": f"{PROTOCOL_VERSION} ({UNIVERSAL_VERSION_LABEL})",
            "Suite": suite_desc,
            "Key-Hash": keyring.key_hash,
            "Identity": f"{keyring.name} <{keyring.email}>",
        }
        armored = _armor_wrap(label, metadata, payload_bytes, packet_type=PACKET_TYPE_KEYRING)

        if output_path is not None:
            out_p = Path(output_path)
            if out_p.suffix.lower() != QPKRF_EXTENSION:
                raise ValueError(f"Exported key ring files MUST use the '{QPKRF_EXTENSION}' file extension.")
            out_p.write_text(armored, encoding="utf-8")
            if include_private:
                try:
                    os.chmod(out_p, 0o600)
                except OSError:
                    pass

        return armored

    @staticmethod
    def import_qpkrf(armored_or_path: str | Path, passphrase: Optional[str] = None) -> QPEPKeyRing:
        if isinstance(armored_or_path, Path) or (
            isinstance(armored_or_path, str)
            and "\n" not in armored_or_path
            and Path(armored_or_path).exists()
        ):
            p = Path(armored_or_path)
            if p.suffix.lower() != QPKRF_EXTENSION:
                raise ValueError(f"Key ring file MUST have the '{QPKRF_EXTENSION}' extension.")
            armored_text = p.read_text(encoding="utf-8")
        else:
            armored_text = str(armored_or_path)

        label, armor_meta, payload_bytes = _armor_unwrap(armored_text)
        valid_labels = (
            "CALYX QPKRF PUBLIC KEY RING",
            "CALYX QPKRF PRIVATE KEY RING",
            "OPENQPEP QPKRF PUBLIC KEY RING",
            "OPENQPEP QPKRF PRIVATE KEY RING",
        )
        if label not in valid_labels:
            raise QPEPWireFormatError(f"Unexpected QPKRF armor header: {label}")

        envelope = _strict_json_loads(payload_bytes)
        if not isinstance(envelope, dict):
            raise QPEPWireFormatError("QPKRF payload must be a JSON object.")

        env_ver = str(envelope.get("version") or "")
        low_ver = env_ver.lower()
        if "-rc" in low_ver or "-pc" in low_ver or "-beta" in low_ver or low_ver.startswith("0."):
            raise QPEPLegacyProtocolError(
                f"Legacy pre-release .qpkrf key ring ({env_ver}) is strictly rejected in OpenQPEP Official Release 1.2.6 "
                f"(zero backwards compatibility)."
            )
        if not ct_eq_str(envelope.get("magic"), "QPKRF-v1.0.0"):
            raise QPEPWireFormatError("Invalid or missing QPKRF magic identifier.")

        identity = envelope.get("identity")
        pub_b = envelope.get("public_bundle")
        if not isinstance(identity, dict) or not isinstance(pub_b, dict):
            raise QPEPWireFormatError("QPKRF envelope missing required 'identity' or 'public_bundle' objects.")

        # Strict UID validation (anti-homograph, anti-bidi, anti-oversizing)
        uid_name = _validate_identity_field("name", identity.get("name"), 256, allow_empty=False)
        uid_email = _validate_identity_field("email", identity.get("email"), 320, allow_empty=False)
        uid_comment = _validate_identity_field("comment", identity.get("comment", ""), 512, allow_empty=True)

        # Anti-substitution cross-checks between armor headers, envelope metadata, and public_bundle
        env_key_hash = envelope.get("key_hash")
        if not isinstance(env_key_hash, str) or len(env_key_hash) != 64:
            raise QPEPKeyRingError("QPKRF envelope has invalid or missing key_hash.")
        header_kh = armor_meta.get("Key-Hash")
        if header_kh is not None and not ct_eq_str(header_kh, env_key_hash):
            raise QPEPKeyRingError("QPKRF armor Key-Hash header does not match signed envelope key_hash (anti-substitution).")

        env_suite_id = envelope.get("suite_id")
        pub_suite_id = pub_b.get("suite_id")
        if env_suite_id is not None and pub_suite_id is not None and not ct_eq_str(env_suite_id, pub_suite_id):
            raise QPEPKeyRingError("QPKRF envelope suite_id does not match public_bundle suite_id (anti-substitution).")

        ring_type = envelope.get("ring_type")
        enc_priv = envelope.get("encrypted_private_bundle")
        if ring_type == "PUBLIC_KEY_RING" and enc_priv is not None:
            raise QPEPKeyRingError("QPKRF marked PUBLIC_KEY_RING must not contain encrypted_private_bundle.")

        keyring = QPEPKeyRing(
            key_hash=env_key_hash,
            created_at=envelope["created_at"],
            name=uid_name,
            email=uid_email,
            qlx_tier=pub_b.get("qlx_tier", "QLX-4096"),
            qvs_tier=pub_b.get("qvs_tier", "QVS-256"),
            comment=uid_comment,
            public_bundle=pub_b,
            encrypted_private_bundle=enc_priv,
            integrity_mac=envelope["integrity_mac"],
        )

        if not CalyxQPEPProtocol.verify_public_keyring_self_signature(keyring):
            raise QPEPKeyRingError("QPKRF self-certification signature or integrity_mac verification failed.")

        if keyring.has_private_key:
            if not passphrase:
                raise QPEPPassphrasePolicyError("Importing a private .qpkrf key ring requires its mandatory QPKD-Argon2id passphrase.")
            verified_priv = CalyxQPEPProtocol.unlock_private_keys(keyring, passphrase)
            zeroize_secret_dict(verified_priv)

        return keyring

    @staticmethod
    def encrypt_bytes(
        plaintext: bytes,
        recipient_keyring: QPEPKeyRing,
        encrypting_keyring: QPEPKeyRing,
        passphrase: str,
        filename: Optional[str] = None,
        compress: bool = True,
    ) -> str:
        """
        Encrypts raw bytes using BOTH the sender's Encrypting Key (embedded attached signature)
        and the Recipient's Key (.qpkrf) across ALL 10 canonical suites (Lattice AND Beyond-LWE).
        Emits ZERO cleartext sender/recipient identity headers.
        """
        enforce_passphrase_policy(passphrase)
        if isinstance(plaintext, bytearray):
            plaintext = bytes(plaintext)
        if not isinstance(plaintext, bytes):
            raise QPEPWireFormatError("Plaintext payload must be bytes or bytearray.")
        if not isinstance(recipient_keyring, QPEPKeyRing) or not isinstance(encrypting_keyring, QPEPKeyRing):
            raise QPEPKeyRingError("recipient_keyring and encrypting_keyring must be QPEPKeyRing instances.")
        if not CalyxQPEPProtocol.verify_public_keyring_self_signature(recipient_keyring):
            raise QPEPKeyRingError("Recipient public key ring self-signature is invalid.")

        embedded_sig = CalyxQPEPProtocol.sign_bytes(plaintext, encrypting_keyring, passphrase)
        norm_fname, file_ext, mime_type = detect_file_extension_and_mime(plaintext, filename)
        inner_envelope = {
            "filename": norm_fname,
            "file_extension": file_ext,
            "mime_type": mime_type,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "plaintext_qsponge_512": qsponge_512(plaintext).hex().upper(),
            "plaintext_size": len(plaintext),
            "compressed": compress,
            "encrypting_key_hash": encrypting_keyring.key_hash,
            "embedded_signature": embedded_sig,
            "data_b64": _b64e(zlib.compress(plaintext, level=6) if compress else plaintext),
        }
        serialized_inner = json.dumps(inner_envelope, separators=(",", ":")).encode("utf-8")

        # Unified authenticated Beyond-LWE dispatch: preserves embedded sender signature, filename & MIME!
        req_suite = CalyxQPEPProtocol.get_keyring_suite_id(recipient_keyring)
        if req_suite in BEYOND_LWE_SUITES and recipient_keyring.public_bundle.get("beyond_lwe_public"):
            blwe_env = b"QPEP-BLWE-ENV-v1.0.0|" + serialized_inner
            return CalyxQPEPProtocol.encrypt_beyond_lwe_packet(blwe_env, recipient_keyring)

        qlx_tier = recipient_keyring.qlx_tier
        recip_hgc_pk_bytes = _b64d(recipient_keyring.public_bundle["hgc_448_public_b64"])
        recip_qlx_pk_bytes = _b64d(recipient_keyring.public_bundle["qlx_public_b64"])

        eph_hgc_pk_bytes, eph_hgc_sk_bytes = x448_keygen()
        with SecretBuffer(eph_hgc_sk_bytes) as eph_buf:
            ss_hgc_raw = x448_exchange(eph_buf.as_bytes(), recip_hgc_pk_bytes)
        ct_qlx, ss_qlx_raw = QLXEngine.encaps(recip_qlx_pk_bytes, tier=qlx_tier)

        with SecretBuffer(ss_hgc_raw) as ss_hgc_buf, SecretBuffer(ss_qlx_raw) as ss_qlx_buf:
            ss_hybrid_raw = qsponge_var(
                b"CALYX-QPEP-KEM-v1.0.0|"
                + ss_qlx_buf.as_bytes()
                + ss_hgc_buf.as_bytes()
                + ct_qlx
                + eph_hgc_pk_bytes
                + recip_qlx_pk_bytes
                + recip_hgc_pk_bytes,
                64,
            )

        with SecretBuffer(ss_hybrid_raw) as ss_hybrid_buf, SecretBuffer(serialized_inner) as inner_buf:
            pkt_salt = os.urandom(32)
            hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=128,
                salt=pkt_salt,
                info=b"CALYX-QPEP-CC512-SUBKEYS-v1.0.0|" + recipient_keyring.key_hash.encode("ascii"),
            )
            with SecretBuffer(hkdf.derive(ss_hybrid_buf.as_bytes())) as okm_buf:
                with okm_buf.view() as okm_mv:
                    k_s1 = bytes(okm_mv[:32])
                    k_s2 = bytes(okm_mv[32:64])
                    k_transcript_mac = bytes(okm_mv[64:128])

                chunks_out = []
                total_len = len(inner_buf)
                offset = 0
                chunk_idx = 0
                with inner_buf.view() as inner_mv:
                    while offset < total_len or (total_len == 0 and chunk_idx == 0):
                        piece = bytes(inner_mv[offset : offset + CHUNK_SIZE])
                        offset += len(piece)
                        is_final = 1 if offset >= total_len else 0
                        aad = f"CALYX-QPEP-CC512-v1.0.0|recip={recipient_keyring.key_hash}|idx={chunk_idx}|final={is_final}".encode("utf-8")
                        n1, n2, ct_chunk = _cc512_encrypt(piece, k_s1, k_s2, aad)
                        chunks_out.append({
                            "idx": chunk_idx,
                            "final": is_final,
                            "cc512_n1_b64": _b64e(n1),
                            "cc512_n2_b64": _b64e(n2),
                            "ct_b64": _b64e(ct_chunk),
                        })
                        chunk_idx += 1
                        if total_len == 0:
                            break

                transcript_bytes = json.dumps(chunks_out, sort_keys=True, separators=(",", ":")).encode("utf-8")
                transcript_tag = hmac.new(
                    k_transcript_mac,
                    b"CALYX-QPEP-TRANSCRIPT-v1.0.0|" + transcript_bytes,
                    hashlib.sha3_512,
                ).hexdigest().upper()

        packet_obj = {
            "magic": "QPEP-v1.0.0",
            "protocol": PROJECT_NAME,
            "version": UNIVERSAL_VERSION,
            "qlx_tier": qlx_tier,
            "recipient_key_hash": recipient_keyring.key_hash,
            "encrypting_key_hash": encrypting_keyring.key_hash,
            "pkt_salt_b64": _b64e(pkt_salt),
            "ephemeral_hgc_448_pk_b64": _b64e(eph_hgc_pk_bytes),
            "qlx_ct_b64": _b64e(ct_qlx),
            "chunks": chunks_out,
            "transcript_qsponge_512": transcript_tag,
        }

        metadata = {
            "Protocol": PROJECT_NAME,
            "Version": f"{PROTOCOL_VERSION} ({UNIVERSAL_VERSION_LABEL})",
            "Suite": f"{qlx_tier}+HGC-448 / CMT-4 CC-512",
        }
        return _armor_wrap("CALYX QPEP ENCRYPTED PACKET", metadata, json.dumps(packet_obj).encode("utf-8"))

    @staticmethod
    def decrypt_packet(
        armored_packet: str,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        enforce_passphrase_policy(passphrase)
        priv_keys = CalyxQPEPProtocol.unlock_private_keys(recipient_private_keyring, passphrase)
        try:
            # Unified authenticated Beyond-LWE dispatch
            rec_suite = CalyxQPEPProtocol.get_keyring_suite_id(recipient_private_keyring)
            if rec_suite in BEYOND_LWE_SUITES and "-----BEGIN CALYX QPEP ENCRYPTED PACKET-----" not in armored_packet:
                raw_blwe = CalyxQPEPProtocol.decrypt_beyond_lwe_packet(armored_packet, recipient_private_keyring, passphrase)
                prefix = b"QPEP-BLWE-ENV-v1.0.0|"
                if raw_blwe.startswith(prefix):
                    inner_envelope = _strict_json_loads(raw_blwe[len(prefix) :])
                    if not isinstance(inner_envelope, dict):
                        raise QPEPWireFormatError("Malformed Beyond-LWE inner envelope JSON structure.")
                    raw_data = _b64d(inner_envelope["data_b64"])
                    plaintext = _safe_zlib_decompress(raw_data) if inner_envelope.get("compressed") else raw_data
                    actual_hash = qsponge_512(plaintext).hex().upper()
                    if not hmac.compare_digest(actual_hash, inner_envelope["plaintext_qsponge_512"]):
                        raise ValueError("Plaintext qSponge-512 integrity check failed.")

                    effective_sender = sender_public_keyring
                    if effective_sender is None and inner_envelope.get("encrypting_key_hash") == recipient_private_keyring.key_hash:
                        effective_sender = recipient_private_keyring
                    sig_verified = None
                    if "embedded_signature" in inner_envelope and effective_sender is not None:
                        sig_verified, _, _ = CalyxQPEPProtocol.verify_signature(
                            inner_envelope["embedded_signature"], signer_public_keyring=effective_sender
                        )
                    norm_fname, file_ext, mime_type = detect_file_extension_and_mime(plaintext, inner_envelope.get("filename"))
                    return plaintext, {
                        "suite_id": rec_suite,
                        "beyond_lwe": True,
                        "qlx_tier": recipient_private_keyring.qlx_tier,
                        "qvs_tier": recipient_private_keyring.qvs_tier,
                        "filename": norm_fname,
                        "file_extension": inner_envelope.get("file_extension") or file_ext,
                        "mime_type": inner_envelope.get("mime_type") or mime_type,
                        "timestamp": inner_envelope.get("timestamp"),
                        "plaintext_qsponge_512": actual_hash,
                        "plaintext_size": inner_envelope.get("plaintext_size"),
                        "encrypting_key_hash": inner_envelope.get("encrypting_key_hash"),
                        "signature_verified": sig_verified,
                        "sender_verified": bool(sig_verified) if sig_verified is not None else False,
                    }
                # Direct low-level Beyond-LWE packet (from encrypt_beyond_lwe_packet)
                actual_hash = qsponge_512(raw_blwe).hex().upper()
                return raw_blwe, {
                    "suite_id": rec_suite,
                    "beyond_lwe": True,
                    "plaintext_qsponge_512": actual_hash,
                    "plaintext_size": len(raw_blwe),
                    "signature_verified": None,
                    "sender_verified": False,
                }

            _, _, payload_bytes = _armor_unwrap(armored_packet, expected_label="CALYX QPEP ENCRYPTED PACKET")
            packet_obj = _strict_json_loads(payload_bytes)
            if not isinstance(packet_obj, dict):
                raise QPEPWireFormatError("OpenQPEP packet payload must be a JSON object.")

            if not ct_eq_str(packet_obj.get("recipient_key_hash"), recipient_private_keyring.key_hash):
                raise QPEPKeyRingError("Packet is addressed to a different Key Hash.")

            qlx_tier = recipient_private_keyring.qlx_tier
            recip_hgc_pk_bytes = _b64d(recipient_private_keyring.public_bundle["hgc_448_public_b64"])
            recip_qlx_pk_bytes = _b64d(recipient_private_keyring.public_bundle["qlx_public_b64"])

            eph_hgc_pk_bytes = _b64d(packet_obj["ephemeral_hgc_448_pk_b64"])
            ct_qlx = _b64d(packet_obj["qlx_ct_b64"])

            with SecretBuffer(priv_keys["hgc_448_private"]) as hgc_sk_buf, SecretBuffer(priv_keys["qlx_private"]) as qlx_sk_buf:
                ss_hgc_raw = x448_exchange(hgc_sk_buf.as_bytes(), eph_hgc_pk_bytes)
                ss_qlx_raw = QLXEngine.decaps(qlx_sk_buf.as_bytes(), ct_qlx, tier=qlx_tier)

            with SecretBuffer(ss_hgc_raw) as ss_hgc_buf, SecretBuffer(ss_qlx_raw) as ss_qlx_buf:
                ss_hybrid_raw = qsponge_var(
                    b"CALYX-QPEP-KEM-v1.0.0|"
                    + ss_qlx_buf.as_bytes()
                    + ss_hgc_buf.as_bytes()
                    + ct_qlx
                    + eph_hgc_pk_bytes
                    + recip_qlx_pk_bytes
                    + recip_hgc_pk_bytes,
                    64,
                )

            reassembled = bytearray()
            try:
                with SecretBuffer(ss_hybrid_raw) as ss_hybrid_buf:
                    pkt_salt = _b64d(packet_obj["pkt_salt_b64"])
                    hkdf = HKDF(
                        algorithm=hashes.SHA3_512(),
                        length=128,
                        salt=pkt_salt,
                        info=b"CALYX-QPEP-CC512-SUBKEYS-v1.0.0|" + recipient_private_keyring.key_hash.encode("ascii"),
                    )
                    with SecretBuffer(hkdf.derive(ss_hybrid_buf.as_bytes())) as okm_buf:
                        with okm_buf.view() as okm_mv:
                            k_s1 = bytes(okm_mv[:32])
                            k_s2 = bytes(okm_mv[32:64])
                            k_transcript_mac = bytes(okm_mv[64:128])

                        chunks = packet_obj.get("chunks", [])
                        if not isinstance(chunks, list) or not chunks:
                            raise QPEPWireFormatError("Malformed OpenQPEP packet: missing or empty chunk list.")
                        if len(chunks) > MAX_PACKET_CHUNKS:
                            raise QPEPWireFormatError(
                                f"OpenQPEP packet chunk count ({len(chunks)}) exceeds maximum allowed ({MAX_PACKET_CHUNKS})."
                            )
                        if any(not isinstance(ch, dict) for ch in chunks):
                            raise QPEPWireFormatError("Malformed OpenQPEP packet: non-object chunk entry.")
                        if chunks[-1].get("final") != 1 or any(ch.get("final") != 0 for ch in chunks[:-1]):
                            raise QPEPTruncationError("Stream truncation or invalid final frame flag detected.")

                        transcript_bytes = json.dumps(chunks, sort_keys=True, separators=(",", ":")).encode("utf-8")
                        expected_tag = hmac.new(
                            k_transcript_mac,
                            b"CALYX-QPEP-TRANSCRIPT-v1.0.0|" + transcript_bytes,
                            hashlib.sha3_512,
                        ).hexdigest().upper()
                        if not hmac.compare_digest(expected_tag, packet_obj["transcript_qsponge_512"]):
                            raise QPEPMacVerificationError("Packet transcript qSponge-512 verification failed.")

                        for expected_idx, ch in enumerate(chunks):
                            if ch["idx"] != expected_idx:
                                raise QPEPTruncationError("Chunk sequence tampering detected.")
                            is_final = ch["final"]
                            aad = f"CALYX-QPEP-CC512-v1.0.0|recip={recipient_private_keyring.key_hash}|idx={expected_idx}|final={is_final}".encode("utf-8")
                            pt_piece = _cc512_decrypt(
                                outer_ct=_b64d(ch["ct_b64"]),
                                k_s1=k_s1,
                                k_s2=k_s2,
                                n1=_b64d(ch["cc512_n1_b64"]),
                                n2=_b64d(ch["cc512_n2_b64"]),
                                aad=aad,
                            )
                            if len(reassembled) + len(pt_piece) > MAX_WIRE_FRAME_BYTES:
                                raise QPEPWireFormatError("Reassembled OpenQPEP packet exceeds maximum allowed size.")
                            reassembled.extend(pt_piece)

                inner_envelope = _strict_json_loads(bytes(reassembled))
                if not isinstance(inner_envelope, dict):
                    raise QPEPWireFormatError("Malformed decrypted OpenQPEP inner envelope JSON structure.")
            finally:
                zeroize_bytes(reassembled)
        finally:
            zeroize_secret_dict(priv_keys)
        raw_data = _b64d(inner_envelope["data_b64"])
        plaintext = _safe_zlib_decompress(raw_data) if inner_envelope.get("compressed") else raw_data

        actual_hash = qsponge_512(plaintext).hex().upper()
        if not ct_eq_str(actual_hash, inner_envelope.get("plaintext_qsponge_512")):
            raise QPEPMacVerificationError("Plaintext qSponge-512 integrity check failed.")

        effective_sender = sender_public_keyring
        if effective_sender is None and ct_eq_str(inner_envelope.get("encrypting_key_hash"), recipient_private_keyring.key_hash):
            effective_sender = recipient_private_keyring

        sig_verified = None
        if "embedded_signature" in inner_envelope and effective_sender is not None:
            sig_verified, _, _ = CalyxQPEPProtocol.verify_signature(
                inner_envelope["embedded_signature"], signer_public_keyring=effective_sender
            )

        norm_fname, file_ext, mime_type = detect_file_extension_and_mime(
            plaintext, inner_envelope.get("filename")
        )
        meta_info = {
            "suite_id": qlx_tier,
            "qlx_tier": qlx_tier,
            "qvs_tier": QLX_TIERS[qlx_tier]["qvs_tier"],
            "filename": norm_fname,
            "file_extension": inner_envelope.get("file_extension") or file_ext,
            "mime_type": inner_envelope.get("mime_type") or mime_type,
            "timestamp": inner_envelope.get("timestamp"),
            "plaintext_qsponge_512": actual_hash,
            "plaintext_size": inner_envelope.get("plaintext_size"),
            "encrypting_key_hash": inner_envelope.get("encrypting_key_hash"),
            "signature_verified": sig_verified,
        }
        return plaintext, meta_info

    @staticmethod
    def encrypt_file(
        input_path: str | Path,
        recipient_keyring: QPEPKeyRing,
        encrypting_keyring: QPEPKeyRing,
        passphrase: str,
        output_path: Optional[str | Path] = None,
    ) -> Tuple[str, Path]:
        in_p = Path(input_path)
        raw_bytes = in_p.read_bytes()
        armored = CalyxQPEPProtocol.encrypt_bytes(
            raw_bytes,
            recipient_keyring=recipient_keyring,
            encrypting_keyring=encrypting_keyring,
            passphrase=passphrase,
            filename=in_p.name,
        )
        out_p = Path(output_path) if output_path else in_p.with_name(in_p.name + ".qpep")
        out_p.write_text(armored, encoding="utf-8")
        return armored, out_p

    @staticmethod
    def decrypt_file(
        input_qpep_path: str | Path,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        output_path_or_dir: Optional[str | Path] = None,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> Tuple[bytes, Path, Dict[str, Any]]:
        in_p = Path(input_qpep_path)
        armored = in_p.read_text(encoding="utf-8")
        pt_bytes, meta = CalyxQPEPProtocol.decrypt_packet(
            armored,
            recipient_private_keyring=recipient_private_keyring,
            passphrase=passphrase,
            sender_public_keyring=sender_public_keyring,
        )
        # Sanitize filename against path traversal
        raw_name = Path(str(meta.get("filename") or "decrypted_file.bin")).name
        rec_name = raw_name if raw_name and raw_name not in (".", "..") else "decrypted_file.bin"
        if output_path_or_dir is None:
            out_p = in_p.parent / rec_name
        else:
            cand = Path(output_path_or_dir)
            out_p = (cand / rec_name) if cand.is_dir() else cand
        out_p.write_bytes(pt_bytes)
        return pt_bytes, out_p, meta

    @staticmethod
    def encrypt_text(
        plaintext: str,
        recipient_keyring: QPEPKeyRing,
        encrypting_keyring: QPEPKeyRing,
        passphrase: str,
    ) -> str:
        return CalyxQPEPProtocol.encrypt_bytes(
            plaintext.encode("utf-8"),
            recipient_keyring=recipient_keyring,
            encrypting_keyring=encrypting_keyring,
            passphrase=passphrase,
            filename="message.txt",
        )

    @staticmethod
    def decrypt_text(
        armored_packet: str,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> str:
        pt_bytes, _ = CalyxQPEPProtocol.decrypt_packet(
            armored_packet,
            recipient_private_keyring=recipient_private_keyring,
            passphrase=passphrase,
            sender_public_keyring=sender_public_keyring,
        )
        return pt_bytes.decode("utf-8")

    @staticmethod
    def sign_bytes(data: bytes, signer_private_keyring: QPEPKeyRing, passphrase: str) -> str:
        """
        Creates an Attached OpenQPEP Signature (CALYX QPEP ATTACHED SIGNATURE) over Wire Format v5.
        Detached signatures are prohibited in OpenQPEP.
        """
        enforce_passphrase_policy(passphrase)
        if isinstance(data, bytearray):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise QPEPWireFormatError("Signature payload data must be bytes or bytearray.")
        if not isinstance(signer_private_keyring, QPEPKeyRing):
            raise QPEPKeyRingError("signer_private_keyring must be a QPEPKeyRing instance.")
        s_suite = CalyxQPEPProtocol.get_keyring_suite_id(signer_private_keyring)
        if s_suite in BEYOND_LWE_SUITES and signer_private_keyring.public_bundle.get("beyond_lwe_public"):
            return CalyxQPEPProtocol.sign_beyond_lwe_bytes(data, signer_private_keyring, passphrase)

        priv_keys = CalyxQPEPProtocol.unlock_private_keys(signer_private_keyring, passphrase)
        try:
            qvs_pk = _b64d(signer_private_keyring.public_bundle["qvs_public_b64"])
            qvs_tier = signer_private_keyring.qvs_tier

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            msg_digest = qsponge_512(data).hex().upper()
            transcript = f"CALYX-QPEP-ATTACHED-SIG-v1.0.0|{signer_private_keyring.key_hash}|{timestamp}|{msg_digest}".encode("utf-8")

            with SecretBuffer(priv_keys["hgc_sig_private"]) as ed_buf, SecretBuffer(priv_keys["qvs_private"]) as qvs_buf:
                sig1 = ed448_sign(ed_buf.as_bytes(), transcript)
                sig2 = QVSEngine.sign(qvs_buf.as_bytes(), qvs_pk, transcript, tier=qvs_tier)
        finally:
            zeroize_secret_dict(priv_keys)

        sig_obj = {
            "magic": "QPSIG-ATTACHED-v1.0.0",
            "protocol": PROJECT_NAME,
            "version": UNIVERSAL_VERSION,
            "signature_mode": "ATTACHED_ENVELOPE",
            "suite": f"{qvs_tier}+qSponge-512",
            "signer_key_hash": signer_private_keyring.key_hash,
            "signer_name": signer_private_keyring.name,
            "signer_email": signer_private_keyring.email,
            "timestamp": timestamp,
            "attached_message_b64": _b64e(data),
            "message_qsponge_512": msg_digest,
            "hgc_signature_b64": _b64e(sig1),
            "qvs_signature_b64": _b64e(sig2),
        }
        metadata = {
            "Protocol": PROJECT_NAME,
            "Version": f"{PROTOCOL_VERSION} ({UNIVERSAL_VERSION_LABEL})",
            "Mode": "ATTACHED-SIGNATURE",
            "Suite": f"{qvs_tier}+qSponge-512",
            "Timestamp": timestamp,
        }
        return _armor_wrap(
            "CALYX QPEP ATTACHED SIGNATURE",
            metadata,
            json.dumps(sig_obj).encode("utf-8"),
            packet_type=PACKET_TYPE_SIGNATURE,
        )

    @staticmethod
    def verify_signature(
        armored_attached_signature: str,
        signer_public_keyring: Optional[QPEPKeyRing] = None,
        keyring_pool: Optional[List[QPEPKeyRing]] = None,
    ) -> Tuple[bool, Optional[bytes], Optional[QPEPKeyRing]]:
        try:
            if (
                signer_public_keyring is not None
                and CalyxQPEPProtocol.get_keyring_suite_id(signer_public_keyring) in BEYOND_LWE_SUITES
                and "-----BEGIN CALYX QPEP ATTACHED SIGNATURE-----" not in armored_attached_signature
            ):
                ok_b, msg_b = CalyxQPEPProtocol.verify_beyond_lwe_signature(armored_attached_signature, signer_public_keyring)
                return ok_b, (msg_b if ok_b else None), (signer_public_keyring if ok_b else None)

            if (
                signer_public_keyring is None
                and keyring_pool is not None
                and "-----BEGIN CALYX QPEP ATTACHED SIGNATURE-----" not in armored_attached_signature
            ):
                for cand in keyring_pool:
                    if CalyxQPEPProtocol.get_keyring_suite_id(cand) in BEYOND_LWE_SUITES:
                        ok_b, msg_b = CalyxQPEPProtocol.verify_beyond_lwe_signature(armored_attached_signature, cand)
                        if ok_b:
                            return True, msg_b, cand
                return False, None, None

            _, _, payload_bytes = _armor_unwrap(
                armored_attached_signature, expected_label="CALYX QPEP ATTACHED SIGNATURE"
            )
            sig_obj = _strict_json_loads(payload_bytes)
            if not isinstance(sig_obj, dict):
                raise QPEPWireFormatError("OpenQPEP attached signature payload must be a JSON object.")
            if "attached_message_b64" not in sig_obj:
                raise QPEPWireFormatError("Detached signatures are prohibited in OpenQPEP; message must be attached.")

            extracted_data = _b64d(sig_obj["attached_message_b64"])
            actual_digest = qsponge_512(extracted_data).hex().upper()
            if not ct_eq_str(actual_digest, sig_obj.get("message_qsponge_512", "")):
                return False, None, None

            target_hash = sig_obj.get("signer_key_hash")
            candidates = []
            if signer_public_keyring is not None:
                candidates = [signer_public_keyring]
            elif keyring_pool is not None:
                candidates = [kr for kr in keyring_pool if ct_eq_str(kr.key_hash, target_hash)] or list(keyring_pool)

            for candidate in candidates:
                if not ct_eq_str(candidate.key_hash, target_hash):
                    continue
                if not CalyxQPEPProtocol.verify_public_keyring_self_signature(candidate):
                    continue
                transcript = (
                    f"CALYX-QPEP-ATTACHED-SIG-v1.0.0|{candidate.key_hash}|{sig_obj['timestamp']}|{actual_digest}".encode("utf-8")
                )
                ed_ok = strict_ed448_verify(
                    _b64d(candidate.public_bundle["hgc_sig_public_b64"]),
                    _b64d(sig_obj["hgc_signature_b64"]),
                    transcript,
                )
                if not ed_ok:
                    continue
                qvs_pk = _b64d(candidate.public_bundle["qvs_public_b64"])
                if QVSEngine.verify(qvs_pk, transcript, _b64d(sig_obj["qvs_signature_b64"]), tier=candidate.qvs_tier):
                    return True, extracted_data, candidate
            return False, None, None
        except (OpenQPEPError, ValueError, TypeError, KeyError, IndexError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
            return False, None, None

    @staticmethod
    def sign_text(text: str, signer_private_keyring: QPEPKeyRing, passphrase: str) -> str:
        return CalyxQPEPProtocol.sign_bytes(text.encode("utf-8"), signer_private_keyring, passphrase)

    @staticmethod
    def verify_text_signature(
        armored_attached_signature: str,
        signer_public_keyring: Optional[QPEPKeyRing] = None,
        keyring_pool: Optional[List[QPEPKeyRing]] = None,
    ) -> Tuple[bool, Optional[str], Optional[QPEPKeyRing]]:
        ok, raw_bytes, kr = CalyxQPEPProtocol.verify_signature(
            armored_attached_signature,
            signer_public_keyring=signer_public_keyring,
            keyring_pool=keyring_pool,
        )
        return ok, (raw_bytes.decode("utf-8") if (ok and raw_bytes is not None) else None), kr

    @staticmethod
    def encrypt_multi_recipient(
        payload: bytes,
        recipient_keyrings,
        *,
        bucket_size: int = 4096,
        pad_slots_power_of_2: bool = True,
        min_slots: int = 4,
        use_blind_hint: bool = True,
    ) -> str:
        from .wire.multi_recipient import encrypt_multi_recipient as _enc_mr
        return _enc_mr(
            payload,
            recipient_keyrings,
            bucket_size=bucket_size,
            pad_slots_power_of_2=pad_slots_power_of_2,
            min_slots=min_slots,
            use_blind_hint=use_blind_hint,
        )

    @staticmethod
    def decrypt_multi_recipient(armored_packet: str, recipient_keyring: QPEPKeyRing, passphrase: str):
        from .wire.multi_recipient import decrypt_multi_recipient as _dec_mr
        return _dec_mr(armored_packet, recipient_keyring, passphrase)

    @staticmethod
    def get_keyring_suite_id(keyring: QPEPKeyRing) -> str:
        return str(keyring.public_bundle.get("suite_id") or keyring.public_bundle.get("qlx_tier") or "QLX-4096")

    @staticmethod
    def encrypt_beyond_lwe_packet(plaintext: bytes, recipient_keyring: QPEPKeyRing) -> str:
        """Encrypts bytes directly using the recipient .qpkrf key ring's native Beyond-LWE suite."""
        suite_id = OpenQPEPProtocol.get_keyring_suite_id(recipient_keyring)
        blwe_pub = recipient_keyring.public_bundle.get("beyond_lwe_public")
        if suite_id not in BEYOND_LWE_SUITES or not blwe_pub:
            raise ValueError(f"Key ring {recipient_keyring.key_hash[:12]} is not a Beyond-LWE suite ({suite_id}).")
        return encrypt_beyond_lwe(suite_id, plaintext, blwe_pub)

    @staticmethod
    def decrypt_beyond_lwe_packet(armored_packet: str, recipient_keyring: QPEPKeyRing, passphrase: str) -> bytes:
        """Unlocks the recipient .qpkrf private key ring via QPKD-Argon2id (kdf_version: 4) and decrypts Beyond-LWE packet."""
        suite_id = OpenQPEPProtocol.get_keyring_suite_id(recipient_keyring)
        priv = OpenQPEPProtocol.unlock_private_keys(recipient_keyring, passphrase)
        try:
            blwe_priv = priv.get("beyond_lwe_private")
            if suite_id not in BEYOND_LWE_SUITES or not blwe_priv:
                raise ValueError(f"Key ring {recipient_keyring.key_hash[:12]} lacks Beyond-LWE private key material.")
            return decrypt_beyond_lwe(suite_id, armored_packet, blwe_priv)
        finally:
            zeroize_secret_dict(priv)

    @staticmethod
    def sign_beyond_lwe_bytes(data: bytes, signer_private_keyring: QPEPKeyRing, passphrase: str) -> str:
        """Signs bytes directly using the signer .qpkrf key ring's native Beyond-LWE signature engine."""
        suite_id = OpenQPEPProtocol.get_keyring_suite_id(signer_private_keyring)
        blwe_pub = signer_private_keyring.public_bundle.get("beyond_lwe_public")
        priv = OpenQPEPProtocol.unlock_private_keys(signer_private_keyring, passphrase)
        try:
            blwe_priv = priv.get("beyond_lwe_private")
            if suite_id not in BEYOND_LWE_SUITES or not blwe_pub or not blwe_priv:
                raise ValueError(f"Key ring {signer_private_keyring.key_hash[:12]} lacks Beyond-LWE signing material.")
            return sign_beyond_lwe(suite_id, data, blwe_pub, blwe_priv)
        finally:
            zeroize_secret_dict(priv)

    @staticmethod
    def verify_beyond_lwe_signature(armored_sig: str, signer_public_keyring: QPEPKeyRing) -> Tuple[bool, bytes]:
        """Verifies a native Beyond-LWE signature against the signer's .qpkrf public key ring."""
        suite_id = OpenQPEPProtocol.get_keyring_suite_id(signer_public_keyring)
        blwe_pub = signer_public_keyring.public_bundle.get("beyond_lwe_public")
        if suite_id not in BEYOND_LWE_SUITES or not blwe_pub:
            return False, b""
        return verify_beyond_lwe(suite_id, armored_sig, blwe_pub)


OpenQPEPProtocol = CalyxQPEPProtocol
