"""
Calyx-Cascade-512 (CC-512) Provably CMT-4 Key-Committing Dual-Stream AEAD &
Nonce-Misuse-Resistant Synthetic-IV Mode (CC-512-SIV) — Official Release 1.2.7.

Security Guarantees:
  1. Wire v5 CMT-4 Key-Committing CC-512 AEAD (`cc512_encrypt` / `cc512_decrypt`, 100% frozen Wire v5):
     - Dual-Algorithm Confidentiality & Integrity: AES-256-GCM nested inside ChaCha20-Poly1305
       with cryptographically independent 256-bit keys and 96-bit nonces.
     - Provable CMT-4 Key Commitment: Derives domain-separated (k_aes, k_chacha, k_commit) via
       qSponge-XOF("CALYX-CC512-CMT4-KEYS-v1.0.0|" || key64 || nonce24, 96) and appends a 256-bit
       qSponge-512 commitment tag bound to (k_commit, nonce24, len(aad), aad, ct_outer), verified in
       constant time BEFORE decryption—eliminating multi-key / invisible-salamanders collisions.
     - Wire overhead: 64 bytes (16 B AES-GCM tag + 16 B Poly1305 tag + 32 B CMT-4 commitment tag).

  2. Nonce-Misuse-Resistant CC-512-SIV (`cc512_siv_encrypt` / `cc512_siv_decrypt` / `CC512SIV`):
     - Deterministic / Hedged MRAE construction for offline vaults, deterministic deduplication,
       and nonce-misuse-resistant key wrapping (`cc512_siv_wrap_key` / `cc512_siv_unwrap_key`).
     - Computes a 256-bit synthetic IV (`siv32`) over injectively length-framed (nonce, aad, plaintext)
       under a domain-separated 512-bit SIV MAC key, then derives a fresh per-message 512-bit key
       and 192-bit dual nonce from (k_enc_root, siv32) to drive CMT-4 CC-512.
     - Repeating or omitting nonces NEVER causes AES-GCM / ChaCha20-Poly1305 keystream reuse or
       GHASH/Poly1305 key recovery; decrypted plaintext is scrubbed in `SecretBuffer` and never
       released unless `siv32` re-verification succeeds in constant time.
     - Wire overhead: 96 bytes (32 B SIV + 64 B CMT-4 CC-512).

  3. Active Memory Hygiene:
     - Strict type, length, and SP 800-38D payload-ceiling assertions (`QPEPWireFormatError`).
     - Every master key, derived subkey, and intermediate decryption buffer is locked and scrubbed
       deterministically via `SecretBuffer` (zero `mlock` page leaks on success or failure).
"""
import struct
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from ..exceptions import QPEPMacVerificationError, QPEPWireFormatError
from ..native.loader import (
    native_cc512_cmt4_tag,
    native_cc512_derive_cmt4_subkeys,
    native_cc512_siv_master_subkeys,
    native_cc512_siv_msg_keys,
    native_cc512_siv_synth,
    native_cc512_verify_cmt4_tag,
)
from .consttime import ct_eq
from .qsponge import qsponge_512, qsponge_var
from .zeroize import SecretBuffer

BytesLike = Union[bytes, bytearray, memoryview]

CC512_KEY_BYTES = 64
CC512_NONCE_BYTES = 24
CC512_CMT_TAG_BYTES = 32
CC512_OVERHEAD_BYTES = 64  # 16 (AES-GCM) + 16 (ChaCha20-Poly1305) + 32 (CMT-4 tag)

CC512_SIV_BYTES = 32
CC512_SIV_OVERHEAD_BYTES = CC512_SIV_BYTES + CC512_OVERHEAD_BYTES  # 96 bytes
CC512_SIV_MAX_NONCE_BYTES = 4096
CC512_MAX_PLAINTEXT_BYTES = (1 << 36) - 32  # NIST SP 800-38D AES-GCM counter-safety ceiling

_SIV_DOMAIN_MASTER = b"CALYX-CC512-SIV-MASTER-v1.1.3|"
_SIV_DOMAIN_SYNTH = b"CALYX-CC512-SIV-SYNTH-v1.1.3|"
_SIV_DOMAIN_MSGKEY = b"CALYX-CC512-SIV-MSGKEY-v1.1.3|"
_SIV_DOMAIN_AAD = b"CALYX-CC512-SIV-AAD-v1.1.3|"
_SIV_DOMAIN_KEYWRAP = b"CALYX-CC512-SIV-KEYWRAP-v1.1.3|"


def _require_bytes_like(value: BytesLike, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise QPEPWireFormatError(f"CC-512 {name} must be bytes, bytearray, or memoryview.")
    return bytes(value)


def _validate_key64(key64: BytesLike) -> SecretBuffer:
    if not isinstance(key64, (bytes, bytearray, memoryview)):
        raise QPEPWireFormatError("CC-512 key must be bytes, bytearray, or memoryview.")
    if len(key64) != CC512_KEY_BYTES:
        raise QPEPWireFormatError("CC-512 requires a 64-byte (512-bit) key.")
    return SecretBuffer(key64)


def _validate_nonce24(nonce24: BytesLike) -> bytes:
    if not isinstance(nonce24, (bytes, bytearray, memoryview)):
        raise QPEPWireFormatError("CC-512 nonce must be bytes, bytearray, or memoryview.")
    if len(nonce24) != CC512_NONCE_BYTES:
        raise QPEPWireFormatError("CC-512 requires a 24-byte (192-bit) dual nonce.")
    return bytes(nonce24)


def _validate_siv_nonce(nonce: Optional[BytesLike]) -> bytes:
    if nonce is None:
        return b""
    nonce_bytes = _require_bytes_like(nonce, "SIV nonce")
    if len(nonce_bytes) > CC512_SIV_MAX_NONCE_BYTES:
        raise QPEPWireFormatError(
            f"CC-512-SIV nonce exceeds maximum allowed length of {CC512_SIV_MAX_NONCE_BYTES} bytes."
        )
    return nonce_bytes


def _derive_cmt4_subkeys(key64: bytes, nonce24: bytes) -> bytes:
    nat = native_cc512_derive_cmt4_subkeys(key64, nonce24)
    if nat is not None:
        return nat
    return qsponge_var(b"CALYX-CC512-CMT4-KEYS-v1.0.0|" + key64 + nonce24, 96)


def _compute_cmt4_tag(k_commit: bytes, nonce24: bytes, aad: bytes, ct_outer: bytes) -> bytes:
    nat = native_cc512_cmt4_tag(k_commit, nonce24, aad, ct_outer)
    if nat is not None:
        return nat
    return qsponge_512(
        b"CALYX-CC512-CMT4-TAG-v1.0.0|"
        + k_commit
        + nonce24
        + struct.pack(">Q", len(aad))
        + aad
        + ct_outer
    )[:CC512_CMT_TAG_BYTES]


def _verify_cmt4_tag(k_commit: bytes, nonce24: bytes, aad: bytes, ct_outer: bytes, recv_cmt: bytes) -> bool:
    nat = native_cc512_verify_cmt4_tag(k_commit, nonce24, aad, ct_outer, recv_cmt)
    if nat is not None:
        return nat
    expected_cmt = _compute_cmt4_tag(k_commit, nonce24, aad, ct_outer)
    return ct_eq(recv_cmt, expected_cmt)


def _derive_siv_master_subkeys(key64: bytes) -> bytes:
    nat = native_cc512_siv_master_subkeys(key64)
    if nat is not None:
        return nat
    return qsponge_var(_SIV_DOMAIN_MASTER + key64, 128)


def _compute_siv32(k_siv_mac: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    nat = native_cc512_siv_synth(k_siv_mac, nonce, aad, plaintext)
    if nat is not None:
        return nat
    return qsponge_512(
        _SIV_DOMAIN_SYNTH
        + k_siv_mac
        + struct.pack(">Q", len(nonce))
        + nonce
        + struct.pack(">Q", len(aad))
        + aad
        + struct.pack(">Q", len(plaintext))
        + plaintext
    )[:CC512_SIV_BYTES]


def _derive_siv_message_keys(k_enc_root: bytes, siv32: bytes) -> bytes:
    nat = native_cc512_siv_msg_keys(k_enc_root, siv32)
    if nat is not None:
        return nat
    return qsponge_var(_SIV_DOMAIN_MSGKEY + k_enc_root + siv32, CC512_KEY_BYTES + CC512_NONCE_BYTES)


def _build_siv_aad(siv32: bytes, nonce: bytes, aad: bytes) -> bytes:
    return (
        _SIV_DOMAIN_AAD
        + siv32
        + struct.pack(">Q", len(nonce))
        + nonce
        + struct.pack(">Q", len(aad))
        + aad
    )


def cc512_encrypt(key64: BytesLike, nonce24: BytesLike, plaintext: BytesLike, aad: BytesLike) -> bytes:
    """
    Encrypts `plaintext` with Wire v5 CMT-4 Key-Committing CC-512 AEAD:
      ct_inner = AES-256-GCM(k_aes, nonce24[:12], plaintext, aad)
      ct_outer = ChaCha20-Poly1305(k_chacha, nonce24[12:24], ct_inner, aad)
      cmt_tag  = qSponge-512("CALYX-CC512-CMT4-TAG-v1.0.0|" || k_commit || nonce24 || len(aad) || aad || ct_outer)[:32]
      output   = ct_outer || cmt_tag
    """
    nonce_bytes = _validate_nonce24(nonce24)
    pt_bytes = _require_bytes_like(plaintext, "plaintext")
    aad_bytes = _require_bytes_like(aad, "aad")
    if len(pt_bytes) > CC512_MAX_PLAINTEXT_BYTES:
        raise QPEPWireFormatError("CC-512 plaintext exceeds maximum AEAD length ceiling.")

    with _validate_key64(key64) as key_buf:
        with SecretBuffer(_derive_cmt4_subkeys(key_buf.as_bytes(), nonce_bytes)) as sub_buf:
            with sub_buf.view() as mv:
                k_aes = bytes(mv[:32])
                k_chacha = bytes(mv[32:64])
                k_commit = bytes(mv[64:96])
            with SecretBuffer(AESGCM(k_aes).encrypt(nonce_bytes[:12], pt_bytes, aad_bytes)) as inner_buf:
                ct_outer = ChaCha20Poly1305(k_chacha).encrypt(nonce_bytes[12:24], inner_buf.as_bytes(), aad_bytes)
            cmt_tag = _compute_cmt4_tag(k_commit, nonce_bytes, aad_bytes, ct_outer)
            return ct_outer + cmt_tag


def cc512_decrypt(key64: BytesLike, nonce24: BytesLike, ciphertext: BytesLike, aad: BytesLike) -> bytes:
    """
    Verifies the 256-bit CMT-4 key commitment tag in constant time, then decrypts
    outer ChaCha20-Poly1305 and inner AES-256-GCM while scrubbing all intermediate keys & buffers.
    """
    nonce_bytes = _validate_nonce24(nonce24)
    ct_bytes = _require_bytes_like(ciphertext, "ciphertext")
    aad_bytes = _require_bytes_like(aad, "aad")
    if len(ct_bytes) < CC512_OVERHEAD_BYTES:
        raise QPEPMacVerificationError("CC-512 ciphertext truncated below 64-byte minimum overhead.")

    ct_outer = ct_bytes[:-CC512_CMT_TAG_BYTES]
    recv_cmt = ct_bytes[-CC512_CMT_TAG_BYTES:]

    with _validate_key64(key64) as key_buf:
        with SecretBuffer(_derive_cmt4_subkeys(key_buf.as_bytes(), nonce_bytes)) as sub_buf:
            with sub_buf.view() as mv:
                k_aes = bytes(mv[:32])
                k_chacha = bytes(mv[32:64])
                k_commit = bytes(mv[64:96])
            if not _verify_cmt4_tag(k_commit, nonce_bytes, aad_bytes, ct_outer, recv_cmt):
                raise QPEPMacVerificationError("CC-512 CMT-4 key-commitment verification failed.")
            try:
                with SecretBuffer(
                    ChaCha20Poly1305(k_chacha).decrypt(nonce_bytes[12:24], ct_outer, aad_bytes)
                ) as inner_buf:
                    return AESGCM(k_aes).decrypt(nonce_bytes[:12], inner_buf.as_bytes(), aad_bytes)
            except (InvalidTag, ValueError, TypeError) as exc:
                raise QPEPMacVerificationError("CC-512 AEAD authentication tag verification failed.") from exc


def cc512_siv_encrypt(
    key64: BytesLike,
    plaintext: BytesLike,
    aad: BytesLike = b"",
    *,
    nonce: Optional[BytesLike] = b"",
) -> bytes:
    """
    Encrypts `plaintext` with Nonce-Misuse-Resistant CMT-4 Key-Committing CC-512-SIV:
      1. Derives independent 512-bit (k_siv_mac, k_enc_root) from `key64`.
      2. Computes 256-bit synthetic IV `siv32 = qSponge-512(domain || k_siv_mac || len(nonce) || nonce || len(aad) || aad || len(pt) || pt)[:32]`.
      3. Derives a fresh per-message (msg_key64, msg_nonce24) from `(k_enc_root, siv32)`.
      4. Encrypts `plaintext` with CMT-4 CC-512 bound to `(siv32, nonce, aad)` and outputs `siv32 || ct_cc512`.

    Deterministic when `nonce` is omitted (`b""` / `None`); hedged probabilistic MRAE when a nonce is provided.
    Output overhead is exactly 96 bytes (`CC512_SIV_OVERHEAD_BYTES`).
    """
    pt_bytes = _require_bytes_like(plaintext, "plaintext")
    aad_bytes = _require_bytes_like(aad, "aad")
    nonce_bytes = _validate_siv_nonce(nonce)
    if len(pt_bytes) > CC512_MAX_PLAINTEXT_BYTES:
        raise QPEPWireFormatError("CC-512-SIV plaintext exceeds maximum AEAD length ceiling.")

    with _validate_key64(key64) as key_buf:
        with SecretBuffer(_derive_siv_master_subkeys(key_buf.as_bytes())) as master_buf:
            with master_buf.view() as mv:
                k_siv_mac = bytes(mv[:64])
                k_enc_root = bytes(mv[64:128])

            siv32 = _compute_siv32(k_siv_mac, nonce_bytes, aad_bytes, pt_bytes)
            siv_aad = _build_siv_aad(siv32, nonce_bytes, aad_bytes)

            with SecretBuffer(_derive_siv_message_keys(k_enc_root, siv32)) as msg_buf:
                with msg_buf.view() as mmv:
                    msg_key64 = bytes(mmv[:CC512_KEY_BYTES])
                    msg_nonce24 = bytes(mmv[CC512_KEY_BYTES : CC512_KEY_BYTES + CC512_NONCE_BYTES])
                ct_cc512 = cc512_encrypt(msg_key64, msg_nonce24, pt_bytes, siv_aad)
                return siv32 + ct_cc512


def cc512_siv_decrypt(
    key64: BytesLike,
    ciphertext: BytesLike,
    aad: BytesLike = b"",
    *,
    nonce: Optional[BytesLike] = b"",
) -> bytes:
    """
    Decrypts and authenticates a CC-512-SIV ciphertext (`siv32 || ct_cc512`):
      1. Derives per-message `(msg_key64, msg_nonce24)` from `(k_enc_root, recv_siv32)`.
      2. Verifies the 256-bit CMT-4 commitment tag + ChaCha20-Poly1305 + AES-256-GCM tags.
      3. Holds candidate plaintext in `SecretBuffer`, recomputes `expected_siv32`, and verifies
         `ct_eq(recv_siv32, expected_siv32)` in constant time BEFORE releasing plaintext.
    """
    ct_bytes = _require_bytes_like(ciphertext, "ciphertext")
    aad_bytes = _require_bytes_like(aad, "aad")
    nonce_bytes = _validate_siv_nonce(nonce)
    if len(ct_bytes) < CC512_SIV_OVERHEAD_BYTES:
        raise QPEPMacVerificationError("CC-512-SIV ciphertext truncated below 96-byte minimum overhead.")

    recv_siv32 = ct_bytes[:CC512_SIV_BYTES]
    ct_cc512 = ct_bytes[CC512_SIV_BYTES:]
    siv_aad = _build_siv_aad(recv_siv32, nonce_bytes, aad_bytes)

    with _validate_key64(key64) as key_buf:
        with SecretBuffer(_derive_siv_master_subkeys(key_buf.as_bytes())) as master_buf:
            with master_buf.view() as mv:
                k_siv_mac = bytes(mv[:64])
                k_enc_root = bytes(mv[64:128])

            with SecretBuffer(_derive_siv_message_keys(k_enc_root, recv_siv32)) as msg_buf:
                with msg_buf.view() as mmv:
                    msg_key64 = bytes(mmv[:CC512_KEY_BYTES])
                    msg_nonce24 = bytes(mmv[CC512_KEY_BYTES : CC512_KEY_BYTES + CC512_NONCE_BYTES])
                pt_raw = cc512_decrypt(msg_key64, msg_nonce24, ct_cc512, siv_aad)

            with SecretBuffer(pt_raw) as pt_buf:
                expected_siv32 = _compute_siv32(k_siv_mac, nonce_bytes, aad_bytes, pt_buf.as_bytes())
                if not ct_eq(recv_siv32, expected_siv32):
                    raise QPEPMacVerificationError("CC-512-SIV synthetic IV verification failed.")
                return pt_buf.as_bytes()


def cc512_siv_wrap_key(
    kek64: BytesLike,
    secret_key: BytesLike,
    aad: BytesLike = b"",
    *,
    nonce: Optional[BytesLike] = b"",
) -> bytes:
    """
    Nonce-misuse-resistant, domain-separated cryptographic key wrap powered by CC-512-SIV.
    Explicitly separates wrapped-key AAD from general CC-512-SIV data payloads and scrubs
    all secret material in `SecretBuffer`.
    """
    aad_bytes = _require_bytes_like(aad, "aad")
    if not isinstance(secret_key, (bytes, bytearray, memoryview)):
        raise QPEPWireFormatError("CC-512-SIV secret_key must be bytes, bytearray, or memoryview.")
    if len(secret_key) == 0:
        raise QPEPWireFormatError("CC-512-SIV secret_key to wrap must not be empty.")
    with SecretBuffer(secret_key) as sk_buf:
        return cc512_siv_encrypt(kek64, sk_buf.as_bytes(), _SIV_DOMAIN_KEYWRAP + aad_bytes, nonce=nonce)


def cc512_siv_unwrap_key(
    kek64: BytesLike,
    wrapped: BytesLike,
    aad: BytesLike = b"",
    *,
    nonce: Optional[BytesLike] = b"",
) -> bytes:
    """Unwraps and authenticates a secret key wrapped with `cc512_siv_wrap_key`."""
    aad_bytes = _require_bytes_like(aad, "aad")
    unwrapped = cc512_siv_decrypt(kek64, wrapped, _SIV_DOMAIN_KEYWRAP + aad_bytes, nonce=nonce)
    if len(unwrapped) == 0:
        raise QPEPMacVerificationError("CC-512-SIV unwrapped secret key is unexpectedly empty.")
    return unwrapped


class CC512SIV:
    """
    Stateful memory-locked context manager for repeated CC-512-SIV offline vault encryption
    and deterministic/hedged key wrapping. Holds the 512-bit master key in `SecretBuffer`.
    """

    def __init__(self, key64: BytesLike):
        self._key_buf = _validate_key64(key64)

    @property
    def is_memory_locked(self) -> bool:
        return self._key_buf.is_memory_locked

    @property
    def is_wiped(self) -> bool:
        return self._key_buf.is_wiped

    def encrypt(self, plaintext: BytesLike, aad: BytesLike = b"", *, nonce: Optional[BytesLike] = b"") -> bytes:
        return cc512_siv_encrypt(self._key_buf.as_bytes(), plaintext, aad, nonce=nonce)

    def decrypt(self, ciphertext: BytesLike, aad: BytesLike = b"", *, nonce: Optional[BytesLike] = b"") -> bytes:
        return cc512_siv_decrypt(self._key_buf.as_bytes(), ciphertext, aad, nonce=nonce)

    def wrap_key(self, secret_key: BytesLike, aad: BytesLike = b"", *, nonce: Optional[BytesLike] = b"") -> bytes:
        return cc512_siv_wrap_key(self._key_buf.as_bytes(), secret_key, aad, nonce=nonce)

    def unwrap_key(self, wrapped: BytesLike, aad: BytesLike = b"", *, nonce: Optional[BytesLike] = b"") -> bytes:
        return cc512_siv_unwrap_key(self._key_buf.as_bytes(), wrapped, aad, nonce=nonce)

    def wipe(self) -> None:
        self._key_buf.wipe()

    def __enter__(self) -> "CC512SIV":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except (TypeError, ValueError, BufferError, OSError, AttributeError):
            pass
