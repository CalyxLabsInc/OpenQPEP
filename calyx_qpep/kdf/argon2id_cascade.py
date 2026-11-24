"""
OpenQPEP Memory-Hard QPKD-Argon2id + qSponge-512 Cascade Key Derivation (Official Release 1.2.3 / kdf_version: 4).

Clean-Slate Official Release 1.2.3 Policy (Zero Legacy Backwards Compatibility):
  - Mandatory `kdf_version: 4` across all `.qpkrf` private key rings and subkey envelopes.
  - All legacy pre-release key rings (`kdf_version: 1` Beta, `kdf_version: 2` Production Candidate,
    `kdf_version: 3` Release Candidate) are hard-rejected with `QPEPLegacyProtocolError`.
  - Uses bit-exact RFC 9106 Argon2id (version 0x13, type 2) across all three backends:
      1. `argon2id-rfc9106-cffi`    (argon2-cffi C reference library, preferred when installed)
      2. `argon2id-rfc9106-openssl` (OpenSSL 3.2+ native C Argon2id via `cryptography`, zero-extra-dep C fallback)
      3. `argon2id-rfc9106-pure-python` (100% bit-exact pure-Python RFC 9106 reference implementation)
    All three backends produce identical bit-for-bit output across all RFC 9106 vectors and OpenQPEP
    `.qpkrf` key rings, mixed with the mandatory 64-byte passphrase character-class witness and optional
    FIDO2-PRF hardware passkey secret output, cascaded through 24-round qSponge-512.
"""
import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple

from ..constants import MANDATORY_KDF_VERSION, PROTOCOL_VERSION
from ..exceptions import QPEPSuiteError
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer, zeroize_bytes
from .hardware_tuner import (
    HARD_CEILING_KDF_MEMORY_KIB,
    enforce_kdf_memory_ceiling,
    select_kdf_profile,
)
from .passphrase_policy import enforce_passphrase_policy

# ---------------------------------------------------------------------------
# Backend Detection: argon2-cffi (Priority 1) -> OpenSSL C Argon2id (Priority 2) -> Pure-Python RFC 9106
# ---------------------------------------------------------------------------
try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash_raw
    _HAS_ARGON2_CFFI = True
except ImportError:
    _HAS_ARGON2_CFFI = False

_HAS_OPENSSL_ARGON2 = False
_OpenSSLArgon2id: Any = None
try:
    from cryptography.exceptions import UnsupportedAlgorithm as _CryptoUnsupportedAlgorithm
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id as _ImportedOpenSSLArgon2id
    try:
        # Self-probe OpenSSL >= 3.2 Argon2id runtime support
        _ImportedOpenSSLArgon2id(
            salt=b"\x00" * 8,
            length=16,
            iterations=1,
            lanes=1,
            memory_cost=8,
        ).derive(b"probe")
        _OpenSSLArgon2id = _ImportedOpenSSLArgon2id
        _HAS_OPENSSL_ARGON2 = True
    except (_CryptoUnsupportedAlgorithm, ValueError, RuntimeError, OSError):
        _HAS_OPENSSL_ARGON2 = False
except ImportError:
    _HAS_OPENSSL_ARGON2 = False

BACKEND_CFFI = "argon2id-rfc9106-cffi"
BACKEND_OPENSSL = "argon2id-rfc9106-openssl"
BACKEND_PURE_PYTHON = "argon2id-rfc9106-pure-python"
VALID_KDF_BACKENDS = (BACKEND_CFFI, BACKEND_OPENSSL, BACKEND_PURE_PYTHON)

# RFC 9106 + Anti-DoS parameter boundaries
MIN_ARGON2_TIME_COST = 1
MAX_ARGON2_TIME_COST = 64
MIN_ARGON2_PARALLELISM = 1
MAX_ARGON2_PARALLELISM = 16
MAX_ARGON2_MEMORY_KIB = HARD_CEILING_KDF_MEMORY_KIB  # 1 GiB hard ceiling
MAX_PURE_PYTHON_ARGON2_KIB = 8192                    # 8 MiB pure-Python ceiling (no silent downgrade!)
MIN_ARGON2_HASH_LEN = 4
MAX_ARGON2_HASH_LEN = 1024
MIN_ARGON2_SALT_BYTES = 8
MAX_ARGON2_SALT_BYTES = 1024

# Official RFC 9106 Section 5.3 Argon2id Test Vector
RFC9106_SECTION_5_3_VECTOR: Dict[str, Any] = {
    "password": bytes([0x01] * 32),
    "salt": bytes([0x02] * 16),
    "secret": bytes([0x03] * 8),
    "associated_data": bytes([0x04] * 12),
    "time_cost": 3,
    "memory_cost": 32,
    "parallelism": 4,
    "hash_len": 32,
    "expected_hex": "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
}


def get_active_kdf_backend() -> str:
    """Returns the highest-priority active RFC 9106 Argon2id backend identifier."""
    if _HAS_ARGON2_CFFI:
        return BACKEND_CFFI
    if _HAS_OPENSSL_ARGON2:
        return BACKEND_OPENSSL
    return BACKEND_PURE_PYTHON


def get_available_kdf_backends() -> List[str]:
    """Returns all available RFC 9106 Argon2id backends on this host in priority order."""
    backends: List[str] = []
    if _HAS_ARGON2_CFFI:
        backends.append(BACKEND_CFFI)
    if _HAS_OPENSSL_ARGON2:
        backends.append(BACKEND_OPENSSL)
    backends.append(BACKEND_PURE_PYTHON)
    return backends


def validate_kdf_params(
    m_kib: Any,
    t_cost: Any,
    p_lanes: Any,
    *,
    hash_len: Any = 64,
    max_memory_kib: Optional[int] = None,
    enforce_ram_fraction: bool = False,
) -> Tuple[int, int, int, int]:
    """
    Strictly validates RFC 9106 Argon2id parameters against type confusion (including bool),
    RFC 9106 mathematical invariants (`m >= 8 * p`), and OpenQPEP anti-DoS ceilings.
    """
    for name, val in (("m_kib", m_kib), ("t_cost", t_cost), ("p_lanes", p_lanes), ("hash_len", hash_len)):
        if isinstance(val, bool) or not isinstance(val, int):
            raise QPEPSuiteError(f"QPKD-Argon2id parameter '{name}' must be an integer (not {type(val).__name__}).")

    if not (MIN_ARGON2_PARALLELISM <= p_lanes <= MAX_ARGON2_PARALLELISM):
        raise QPEPSuiteError(
            f"QPKD-Argon2id p_lanes={p_lanes} out of bounds [{MIN_ARGON2_PARALLELISM}, {MAX_ARGON2_PARALLELISM}]."
        )
    if not (MIN_ARGON2_TIME_COST <= t_cost <= MAX_ARGON2_TIME_COST):
        raise QPEPSuiteError(
            f"QPKD-Argon2id t_cost={t_cost} out of bounds [{MIN_ARGON2_TIME_COST}, {MAX_ARGON2_TIME_COST}]."
        )
    if not (MIN_ARGON2_HASH_LEN <= hash_len <= MAX_ARGON2_HASH_LEN):
        raise QPEPSuiteError(
            f"QPKD-Argon2id hash_len={hash_len} out of bounds [{MIN_ARGON2_HASH_LEN}, {MAX_ARGON2_HASH_LEN}]."
        )
    min_rfc_m = 8 * p_lanes
    if m_kib < min_rfc_m:
        raise QPEPSuiteError(
            f"QPKD-Argon2id m_kib={m_kib} violates RFC 9106 minimum 8 * p_lanes ({min_rfc_m})."
        )

    effective_max = MAX_ARGON2_MEMORY_KIB if max_memory_kib is None else max_memory_kib
    enforce_kdf_memory_ceiling(
        m_kib,
        max_memory_kib=effective_max,
        enforce_ram_fraction=enforce_ram_fraction,
    )
    return m_kib, t_cost, p_lanes, hash_len


# ---------------------------------------------------------------------------
# Pure-Python Bit-Exact RFC 9106 Argon2id Implementation (BLAKE2b + H' + G)
# ---------------------------------------------------------------------------
_MASK64 = 0xFFFFFFFFFFFFFFFF
_ARGON2_VERSION = 0x13
_ARGON2_TYPE_ID = 2
_SYNC_POINTS = 4
_ADDRESSES_IN_BLOCK = 128
_ZERO_BLOCK_TUPLE = (0,) * 128
_COL_IDXS = tuple(
    tuple(16 * k + 2 * col + off for k in range(8) for off in (0, 1))
    for col in range(8)
)


def _rotr64(x: int, n: int) -> int:
    return ((x >> n) | ((x << (64 - n)) & _MASK64)) & _MASK64


def _fblamka(x: int, y: int) -> int:
    m = (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF)
    return (x + y + ((m << 1) & _MASK64)) & _MASK64


def _gb(v: List[int], a: int, b: int, c: int, d: int) -> None:
    v[a] = _fblamka(v[a], v[b]); v[d] = _rotr64(v[d] ^ v[a], 32)
    v[c] = _fblamka(v[c], v[d]); v[b] = _rotr64(v[b] ^ v[c], 24)
    v[a] = _fblamka(v[a], v[b]); v[d] = _rotr64(v[d] ^ v[a], 16)
    v[c] = _fblamka(v[c], v[d]); v[b] = _rotr64(v[b] ^ v[c], 63)


def _permute_p(s: List[int]) -> None:
    _gb(s, 0, 4, 8, 12); _gb(s, 1, 5, 9, 13); _gb(s, 2, 6, 10, 14); _gb(s, 3, 7, 11, 15)
    _gb(s, 0, 5, 10, 15); _gb(s, 1, 6, 11, 12); _gb(s, 2, 7, 8, 13); _gb(s, 3, 4, 9, 14)


def _blake2b_long(data: bytes, out_len: int) -> bytes:
    """RFC 9106 Section 3.3 variable-length hash H'."""
    prefix = struct.pack("<I", out_len)
    if out_len <= 64:
        return hashlib.blake2b(prefix + data, digest_size=out_len).digest()
    r = (out_len + 31) // 32 - 2
    v = hashlib.blake2b(prefix + data, digest_size=64).digest()
    out = bytearray(v[:32])
    try:
        for _ in range(1, r):
            v = hashlib.blake2b(v, digest_size=64).digest()
            out.extend(v[:32])
        rem = out_len - 32 * r
        v = hashlib.blake2b(v, digest_size=rem).digest()
        out.extend(v)
        return bytes(out)
    finally:
        zeroize_bytes(out)


def _compress_block(x_block: List[int], y_block: List[int]) -> List[int]:
    """RFC 9106 Section 3.5 compression function G(X, Y) over 128 x uint64 words (1024 B)."""
    r = [x_block[i] ^ y_block[i] for i in range(128)]
    z = r[:]
    for row in range(8):
        base = row * 16
        chunk = z[base : base + 16]
        _permute_p(chunk)
        z[base : base + 16] = chunk
    for idxs in _COL_IDXS:
        chunk = [z[i] for i in idxs]
        _permute_p(chunk)
        for pos, i in enumerate(idxs):
            z[i] = chunk[pos]
    return [z[i] ^ r[i] for i in range(128)]


def _next_argon2i_addresses(input_block: List[int], zero_block: List[int]) -> List[int]:
    """
    RFC 9106 Section 3.4.1.2 data-independent address block generator:
      input_block[6] += 1
      return G(ZERO, G(ZERO, input_block))
    """
    input_block[6] = (input_block[6] + 1) & _MASK64
    tmp = _compress_block(zero_block, input_block)
    try:
        return _compress_block(zero_block, tmp)
    finally:
        for w in range(128):
            tmp[w] = 0


def _argon2id_pure_python(
    password: bytes,
    salt: bytes,
    *,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int = 64,
    associated_data: bytes = b"",
    secret: bytes = b"",
    allow_slow_pure_python: bool = False,
) -> bytes:
    """
    100% Bit-Exact Pure-Python RFC 9106 Argon2id (version 0x13, type 2) reference implementation.
      - Uses authentic Argon2id hybrid addressing: data-independent (Argon2i) in pass 0 slices 0..1,
        and data-dependent (Argon2d) in pass 0 slices 2..3 and all subsequent passes.
      - Implements exact RFC 9106 Section 3.4.2 reference window |W| and start_pos calculation.
      - NEVER silently downgrades memory_cost: raises QPEPSuiteError if memory_cost exceeds
        MAX_PURE_PYTHON_ARGON2_KIB unless `allow_slow_pure_python=True`.
      - Explicitly wipes all working lanes, address blocks, and H_0 buffers on exit.
    """
    m, t, p, out_len = validate_kdf_params(
        memory_cost,
        time_cost,
        parallelism,
        hash_len=hash_len,
    )
    if not allow_slow_pure_python and m > MAX_PURE_PYTHON_ARGON2_KIB:
        raise QPEPSuiteError(
            f"Pure-Python RFC 9106 Argon2id refuses to silently downgrade m_kib={m} "
            f"(exceeds pure-Python ceiling {MAX_PURE_PYTHON_ARGON2_KIB} KiB). "
            f"Install 'argon2-cffi>=23.1.0' or 'cryptography>=44.0.0' (OpenSSL 3.2+), "
            f"or pass allow_slow_pure_python=True explicitly."
        )

    # RFC 9106 Section 3.2: m' = 4 * p * floor(m / (4 * p)), q = m' / p, segment_length = q / 4
    m_prime = 4 * p * (m // (4 * p))
    q = m_prime // p
    seg_len = q // _SYNC_POINTS

    h0_buf = bytearray(
        struct.pack("<IIIIII", p, out_len, m, t, _ARGON2_VERSION, _ARGON2_TYPE_ID)
        + struct.pack("<I", len(password)) + password
        + struct.pack("<I", len(salt)) + salt
        + struct.pack("<I", len(secret)) + secret
        + struct.pack("<I", len(associated_data)) + associated_data
    )
    lanes: List[List[List[int]]] = [[[0] * 128 for _ in range(q)] for _ in range(p)]
    final_blk: List[int] = [0] * 128
    zero_blk: List[int] = list(_ZERO_BLOCK_TUPLE)
    addr_input: List[int] = [0] * 128
    addr_blk: List[int] = [0] * 128
    try:
        with SecretBuffer(h0_buf) as h0_in_sb:
            h0 = hashlib.blake2b(h0_in_sb.raw, digest_size=64).digest()
        zeroize_bytes(h0_buf)

        with SecretBuffer(h0) as h0_sb:
            h0_raw = h0_sb.as_bytes()
            for lane in range(p):
                b0 = _blake2b_long(h0_raw + struct.pack("<II", 0, lane), 1024)
                b1 = _blake2b_long(h0_raw + struct.pack("<II", 1, lane), 1024)
                lanes[lane][0] = list(struct.unpack("<128Q", b0))
                lanes[lane][1] = list(struct.unpack("<128Q", b1))

        for pass_num in range(t):
            for slice_idx in range(_SYNC_POINTS):
                data_independent = (pass_num == 0 and slice_idx < 2)
                start_pos = 0 if (pass_num == 0 or slice_idx == 3) else ((slice_idx + 1) * seg_len)
                for lane in range(p):
                    start_idx = 2 if (pass_num == 0 and slice_idx == 0) else 0
                    if data_independent:
                        for w in range(128):
                            addr_input[w] = 0
                        addr_input[0] = pass_num
                        addr_input[1] = lane
                        addr_input[2] = slice_idx
                        addr_input[3] = m_prime
                        addr_input[4] = t
                        addr_input[5] = _ARGON2_TYPE_ID
                        addr_input[6] = 0
                        if start_idx == 2:
                            addr_blk = _next_argon2i_addresses(addr_input, zero_blk)

                    for idx in range(start_idx, seg_len):
                        curr = slice_idx * seg_len + idx
                        prev = (curr - 1) if curr > 0 else (q - 1)
                        prev_blk = lanes[lane][prev]

                        if data_independent:
                            slot = idx % _ADDRESSES_IN_BLOCK
                            if slot == 0:
                                addr_blk = _next_argon2i_addresses(addr_input, zero_blk)
                            pseudo_rand = addr_blk[slot]
                        else:
                            pseudo_rand = prev_blk[0]

                        j1 = pseudo_rand & 0xFFFFFFFF
                        j2 = (pseudo_rand >> 32) & 0xFFFFFFFF
                        ref_lane = lane if (pass_num == 0 and slice_idx == 0) else (j2 % p)
                        same_lane = (ref_lane == lane)

                        if pass_num == 0:
                            if slice_idx == 0:
                                ref_area = idx - 1
                            elif same_lane:
                                ref_area = slice_idx * seg_len + idx - 1
                            else:
                                ref_area = slice_idx * seg_len - (1 if idx == 0 else 0)
                        else:
                            if same_lane:
                                ref_area = q - seg_len + idx - 1
                            else:
                                ref_area = q - seg_len - (1 if idx == 0 else 0)

                        rel = (j1 * j1) >> 32
                        rel = ref_area - 1 - ((ref_area * rel) >> 32)
                        ref_idx = (start_pos + rel) % q

                        new_blk = _compress_block(prev_blk, lanes[ref_lane][ref_idx])
                        if pass_num == 0:
                            lanes[lane][curr] = new_blk
                        else:
                            old_blk = lanes[lane][curr]
                            for w in range(128):
                                old_blk[w] ^= new_blk[w]
                            for w in range(128):
                                new_blk[w] = 0

        for w in range(128):
            final_blk[w] = lanes[0][q - 1][w]
        for lane in range(1, p):
            lb = lanes[lane][q - 1]
            for w in range(128):
                final_blk[w] ^= lb[w]
        with SecretBuffer(struct.pack("<128Q", *final_blk)) as fb_sb:
            return _blake2b_long(fb_sb.as_bytes(), out_len)
    finally:
        zeroize_bytes(h0_buf)
        for lane_arr in lanes:
            for blk in lane_arr:
                for w in range(len(blk)):
                    blk[w] = 0
        for w in range(128):
            final_blk[w] = 0
            addr_input[w] = 0
            addr_blk[w] = 0


def argon2id_raw(
    password: bytes,
    salt: bytes,
    *,
    m_kib: int,
    t_cost: int,
    p_lanes: int,
    out_len: int = 64,
    associated_data: bytes = b"",
    secret: bytes = b"",
    backend: Optional[str] = None,
    strict_backend: bool = True,
    max_memory_kib: Optional[int] = None,
    allow_slow_pure_python: bool = False,
) -> Tuple[bytes, str]:
    """
    Canonical OpenQPEP RFC 9106 Argon2id entrypoint with bit-exact parity across:
      - `argon2id-rfc9106-cffi` (argon2-cffi)
      - `argon2id-rfc9106-openssl` (OpenSSL 3.2+ via cryptography)
      - `argon2id-rfc9106-pure-python` (Pure-Python RFC 9106 reference)
    """
    if not isinstance(password, (bytes, bytearray)):
        raise QPEPSuiteError("Argon2id password must be bytes or bytearray.")
    if not isinstance(salt, (bytes, bytearray)) or not (MIN_ARGON2_SALT_BYTES <= len(salt) <= MAX_ARGON2_SALT_BYTES):
        raise QPEPSuiteError(
            f"Argon2id salt must be between {MIN_ARGON2_SALT_BYTES} and {MAX_ARGON2_SALT_BYTES} bytes."
        )
    if not isinstance(associated_data, (bytes, bytearray)):
        raise QPEPSuiteError("Argon2id associated_data must be bytes or bytearray.")
    if not isinstance(secret, (bytes, bytearray)):
        raise QPEPSuiteError("Argon2id secret must be bytes or bytearray.")

    m, t, p, hlen = validate_kdf_params(
        m_kib,
        t_cost,
        p_lanes,
        hash_len=out_len,
        max_memory_kib=max_memory_kib,
    )
    pw_b = bytes(password)
    salt_b = bytes(salt)
    ad_b = bytes(associated_data)
    sec_b = bytes(secret)
    has_ad_or_secret = bool(ad_b or sec_b)

    if backend is not None and backend not in VALID_KDF_BACKENDS:
        raise QPEPSuiteError(f"Unsupported Argon2id backend '{backend}'. Expected one of {VALID_KDF_BACKENDS}.")

    # Explicit pure-Python request is always honored directly
    if backend == BACKEND_PURE_PYTHON:
        raw = _argon2id_pure_python(
            password=pw_b,
            salt=salt_b,
            time_cost=t,
            memory_cost=m,
            parallelism=p,
            hash_len=hlen,
            associated_data=ad_b,
            secret=sec_b,
            allow_slow_pure_python=allow_slow_pure_python,
        )
        return raw, BACKEND_PURE_PYTHON

    if backend == BACKEND_CFFI:
        if has_ad_or_secret:
            if strict_backend:
                raise QPEPSuiteError(
                    "argon2id-rfc9106-cffi hash_secret_raw does not support non-empty associated_data or secret."
                )
        elif _HAS_ARGON2_CFFI:
            raw = _argon2_hash_raw(
                secret=pw_b,
                salt=salt_b,
                time_cost=t,
                memory_cost=m,
                parallelism=p,
                hash_len=hlen,
                type=_Argon2Type.ID,
            )
            return raw, BACKEND_CFFI
        elif strict_backend:
            raise QPEPSuiteError("Requested backend 'argon2id-rfc9106-cffi' is not installed.")

    if backend == BACKEND_OPENSSL:
        if _HAS_OPENSSL_ARGON2:
            raw = _OpenSSLArgon2id(
                salt=salt_b,
                length=hlen,
                iterations=t,
                lanes=p,
                memory_cost=m,
                ad=ad_b if ad_b else None,
                secret=sec_b if sec_b else None,
            ).derive(pw_b)
            return raw, BACKEND_OPENSSL
        if strict_backend:
            raise QPEPSuiteError("Requested backend 'argon2id-rfc9106-openssl' is not available on this host.")

    # Auto-selection (or bit-exact cross-backend fallback when strict_backend=False)
    if not has_ad_or_secret and _HAS_ARGON2_CFFI:
        raw = _argon2_hash_raw(
            secret=pw_b,
            salt=salt_b,
            time_cost=t,
            memory_cost=m,
            parallelism=p,
            hash_len=hlen,
            type=_Argon2Type.ID,
        )
        return raw, BACKEND_CFFI

    if _HAS_OPENSSL_ARGON2:
        raw = _OpenSSLArgon2id(
            salt=salt_b,
            length=hlen,
            iterations=t,
            lanes=p,
            memory_cost=m,
            ad=ad_b if ad_b else None,
            secret=sec_b if sec_b else None,
        ).derive(pw_b)
        return raw, BACKEND_OPENSSL

    raw = _argon2id_pure_python(
        password=pw_b,
        salt=salt_b,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=hlen,
        associated_data=ad_b,
        secret=sec_b,
        allow_slow_pure_python=allow_slow_pure_python,
    )
    return raw, BACKEND_PURE_PYTHON


def _memory_hard_argon2id_raw(
    secret_bytes: bytes,
    salt: bytes,
    *,
    m_kib: int,
    t_cost: int,
    p_lanes: int,
    out_len: int = 64,
    backend_override: Optional[str] = None,
    max_memory_kib: Optional[int] = None,
) -> Tuple[bytes, str]:
    """
    Executes bit-exact RFC 9106 Argon2id for OpenQPEP QPKD-Argon2id (kdf_version: 4).
    Because all three backends compute identical RFC 9106 Argon2id (ad=b"", secret=b""),
    a keyring wrapped under argon2-cffi unlocks transparently under OpenSSL C Argon2id
    or Pure-Python RFC 9106 (and vice versa).
    """
    return argon2id_raw(
        password=secret_bytes,
        salt=salt,
        m_kib=m_kib,
        t_cost=t_cost,
        p_lanes=p_lanes,
        out_len=out_len,
        associated_data=b"",
        secret=b"",
        backend=backend_override,
        strict_backend=(backend_override == BACKEND_PURE_PYTHON),
        max_memory_kib=max_memory_kib,
    )


def verify_argon2id_backend_parity() -> Dict[str, Any]:
    """
    Self-verifies bit-exact RFC 9106 Argon2id parity across all available backends on this host:
      1. Official RFC 9106 Section 5.3 Argon2id test vector (pure-Python + OpenSSL C when available).
      2. OpenQPEP multi-parameter differential matrix (varying m_kib, t_cost, p_lanes, out_len)
         comparing every available C backend (argon2-cffi / OpenSSL) against Pure-Python RFC 9106.
    """
    vec = RFC9106_SECTION_5_3_VECTOR
    py_rfc_raw, _ = argon2id_raw(
        vec["password"],
        vec["salt"],
        m_kib=vec["memory_cost"],
        t_cost=vec["time_cost"],
        p_lanes=vec["parallelism"],
        out_len=vec["hash_len"],
        associated_data=vec["associated_data"],
        secret=vec["secret"],
        backend=BACKEND_PURE_PYTHON,
    )
    rfc_matches: Dict[str, bool] = {
        BACKEND_PURE_PYTHON: (py_rfc_raw.hex() == vec["expected_hex"]),
    }
    if _HAS_OPENSSL_ARGON2:
        ossl_rfc_raw, _ = argon2id_raw(
            vec["password"],
            vec["salt"],
            m_kib=vec["memory_cost"],
            t_cost=vec["time_cost"],
            p_lanes=vec["parallelism"],
            out_len=vec["hash_len"],
            associated_data=vec["associated_data"],
            secret=vec["secret"],
            backend=BACKEND_OPENSSL,
        )
        rfc_matches[BACKEND_OPENSSL] = (ossl_rfc_raw.hex() == vec["expected_hex"])

    matrix_cases = [
        {"m_kib": 32, "t_cost": 1, "p_lanes": 1, "out_len": 32},
        {"m_kib": 64, "t_cost": 2, "p_lanes": 2, "out_len": 64},
        {"m_kib": 100, "t_cost": 3, "p_lanes": 4, "out_len": 64},
        {"m_kib": 256, "t_cost": 2, "p_lanes": 4, "out_len": 64},
    ]
    c_backends = [b for b in get_available_kdf_backends() if b != BACKEND_PURE_PYTHON]
    parity_ok = all(rfc_matches.values())
    cases_checked = 0

    for idx, case in enumerate(matrix_cases):
        pw = f"CALYX-PARITY-PW-{idx}".encode("ascii")
        salt = bytes([(idx * 37 + j) & 0xFF for j in range(32)])
        py_out, _ = argon2id_raw(pw, salt, backend=BACKEND_PURE_PYTHON, **case)
        for cb in c_backends:
            c_out, _ = argon2id_raw(pw, salt, backend=cb, **case)
            if c_out != py_out:
                parity_ok = False
        cases_checked += 1

    return {
        "parity_verified": parity_ok,
        "active_backend": get_active_kdf_backend(),
        "available_backends": get_available_kdf_backends(),
        "rfc9106_section_5_3": rfc_matches,
        "differential_cases_checked": cases_checked,
    }


def derive_qpkrf_keys_v4(
    passphrase: str,
    salt: bytes,
    *,
    qlx_tier: str = "QLX-4096",
    kdf_params: Optional[Dict[str, Any]] = None,
    fido2_prf_secret: Optional[bytes] = None,
    max_memory_kib: Optional[int] = None,
) -> Tuple[bytes, bytes, bytes, Dict[str, Any]]:
    """
    OpenQPEP Official Release 1.2.3 Mandatory Memory-Hard Key Derivation (kdf_version: 4):
      1. Enforces mandatory passphrase policy and extracts the 64-byte structural witness.
      2. Mixes optional FIDO2-PRF hardware passkey secret (when hardware-bound).
      3. Strictly validates KDF memory/time/lane bounds against OOM & CPU-bomb ceilings.
      4. Derives 64-byte root key via bit-exact RFC 9106 Argon2id (cffi / OpenSSL / pure-Python).
      5. Cascades through 24-round qSponge-512 (SHA3-512) into independent (k_s1, k_s2, k_mac).
      6. Actively scrubs intermediate root key material via SecretBuffer.
    """
    if not isinstance(salt, (bytes, bytearray)) or not (16 <= len(salt) <= MAX_ARGON2_SALT_BYTES):
        raise QPEPSuiteError(
            f"QPKD-Argon2id (kdf_version: 4) requires a salt of 16..{MAX_ARGON2_SALT_BYTES} bytes."
        )

    witness = enforce_passphrase_policy(passphrase)
    if kdf_params is not None:
        if not isinstance(kdf_params, dict):
            raise QPEPSuiteError("QPKD-Argon2id kdf_params must be a dictionary.")
        raw_m = kdf_params.get("m_kib", 65536)
        raw_t = kdf_params.get("t_cost", 3)
        raw_p = kdf_params.get("p_lanes", 4)
        m_kib, t_cost, p_lanes, _ = validate_kdf_params(
            raw_m, raw_t, raw_p, hash_len=64, max_memory_kib=max_memory_kib,
        )
        profile_name = str(kdf_params.get("hardware_profile", "custom"))
        backend_req = kdf_params.get("backend")
        if backend_req is not None and not isinstance(backend_req, str):
            raise QPEPSuiteError("QPKD-Argon2id kdf_params['backend'] must be a string or None.")
    else:
        profile = select_kdf_profile(qlx_tier, max_memory_kib=max_memory_kib)
        m_kib = profile.m_kib
        t_cost = profile.t_cost
        p_lanes = profile.p_lanes
        profile_name = profile.profile_name
        backend_req = None

    hw_mix_buf = bytearray()
    fido2_bound = False
    if fido2_prf_secret is not None:
        if not isinstance(fido2_prf_secret, (bytes, bytearray)) or len(fido2_prf_secret) < 32:
            raise QPEPSuiteError("FIDO2-PRF hardware secret must be bytes of at least 32 bytes.")
        hw_mix_buf.extend(b"|FIDO2-PRF-v1.0.0|")
        hw_mix_buf.extend(fido2_prf_secret)
        fido2_bound = True

    ikm_staging = bytearray(b"CALYX-QPKD-ARGON2ID-v4-1.0.0|")
    try:
        with SecretBuffer(witness) as witness_buf:
            ikm_staging.extend(passphrase.encode("utf-8"))
            ikm_staging.extend(b"|")
            ikm_staging.extend(witness_buf.raw)
            if hw_mix_buf:
                ikm_staging.extend(hw_mix_buf)
        with SecretBuffer(ikm_staging) as ikm_buf:
            zeroize_bytes(ikm_staging)
            zeroize_bytes(hw_mix_buf)
            argon_root, active_backend = _memory_hard_argon2id_raw(
                ikm_buf.as_bytes(),
                bytes(salt),
                m_kib=m_kib,
                t_cost=t_cost,
                p_lanes=p_lanes,
                out_len=64,
                backend_override=backend_req,
                max_memory_kib=max_memory_kib,
            )
    finally:
        zeroize_bytes(ikm_staging)
        zeroize_bytes(hw_mix_buf)

    with SecretBuffer(argon_root) as root_buf:
        rb = root_buf.as_bytes()
        k_s1 = qsponge_512(b"CALYX-QPKRF-V4-1.0.0-KS1|" + rb + bytes(salt))[:32]
        k_s2 = qsponge_512(b"CALYX-QPKRF-V4-1.0.0-KS2|" + rb + bytes(salt))[:32]
        k_mac = qsponge_512(b"CALYX-QPKRF-V4-1.0.0-KMAC|" + rb + bytes(salt))

    effective_params: Dict[str, Any] = {
        "kdf_version": MANDATORY_KDF_VERSION,
        "algorithm": "QPKD-Argon2id+qSponge-512",
        "personalization": PROTOCOL_VERSION,
        "backend": active_backend,
        "hardware_profile": profile_name,
        "m_kib": m_kib,
        "t_cost": t_cost,
        "p_lanes": p_lanes,
        "fido2_prf_bound": fido2_bound,
    }
    return k_s1, k_s2, k_mac, effective_params
