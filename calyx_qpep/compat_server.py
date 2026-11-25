"""
OpenQPEP Official Release 1.2.5 — Shared Server Compatibility & Security Adapter (`calyx_qpep.compat_server`).

Provides a single canonical implementation of common server-side security primitives used across
Directory_Server, Messenger_Server, CalyxMail_Backend, and Website_Server:
  1. Thread-safe sliding-window per-IP / per-key rate limiting (`SlidingWindowRateLimiter`).
  2. Strict Wire Format v5 (\\x89QPE\\x05\\x00) frame MAC & whitening verification.
  3. Canonical pre-release version-token rejection (`-rc`, `-pc`, `-beta`, `0.x`) while preserving
     100% compatibility across all Official Stable Public Releases (`1.0.0`, `1.0.2`, `1.1.0`, `1.2.5`, ...).
  4. Canonical CMT-4 Key-Committing CC-512 AEAD and `.qpkrf` directory verification helpers.
"""
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, Optional, Tuple

from .constants import (
    ALL_LEGACY_WIRE_MAGICS,
    MANDATORY_KDF_VERSION,
    MAX_ARMOR_BYTES,
    MAX_WIRE_FRAME_BYTES,
    PROTOCOL_VERSION,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    WIRE_MAGIC_V5,
    WIRE_MAGIC_V5_1,
)
from .exceptions import (
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPWireFormatError,
)
from .primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from .protocol import OpenQPEPProtocol, QPEPKeyRing
from .wire.framing import pack_wire_frame, unpack_wire_frame


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding-window rate limiter keyed by client IP / endpoint bucket.
    Automatically prunes expired entries to keep RAM bounded under sustained flood traffic.
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0, max_buckets: int = 16384):
        if max_requests <= 0 or window_seconds <= 0 or max_buckets <= 0:
            raise ValueError("max_requests, window_seconds, and max_buckets must be positive.")
        self.max_requests = int(max_requests)
        self.window_seconds = float(window_seconds)
        self.max_buckets = int(max_buckets)
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = {}

    def allow(self, key: str, now: Optional[float] = None) -> Tuple[bool, int, int]:
        """
        Checks whether `key` may proceed.
        Returns `(allowed, remaining, retry_after_seconds)`.
        """
        if not isinstance(key, str) or not key or len(key) > 256:
            raise QPEPWireFormatError("Rate-limiter bucket key must be a non-empty string (<= 256 chars).")
        ts = time.monotonic() if now is None else float(now)
        cutoff = ts - self.window_seconds
        with self._lock:
            if len(self._buckets) >= self.max_buckets and key not in self._buckets:
                stale = [k for k, dq in self._buckets.items() if not dq or dq[-1] <= cutoff]
                for k in stale:
                    del self._buckets[k]
                # Bounded-RAM flood defense: if all buckets are still active, evict oldest bucket
                if len(self._buckets) >= self.max_buckets:
                    oldest_key = min(self._buckets.items(), key=lambda kv: kv[1][-1] if kv[1] else -1.0)[0]
                    del self._buckets[oldest_key]
            dq = self._buckets.get(key)
            if dq is None:
                dq = deque()
                self._buckets[key] = dq
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= self.max_requests:
                retry_after = max(1, int(self.window_seconds - (ts - dq[0])) + 1)
                return False, 0, retry_after
            dq.append(ts)
            remaining = max(0, self.max_requests - len(dq))
            return True, remaining, 0

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


def is_legacy_prerelease_version(version_str: str) -> bool:
    """
    Returns True if `version_str` identifies a retired pre-release (`-rc`, `-pc`, `-beta`, `0.x`).
    Official stable public releases (`1.0.0`, `1.0.1`, `1.0.2`, `1.1.0`, `1.2.5`, ...) return False.
    """
    if not isinstance(version_str, str):
        return False
    low = version_str.strip().lower()
    if not low:
        return False
    # Strip optional 'openqpep/' or 'v' prefix
    if low.startswith("openqpep/"):
        low = low[len("openqpep/"):]
    if low.startswith("v"):
        low = low[1:]
    return (
        "-rc" in low
        or "-pc" in low
        or "-beta" in low
        or "release candidate" in low
        or "production candidate" in low
        or low.startswith("0.")
    )


def reject_legacy_version_token(version_str: str) -> None:
    """Raises QPEPLegacyProtocolError if `version_str` belongs to a retired pre-release."""
    if is_legacy_prerelease_version(version_str):
        raise QPEPLegacyProtocolError(
            f"Legacy pre-release version '{version_str}' is strictly rejected in "
            f"OpenQPEP {UNIVERSAL_VERSION_LABEL} (zero pre-release compatibility)."
        )


def verify_wire_v5_frame_strict(frame: bytes, label: str) -> Tuple[bytes, int]:
    """
    Verifies and unpacks an Official Wire Format v5 (\\x89QPE\\x05\\x00) binary frame.
    Compatible with all v1.0.x and v1.1.x frames; raises QPEPLegacyProtocolError for v1..v4
    and QPEPMacVerificationError on MAC mismatch.
    """
    if not isinstance(frame, (bytes, bytearray)) or len(frame) > MAX_WIRE_FRAME_BYTES:
        raise QPEPWireFormatError("Wire v5 frame must be bytes within MAX_WIRE_FRAME_BYTES.")
    if not isinstance(label, str) or not label.strip() or len(label) > 128:
        raise QPEPWireFormatError("Wire v5 frame label must be a non-empty ASCII string (<= 128 chars).")
    return unpack_wire_frame(bytes(frame), label)


def verify_qpkrf_for_directory(public_qpkrf: str) -> Tuple[QPEPKeyRing, Dict[str, Any]]:
    """
    Validates a public .qpkrf key ring for directory publication:
      - Strictly enforces Wire Format v5 (\\x89QPE\\x05\\x00) + mandatory 48-bit armor CRC.
      - Rejects private key rings and legacy pre-release versions.
      - Verifies 512-bit integrity_mac and hybrid Ed448 + QVS self-certification signature.
    """
    if not isinstance(public_qpkrf, str) or not public_qpkrf.strip() or len(public_qpkrf) > MAX_ARMOR_BYTES:
        raise QPEPWireFormatError("Public .qpkrf input must be a non-empty armored string within MAX_ARMOR_BYTES.")
    kr = OpenQPEPProtocol.import_qpkrf(public_qpkrf)
    if kr.has_private_key:
        raise QPEPWireFormatError("Private .qpkrf key rings must NEVER be published to a public directory.")
    if not OpenQPEPProtocol.verify_public_keyring_self_signature(kr):
        raise QPEPMacVerificationError("QPKRF self-certification signature verification failed.")
    summary = {
        "key_hash": kr.key_hash,
        "name": kr.name,
        "email": kr.email,
        "qlx_tier": kr.qlx_tier,
        "qvs_tier": kr.qvs_tier,
        "suite_id": OpenQPEPProtocol.get_keyring_suite_id(kr),
        "protocol_version": PROTOCOL_VERSION,
        "kdf_version": MANDATORY_KDF_VERSION,
        "wire_magic_hex": WIRE_MAGIC_V5.hex().upper(),
    }
    return kr, summary


__all__ = [
    "SlidingWindowRateLimiter",
    "is_legacy_prerelease_version",
    "reject_legacy_version_token",
    "verify_wire_v5_frame_strict",
    "verify_qpkrf_for_directory",
    "pack_wire_frame",
    "unpack_wire_frame",
    "cc512_encrypt",
    "cc512_decrypt",
    "ALL_LEGACY_WIRE_MAGICS",
    "WIRE_MAGIC_V5",
    "WIRE_MAGIC_V5_1",
    "UNIVERSAL_VERSION",
    "UNIVERSAL_VERSION_LABEL",
    "PROTOCOL_VERSION",
]
