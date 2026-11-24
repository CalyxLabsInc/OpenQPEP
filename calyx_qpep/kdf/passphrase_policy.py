"""
Calyx QPEP Hardcoded Cryptographic Passphrase Gate (QPKD-Argon2id — Official Release 1.1.7).

In OpenQPEP, passphrases are NOT merely an optional UI check: the structural character-class
witness of the passphrase (length >= 12, digits >= 2, specials >= 4, uppercase >= 2, lowercase >= 4)
is mathematically absorbed into the QPKD-Argon2id key-derivation sponge. Without a compliant passphrase,
the mathematical witness vector cannot be constructed and no key material can be derived or unlocked.

v1.1.7 Hardening:
  - Enforces strict upper length ceiling (MAX_LENGTH = 1024 chars / MAX_PASSPHRASE_UTF8_BYTES = 4096)
    to prevent memory/CPU DoS in witness & Argon2id H_0 construction.
  - Rejects NUL bytes, ASCII C0/C1 control characters, and Unicode Bidi-override/format spoofing
    characters (preventing invisible-character special-count bypasses & C-FFI truncation bugs).
  - Actively zeroizes plaintext passphrase witness staging buffers via SecretBuffer + zeroize_bytes.
  - Provides conservative entropy estimation (estimate_passphrase_entropy_bits) and strength tiers
    while preserving 100% bit-exact CALYX-QPEP-HARDCODED-POLICY-WITNESS-v1.0.0 compatibility.
"""
import hashlib
import math
import unicodedata
from dataclasses import dataclass
from typing import List

from ..exceptions import QPEPPassphrasePolicyError
from ..primitives.zeroize import SecretBuffer, zeroize_bytes

MIN_LENGTH = 12
MAX_LENGTH = 1024
MAX_PASSPHRASE_UTF8_BYTES = 4096
MIN_DIGITS = 2
MIN_SPECIALS = 4
MIN_UPPERCASE = 2
MIN_LOWERCASE = 4

_BIDI_OVERRIDE_CODEPOINTS = frozenset({
    0x061C,  # ARABIC LETTER MARK
    0x200E,  # LEFT-TO-RIGHT MARK
    0x200F,  # RIGHT-TO-LEFT MARK
    0x202A,  # LEFT-TO-RIGHT EMBEDDING
    0x202B,  # RIGHT-TO-LEFT EMBEDDING
    0x202C,  # POP DIRECTIONAL FORMATTING
    0x202D,  # LEFT-TO-RIGHT OVERRIDE
    0x202E,  # RIGHT-TO-LEFT OVERRIDE
    0x2066,  # LEFT-TO-RIGHT ISOLATE
    0x2067,  # RIGHT-TO-LEFT ISOLATE
    0x2068,  # FIRST STRONG ISOLATE
    0x2069,  # POP DIRECTIONAL ISOLATE
})


def _has_disallowed_passphrase_chars(passphrase: str) -> bool:
    """Rejects NUL, C0/C1 control chars, Unicode surrogates, and Bidi-override/format characters."""
    for ch in passphrase:
        cp = ord(ch)
        if cp < 0x20 or (0x7F <= cp <= 0x9F):
            return True
        if 0xD800 <= cp <= 0xDFFF:
            return True
        if cp in _BIDI_OVERRIDE_CODEPOINTS:
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs"):
            return True
    return False


def estimate_passphrase_entropy_bits(passphrase: str) -> float:
    """
    Conservative passphrase entropy estimator (bits) combining character-pool cardinality
    and Shannon diversity with penalties for repeated characters and sequential runs.
    """
    if not isinstance(passphrase, str) or not passphrase:
        return 0.0

    has_lower = any("a" <= c <= "z" for c in passphrase)
    has_upper = any("A" <= c <= "Z" for c in passphrase)
    has_digit = any("0" <= c <= "9" for c in passphrase)
    has_ascii_special = any(
        0x20 <= ord(c) <= 0x7E and not ("0" <= c <= "9" or "A" <= c <= "Z" or "a" <= c <= "z")
        for c in passphrase
    )
    has_unicode = any(ord(c) > 0x7E for c in passphrase)

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_ascii_special:
        pool += 33
    if has_unicode:
        pool += 64
    if pool <= 1:
        return 0.0

    # Penalize immediate repeats and +/-1 sequential character runs (e.g., "aaaa", "1234")
    effective_len = 0.0
    prev_cp = -999
    for idx, ch in enumerate(passphrase):
        cp = ord(ch)
        if idx > 0 and cp == prev_cp:
            effective_len += 0.25
        elif idx > 0 and abs(cp - prev_cp) == 1:
            effective_len += 0.5
        else:
            effective_len += 1.0
        prev_cp = cp

    pool_bits = effective_len * math.log2(pool)

    # Cap by empirical Shannon diversity upper bound scaled by unique character ratio
    counts = {}
    for ch in passphrase:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(passphrase)
    shannon_per_char = -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())
    shannon_bound = (shannon_per_char + 1.5) * n

    return round(min(pool_bits, shannon_bound), 2)


def _classify_strength_tier(is_valid: bool, entropy_bits: float) -> str:
    if not is_valid:
        return "rejected"
    if entropy_bits >= 112.0:
        return "sovereign"
    if entropy_bits >= 80.0:
        return "strong"
    return "baseline"


@dataclass(frozen=True)
class PassphraseValidationResult:
    is_valid: bool
    length: int
    digits: int
    specials: int
    uppercase: int
    lowercase: int
    errors: List[str]
    entropy_bits: float = 0.0
    strength_tier: str = "rejected"


def analyze_passphrase(passphrase: str) -> PassphraseValidationResult:
    if not isinstance(passphrase, str) or len(passphrase) == 0:
        return PassphraseValidationResult(
            is_valid=False,
            length=0,
            digits=0,
            specials=0,
            uppercase=0,
            lowercase=0,
            errors=["Passphrase is required in OpenQPEP and cannot be empty."],
            entropy_bits=0.0,
            strength_tier="rejected",
        )

    length = len(passphrase)
    if length > MAX_LENGTH:
        return PassphraseValidationResult(
            is_valid=False,
            length=length,
            digits=0,
            specials=0,
            uppercase=0,
            lowercase=0,
            errors=[f"Passphrase exceeds maximum allowed length of {MAX_LENGTH} characters (got {length})."],
            entropy_bits=0.0,
            strength_tier="rejected",
        )

    if _has_disallowed_passphrase_chars(passphrase):
        return PassphraseValidationResult(
            is_valid=False,
            length=length,
            digits=0,
            specials=0,
            uppercase=0,
            lowercase=0,
            errors=[
                "Passphrase contains disallowed control, NUL, surrogate, or Unicode Bidi/format characters."
            ],
            entropy_bits=0.0,
            strength_tier="rejected",
        )

    utf8_len = len(passphrase.encode("utf-8"))
    if utf8_len > MAX_PASSPHRASE_UTF8_BYTES:
        return PassphraseValidationResult(
            is_valid=False,
            length=length,
            digits=0,
            specials=0,
            uppercase=0,
            lowercase=0,
            errors=[
                f"Passphrase UTF-8 encoding exceeds maximum allowed {MAX_PASSPHRASE_UTF8_BYTES} bytes (got {utf8_len})."
            ],
            entropy_bits=0.0,
            strength_tier="rejected",
        )

    digits = sum(1 for c in passphrase if "0" <= c <= "9")
    uppercase = sum(1 for c in passphrase if "A" <= c <= "Z")
    lowercase = sum(1 for c in passphrase if "a" <= c <= "z")
    specials = sum(
        1
        for c in passphrase
        if not ("0" <= c <= "9" or "A" <= c <= "Z" or "a" <= c <= "z")
    )

    errors: List[str] = []
    if length < MIN_LENGTH:
        errors.append(f"Minimum length is {MIN_LENGTH} characters (got {length}).")
    if digits < MIN_DIGITS:
        errors.append(f"Minimum {MIN_DIGITS} numbers required (got {digits}).")
    if specials < MIN_SPECIALS:
        errors.append(f"Minimum {MIN_SPECIALS} special characters required (got {specials}).")
    if uppercase < MIN_UPPERCASE:
        errors.append(f"Minimum {MIN_UPPERCASE} uppercase letters required (got {uppercase}).")
    if lowercase < MIN_LOWERCASE:
        errors.append(f"Minimum {MIN_LOWERCASE} lowercase letters required (got {lowercase}).")

    is_valid = len(errors) == 0
    entropy_bits = estimate_passphrase_entropy_bits(passphrase)
    return PassphraseValidationResult(
        is_valid=is_valid,
        length=length,
        digits=digits,
        specials=specials,
        uppercase=uppercase,
        lowercase=lowercase,
        errors=errors,
        entropy_bits=entropy_bits,
        strength_tier=_classify_strength_tier(is_valid, entropy_bits),
    )


def enforce_passphrase_policy(passphrase: str) -> bytes:
    """
    Validates the mandatory OpenQPEP passphrase policy and returns the 64-byte cryptographic
    policy witness required by all QLX, QVS, Beyond-LWE, and CC-512 key derivation operations.
    Scrubs intermediate plaintext passphrase staging memory via SecretBuffer.
    """
    res = analyze_passphrase(passphrase)
    if not res.is_valid:
        raise QPEPPassphrasePolicyError(
            "OpenQPEP Mandatory Passphrase Policy Violation: " + " ".join(res.errors)
        )

    d_chars = "".join(c for c in passphrase if "0" <= c <= "9")[:2]
    u_chars = "".join(c for c in passphrase if "A" <= c <= "Z")[:2]
    l_chars = "".join(c for c in passphrase if "a" <= c <= "z")[:4]
    s_chars = "".join(c for c in passphrase if not ("0" <= c <= "9" or "A" <= c <= "Z" or "a" <= c <= "z"))[:4]

    if len(d_chars) < 2 or len(u_chars) < 2 or len(l_chars) < 4 or len(s_chars) < 4 or len(passphrase) < 12:
        raise QPEPPassphrasePolicyError("Cryptographic character-class witness construction failed.")

    staging = bytearray(b"CALYX-QPEP-HARDCODED-POLICY-WITNESS-v1.0.0|")
    try:
        staging.extend(
            f"L>=12:{len(d_chars)>=2}:{len(s_chars)>=4}:{len(u_chars)>=2}:{len(l_chars)>=4}|".encode("ascii")
        )
        staging.extend(passphrase.encode("utf-8"))
        with SecretBuffer(staging) as witness_buf:
            zeroize_bytes(staging)
            return hashlib.sha3_512(witness_buf.raw).digest()
    finally:
        zeroize_bytes(staging)
