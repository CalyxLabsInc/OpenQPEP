"""
Backward-compatible re-export facade for QPKD-Argon2id Passphrase Policy (Official Release 1.1.7).
Canonical implementation now lives in calyx_qpep.kdf.passphrase_policy.
"""
from .kdf.passphrase_policy import (
    MIN_LENGTH,
    MAX_LENGTH,
    MAX_PASSPHRASE_UTF8_BYTES,
    MIN_DIGITS,
    MIN_SPECIALS,
    MIN_UPPERCASE,
    MIN_LOWERCASE,
    QPEPPassphrasePolicyError,
    PassphraseValidationResult,
    estimate_passphrase_entropy_bits,
    analyze_passphrase,
    enforce_passphrase_policy,
)

__all__ = [
    "MIN_LENGTH",
    "MAX_LENGTH",
    "MAX_PASSPHRASE_UTF8_BYTES",
    "MIN_DIGITS",
    "MIN_SPECIALS",
    "MIN_UPPERCASE",
    "MIN_LOWERCASE",
    "QPEPPassphrasePolicyError",
    "PassphraseValidationResult",
    "estimate_passphrase_entropy_bits",
    "analyze_passphrase",
    "enforce_passphrase_policy",
]
