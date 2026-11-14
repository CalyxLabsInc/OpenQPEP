"""
Calyx QPEP (Calyx Quantum Proof Encryption Protocol)
Official Reference Implementation by Calyx Labs Inc.
"""
from .passphrase import (
    enforce_passphrase_policy,
    analyze_passphrase,
    QPEPPassphrasePolicyError,
    PassphraseValidationResult,
)
from .protocol import (
    CalyxQPEPProtocol,
    QPEPKeyRing,
    PROTOCOL_VERSION,
    SUITE_ID,
    QPKRF_EXTENSION,
)

__all__ = [
    "CalyxQPEPProtocol",
    "QPEPKeyRing",
    "enforce_passphrase_policy",
    "analyze_passphrase",
    "QPEPPassphrasePolicyError",
    "PassphraseValidationResult",
    "PROTOCOL_VERSION",
    "SUITE_ID",
    "QPKRF_EXTENSION",
]
__version__ = "1.0.0"
