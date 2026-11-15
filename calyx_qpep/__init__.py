"""
Calyx QPEP (Calyx Quantum Proof Encryption Protocol)
Official Reference Implementation by Calyx Labs Inc. (https://github.com/CalyxLabsInc/OpenQPEP/)
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
    DEFAULT_SUITE,
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
    "DEFAULT_SUITE",
    "QPKRF_EXTENSION",
]
__version__ = "0.1.1-beta"
