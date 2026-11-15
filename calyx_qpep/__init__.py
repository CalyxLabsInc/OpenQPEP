"""
OpenQPEP (CALYX-QPEP) – Calyx Quantum Proof Encryption Protocol
Copyright © 2026 Calyx Labs Inc. Developed by Tristen Martinez. All rights reserved.
(https://github.com/CalyxLabsInc/OpenQPEP/)
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
__version__ = "0.1.2-beta"
