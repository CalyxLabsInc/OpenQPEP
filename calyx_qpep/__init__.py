"""
OpenQPEP by Calyx Labs Inc. (Beta Version 0.1.6)
Official Reference Implementation by Tristen Martinez at Calyx Labs Inc.
Repository: https://github.com/CalyxLabsInc/OpenQPEP/
Public Key Directory: https://qpepkeys.calyxlabsinc.org
"""
from .passphrase import (
    enforce_passphrase_policy,
    analyze_passphrase,
    QPEPPassphrasePolicyError,
    PassphraseValidationResult,
)
from .protocol import (
    OpenQPEPProtocol,
    CalyxQPEPProtocol,
    QPEPKeyRing,
    PROJECT_NAME,
    APP_NAME,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    PROTOCOL_VERSION,
    DEFAULT_SUITE,
    QPKRF_EXTENSION,
)

__all__ = [
    "OpenQPEPProtocol",
    "CalyxQPEPProtocol",
    "QPEPKeyRing",
    "enforce_passphrase_policy",
    "analyze_passphrase",
    "QPEPPassphrasePolicyError",
    "PassphraseValidationResult",
    "PROJECT_NAME",
    "APP_NAME",
    "UNIVERSAL_VERSION",
    "UNIVERSAL_VERSION_LABEL",
    "PROTOCOL_VERSION",
    "DEFAULT_SUITE",
    "QPKRF_EXTENSION",
]
__version__ = "0.1.6"
