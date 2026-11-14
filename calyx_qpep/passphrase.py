"""
Calyx QPEP Mandatory Passphrase Policy Validator (QPKD-Argon Gate).

Policy Requirements (Strictly Mandatory):
- Minimum 12 characters total length
- At least 2 numeric digits (0-9)
- At least 4 special characters (non-alphanumeric ASCII symbols/punctuation)
- At least 2 uppercase letters (A-Z)
- At least 4 lowercase letters (a-z)
"""
from dataclasses import dataclass
from typing import List


class QPEPPassphrasePolicyError(ValueError):
    """Raised when a passphrase violates the mandatory Calyx QPEP security policy."""


@dataclass(frozen=True)
class PassphraseValidationResult:
    is_valid: bool
    length: int
    digits: int
    specials: int
    uppercase: int
    lowercase: int
    errors: List[str]


MIN_LENGTH = 12
MIN_DIGITS = 2
MIN_SPECIALS = 4
MIN_UPPERCASE = 2
MIN_LOWERCASE = 4


def analyze_passphrase(passphrase: str) -> PassphraseValidationResult:
    if not isinstance(passphrase, str) or len(passphrase) == 0:
        return PassphraseValidationResult(
            is_valid=False,
            length=0,
            digits=0,
            specials=0,
            uppercase=0,
            lowercase=0,
            errors=["Passphrase is required in Calyx QPEP and cannot be empty."],
        )

    digits = sum(1 for c in passphrase if "0" <= c <= "9")
    uppercase = sum(1 for c in passphrase if "A" <= c <= "Z")
    lowercase = sum(1 for c in passphrase if "a" <= c <= "z")
    specials = sum(
        1
        for c in passphrase
        if not ("0" <= c <= "9" or "A" <= c <= "Z" or "a" <= c <= "z")
    )
    length = len(passphrase)

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

    return PassphraseValidationResult(
        is_valid=(len(errors) == 0),
        length=length,
        digits=digits,
        specials=specials,
        uppercase=uppercase,
        lowercase=lowercase,
        errors=errors,
    )


def enforce_passphrase_policy(passphrase: str) -> None:
    res = analyze_passphrase(passphrase)
    if not res.is_valid:
        raise QPEPPassphrasePolicyError(
            "Calyx QPEP Passphrase Policy Violation: " + " ".join(res.errors)
        )
