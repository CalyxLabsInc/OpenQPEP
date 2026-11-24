# OpenQPEP Official Release 1.2.1 (v1.2.1)
"""
qSponge-512 (SHA3-512) and qSponge-XOF (SHAKE-256) 24-round Keccak-f[1600] primitives.
Automatically dispatches to the zero-dependency, constant-time, unrolled Native C99
`libopenqpep` Keccak-f[1600] engine (`keccak_f1600.c`) when enabled, with bit-exact
NIST FIPS 202 `hashlib` fallback when `OPENQPEP_DISABLE_NATIVE=1` or library is absent.
"""
import hashlib

from ..native.loader import native_qsponge_512, native_qsponge_var


def qsponge_var(data: bytes, out_len: int) -> bytes:
    """Domain-separated qSponge-XOF (24-round Keccak-f[1600] SHAKE-256) variable-length output."""
    if out_len < 0:
        raise ValueError("qsponge_var out_len must be non-negative.")
    if out_len == 0:
        return b""
    native_out = native_qsponge_var(data, out_len)
    if native_out is not None:
        return native_out
    return hashlib.shake_256(data).digest(out_len)


def qsponge_512(data: bytes) -> bytes:
    """Fixed 512-bit qSponge-512 (24-round Keccak-f[1600] SHA3-512) digest."""
    native_out = native_qsponge_512(data)
    if native_out is not None:
        return native_out
    return hashlib.sha3_512(data).digest()
