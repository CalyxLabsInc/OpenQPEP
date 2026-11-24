"""
OpenQPEP Native C99 / SIMD Vectorized Acceleration Loader (libopenqpep) — Official Release 1.2.1.
Loads libopenqpep.so / .dylib / .dll via ctypes with zero-copy array.array buffer marshaling.
Seamlessly falls back to the bit-exact pure-Python reference engine when absent or disabled.
"""
import array
import ctypes
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional

_NATIVE_DIR = Path(__file__).resolve().parent
_LIB: Optional[ctypes.CDLL] = None
_LIB_PATH: Optional[str] = None
_NATIVE_ENABLED: bool = os.environ.get("OPENQPEP_DISABLE_NATIVE", "0") != "1"

_c_void_p = ctypes.c_void_p
_ZERO_256_I32 = [0] * 256


def _try_load_library() -> Optional[ctypes.CDLL]:
    global _LIB, _LIB_PATH
    if _LIB is not None:
        return _LIB
    ext_map = {"Darwin": "dylib", "Windows": "dll"}
    ext = ext_map.get(platform.system(), "so")
    candidates = [
        _NATIVE_DIR / f"libopenqpep.{ext}",
        _NATIVE_DIR / "libopenqpep.so",
        _NATIVE_DIR / "libopenqpep.dylib",
        _NATIVE_DIR / "libopenqpep.dll",
    ]
    for path in candidates:
        if path.is_file():
            try:
                lib = ctypes.CDLL(str(path))
                _configure_signatures(lib)
                _LIB = lib
                _LIB_PATH = str(path)
                return lib
            except OSError:
                continue
    return None


def _configure_signatures(lib: ctypes.CDLL) -> None:
    if hasattr(lib, "openqpep_abi_version"):
        lib.openqpep_abi_version.argtypes = []
        lib.openqpep_abi_version.restype = ctypes.c_uint32
    if hasattr(lib, "openqpep_version_string"):
        lib.openqpep_version_string.argtypes = []
        lib.openqpep_version_string.restype = ctypes.c_char_p

    lib.openqpep_native_abi_info.argtypes = []
    lib.openqpep_native_abi_info.restype = ctypes.c_uint32

    lib.openqpep_ntt_3329.argtypes = [_c_void_p]
    lib.openqpep_ntt_3329.restype = None

    lib.openqpep_inv_ntt_3329.argtypes = [_c_void_p]
    lib.openqpep_inv_ntt_3329.restype = None

    lib.openqpep_ntt_base_mul_3329.argtypes = [_c_void_p, _c_void_p, _c_void_p]
    lib.openqpep_ntt_base_mul_3329.restype = None

    lib.openqpep_poly_add_3329.argtypes = [_c_void_p, _c_void_p, _c_void_p]
    lib.openqpep_poly_add_3329.restype = None

    lib.openqpep_poly_sub_3329.argtypes = [_c_void_p, _c_void_p, _c_void_p]
    lib.openqpep_poly_sub_3329.restype = None

    lib.openqpep_ntt_qvs.argtypes = [_c_void_p]
    lib.openqpep_ntt_qvs.restype = None

    lib.openqpep_inv_ntt_qvs.argtypes = [_c_void_p]
    lib.openqpep_inv_ntt_qvs.restype = None

    lib.openqpep_ntt_mul_qvs.argtypes = [_c_void_p, _c_void_p, _c_void_p]
    lib.openqpep_ntt_mul_qvs.restype = None

    lib.openqpep_cbd2_3329.argtypes = [ctypes.c_char_p, _c_void_p]
    lib.openqpep_cbd2_3329.restype = None

    lib.openqpep_cbd1_3329.argtypes = [ctypes.c_char_p, _c_void_p]
    lib.openqpep_cbd1_3329.restype = None

    lib.openqpep_cbd2_qvs.argtypes = [ctypes.c_char_p, _c_void_p]
    lib.openqpep_cbd2_qvs.restype = None

    lib.openqpep_plain_lwe_row_accum_u16.argtypes = [_c_void_p, _c_void_p, ctypes.c_uint16, ctypes.c_uint32]
    lib.openqpep_plain_lwe_row_accum_u16.restype = None

    lib.openqpep_plain_lwe_keygen_row_u16.argtypes = [
        _c_void_p, _c_void_p, _c_void_p, _c_void_p, ctypes.c_uint32, ctypes.c_uint32
    ]
    lib.openqpep_plain_lwe_keygen_row_u16.restype = None

    if hasattr(lib, "openqpep_explicit_bzero"):
        lib.openqpep_explicit_bzero.argtypes = [_c_void_p, ctypes.c_size_t]
        lib.openqpep_explicit_bzero.restype = None
    if hasattr(lib, "openqpep_is_zeroed"):
        lib.openqpep_is_zeroed.argtypes = [_c_void_p, ctypes.c_size_t]
        lib.openqpep_is_zeroed.restype = ctypes.c_int
    if hasattr(lib, "openqpep_verify_wire_v5_magic"):
        lib.openqpep_verify_wire_v5_magic.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        lib.openqpep_verify_wire_v5_magic.restype = ctypes.c_int
    if hasattr(lib, "openqpep_ct_eq"):
        lib.openqpep_ct_eq.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        lib.openqpep_ct_eq.restype = ctypes.c_int
    if hasattr(lib, "openqpep_ct_cmov"):
        lib.openqpep_ct_cmov.argtypes = [ctypes.c_int, _c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        lib.openqpep_ct_cmov.restype = None
    if hasattr(lib, "openqpep_qsponge_512"):
        lib.openqpep_qsponge_512.argtypes = [ctypes.c_char_p, ctypes.c_size_t, _c_void_p]
        lib.openqpep_qsponge_512.restype = ctypes.c_int
    if hasattr(lib, "openqpep_sha3_256"):
        lib.openqpep_sha3_256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, _c_void_p]
        lib.openqpep_sha3_256.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qsponge_var"):
        lib.openqpep_qsponge_var.argtypes = [ctypes.c_char_p, ctypes.c_size_t, _c_void_p, ctypes.c_size_t]
        lib.openqpep_qsponge_var.restype = ctypes.c_int
    if hasattr(lib, "openqpep_shake128"):
        lib.openqpep_shake128.argtypes = [ctypes.c_char_p, ctypes.c_size_t, _c_void_p, ctypes.c_size_t]
        lib.openqpep_shake128.restype = ctypes.c_int
    if hasattr(lib, "openqpep_keccak_init"):
        lib.openqpep_keccak_init.argtypes = [_c_void_p, ctypes.c_uint32, ctypes.c_uint8]
        lib.openqpep_keccak_init.restype = ctypes.c_int
    if hasattr(lib, "openqpep_keccak_absorb"):
        lib.openqpep_keccak_absorb.argtypes = [_c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        lib.openqpep_keccak_absorb.restype = ctypes.c_int
    if hasattr(lib, "openqpep_keccak_finalize"):
        lib.openqpep_keccak_finalize.argtypes = [_c_void_p]
        lib.openqpep_keccak_finalize.restype = ctypes.c_int
    if hasattr(lib, "openqpep_keccak_squeeze"):
        lib.openqpep_keccak_squeeze.argtypes = [_c_void_p, _c_void_p, ctypes.c_size_t]
        lib.openqpep_keccak_squeeze.restype = ctypes.c_int
    if hasattr(lib, "openqpep_keccak_wipe"):
        lib.openqpep_keccak_wipe.argtypes = [_c_void_p]
        lib.openqpep_keccak_wipe.restype = None


_try_load_library()


def is_native_available() -> bool:
    return _NATIVE_ENABLED and (_LIB is not None)


def set_native_enabled(enabled: bool) -> None:
    global _NATIVE_ENABLED
    _NATIVE_ENABLED = bool(enabled)


def native_abi_version() -> Optional[int]:
    if _LIB is None or not hasattr(_LIB, "openqpep_abi_version"):
        return None
    return int(_LIB.openqpep_abi_version())


def native_version_string() -> Optional[str]:
    if _LIB is None or not hasattr(_LIB, "openqpep_version_string"):
        return None
    raw = _LIB.openqpep_version_string()
    return raw.decode("ascii") if isinstance(raw, (bytes, bytearray)) else None


def native_backend_info() -> Dict[str, Any]:
    if _LIB is None:
        return {
            "loaded": False,
            "enabled": False,
            "backend": "pure-python",
            "abi_version": None,
            "c_version": None,
            "simd": [],
            "arch": platform.machine(),
            "library_path": None,
        }
    flags = int(_LIB.openqpep_native_abi_info())
    simd: List[str] = []
    if flags & 0x01:
        simd.append("C99")
    if flags & 0x02:
        simd.append("AVX2")
    if flags & 0x04:
        simd.append("NEON")
    return {
        "loaded": True,
        "enabled": _NATIVE_ENABLED,
        "backend": "libopenqpep-c99" if _NATIVE_ENABLED else "pure-python (native disabled)",
        "abi_version": native_abi_version(),
        "c_version": native_version_string(),
        "simd": simd,
        "arch": platform.machine(),
        "library_path": _LIB_PATH,
    }


def native_ntt_3329(poly: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    arr = array.array("i", poly)
    _LIB.openqpep_ntt_3329(arr.buffer_info()[0])
    return arr.tolist()


def native_inv_ntt_3329(poly_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    arr = array.array("i", poly_hat)
    _LIB.openqpep_inv_ntt_3329(arr.buffer_info()[0])
    return arr.tolist()


def native_ntt_base_mul_3329(a_hat: List[int], b_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    a_arr = array.array("i", a_hat)
    b_arr = array.array("i", b_hat)
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_ntt_base_mul_3329(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
    return out.tolist()


def native_poly_add_3329(a: List[int], b: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    a_arr = array.array("i", a)
    b_arr = array.array("i", b)
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_poly_add_3329(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
    return out.tolist()


def native_poly_sub_3329(a: List[int], b: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    a_arr = array.array("i", a)
    b_arr = array.array("i", b)
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_poly_sub_3329(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
    return out.tolist()


def native_ntt_qvs(poly: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    arr = array.array("i", poly)
    _LIB.openqpep_ntt_qvs(arr.buffer_info()[0])
    return arr.tolist()


def native_inv_ntt_qvs(poly_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    arr = array.array("i", poly_hat)
    _LIB.openqpep_inv_ntt_qvs(arr.buffer_info()[0])
    return arr.tolist()


def native_ntt_mul_qvs(a_hat: List[int], b_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    a_arr = array.array("i", a_hat)
    b_arr = array.array("i", b_hat)
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_ntt_mul_qvs(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
    return out.tolist()


def native_cbd2_3329(raw128: bytes) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_cbd2_3329(raw128, out.buffer_info()[0])
    return out.tolist()


def native_cbd1_3329(raw64: bytes) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_cbd1_3329(raw64, out.buffer_info()[0])
    return out.tolist()


def native_cbd2_qvs(raw128: bytes) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_cbd2_qvs(raw128, out.buffer_info()[0])
    return out.tolist()


def native_plain_lwe_keygen_row(e_row: List[int], a_row: List[int], s_flat: List[int], n: int, nbar: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    b_out = array.array("H", [0] * nbar)
    e_arr = array.array("H", e_row)
    a_arr = array.array("H", a_row)
    s_arr = array.array("H", s_flat)
    _LIB.openqpep_plain_lwe_keygen_row_u16(
        b_out.buffer_info()[0], e_arr.buffer_info()[0], a_arr.buffer_info()[0], s_arr.buffer_info()[0], n, nbar
    )
    return b_out.tolist()


def native_plain_lwe_row_accum(dst: List[int], row: List[int], scalar: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    dst_arr = array.array("H", dst)
    row_arr = array.array("H", row)
    _LIB.openqpep_plain_lwe_row_accum_u16(dst_arr.buffer_info()[0], row_arr.buffer_info()[0], scalar & 0xFFFF, len(row))
    return dst_arr.tolist()


def native_explicit_bzero(addr: int, length: int) -> bool:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_explicit_bzero")):
        return False
    _LIB.openqpep_explicit_bzero(addr, length)
    return True


def native_is_zeroed(addr: int, length: int) -> Optional[bool]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_is_zeroed")):
        return None
    return bool(_LIB.openqpep_is_zeroed(addr, length))


def native_verify_wire_v5_magic(hdr: bytes) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_verify_wire_v5_magic")):
        return None
    return int(_LIB.openqpep_verify_wire_v5_magic(hdr, len(hdr)))


def native_ct_eq(a: bytes, b: bytes) -> Optional[bool]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_ct_eq")):
        return None
    if len(a) != len(b):
        return False
    return bool(_LIB.openqpep_ct_eq(a, b, len(a)))


def native_qsponge_512(data: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qsponge_512")):
        return None
    raw = data if isinstance(data, bytes) else bytes(data)
    out = ctypes.create_string_buffer(64)
    rc = int(_LIB.openqpep_qsponge_512(raw if raw else None, len(raw), out))
    if rc != 0:
        raise ValueError(f"openqpep_qsponge_512 failed with status {rc}.")
    return out.raw


def native_sha3_256(data: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_sha3_256")):
        return None
    raw = data if isinstance(data, bytes) else bytes(data)
    out = ctypes.create_string_buffer(32)
    rc = int(_LIB.openqpep_sha3_256(raw if raw else None, len(raw), out))
    if rc != 0:
        raise ValueError(f"openqpep_sha3_256 failed with status {rc}.")
    return out.raw


def native_qsponge_var(data: bytes, out_len: int) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qsponge_var")):
        return None
    if out_len < 0:
        raise ValueError("out_len must be non-negative.")
    if out_len == 0:
        return b""
    raw = data if isinstance(data, bytes) else bytes(data)
    out = ctypes.create_string_buffer(out_len)
    rc = int(_LIB.openqpep_qsponge_var(raw if raw else None, len(raw), out, out_len))
    if rc != 0:
        raise ValueError(f"openqpep_qsponge_var failed with status {rc}.")
    return out.raw


def native_shake128(data: bytes, out_len: int) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_shake128")):
        return None
    if out_len < 0:
        raise ValueError("out_len must be non-negative.")
    if out_len == 0:
        return b""
    raw = data if isinstance(data, bytes) else bytes(data)
    out = ctypes.create_string_buffer(out_len)
    rc = int(_LIB.openqpep_shake128(raw if raw else None, len(raw), out, out_len))
    if rc != 0:
        raise ValueError(f"openqpep_shake128 failed with status {rc}.")
    return out.raw


class _CKeccakCtx(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint64 * 25),
        ("rate", ctypes.c_uint32),
        ("pos", ctypes.c_uint32),
        ("domain_sep", ctypes.c_uint8),
        ("squeezing", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
    ]


_KECCAK_MODES = {
    "sha3-512": (72, 0x06),
    "qsponge-512": (72, 0x06),
    "sha3-256": (136, 0x06),
    "shake256": (136, 0x1F),
    "qsponge-xof": (136, 0x1F),
    "shake128": (168, 0x1F),
}


class NativeKeccakSponge:
    """
    Incremental native C99 Keccak-f[1600] sponge context manager (`openqpep_keccak_ctx_t`).
    Supports streaming `.absorb()`, `.finalize()`, multi-call `.squeeze()`, and automatic
    compiler-barrier zeroization (`openqpep_keccak_wipe`) on close/exit.
    """

    def __init__(self, mode: str = "shake256"):
        if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_keccak_init")):
            raise RuntimeError("Native C99 Keccak-f[1600] backend is not available or disabled.")
        key = str(mode).lower()
        if key not in _KECCAK_MODES:
            raise ValueError(f"Unsupported Keccak mode '{mode}'. Expected one of {sorted(_KECCAK_MODES)}.")
        rate, domain_sep = _KECCAK_MODES[key]
        self._ctx = _CKeccakCtx()
        self._wiped = False
        rc = int(_LIB.openqpep_keccak_init(ctypes.byref(self._ctx), rate, domain_sep))
        if rc != 0:
            raise ValueError(f"openqpep_keccak_init failed with status {rc}.")

    def absorb(self, data: bytes) -> "NativeKeccakSponge":
        if self._wiped:
            raise RuntimeError("Cannot absorb into a wiped NativeKeccakSponge.")
        raw = data if isinstance(data, bytes) else bytes(data)
        rc = int(_LIB.openqpep_keccak_absorb(ctypes.byref(self._ctx), raw if raw else None, len(raw)))
        if rc != 0:
            raise ValueError(f"openqpep_keccak_absorb failed with status {rc} (already finalized?).")
        return self

    def finalize(self) -> "NativeKeccakSponge":
        if self._wiped:
            raise RuntimeError("Cannot finalize a wiped NativeKeccakSponge.")
        rc = int(_LIB.openqpep_keccak_finalize(ctypes.byref(self._ctx)))
        if rc != 0:
            raise ValueError(f"openqpep_keccak_finalize failed with status {rc}.")
        return self

    def squeeze(self, out_len: int) -> bytes:
        if self._wiped:
            raise RuntimeError("Cannot squeeze from a wiped NativeKeccakSponge.")
        if out_len < 0:
            raise ValueError("out_len must be non-negative.")
        if out_len == 0:
            return b""
        out = ctypes.create_string_buffer(out_len)
        rc = int(_LIB.openqpep_keccak_squeeze(ctypes.byref(self._ctx), out, out_len))
        if rc != 0:
            raise ValueError(f"openqpep_keccak_squeeze failed with status {rc}.")
        return out.raw

    def wipe(self) -> None:
        if not self._wiped and _LIB is not None and hasattr(_LIB, "openqpep_keccak_wipe"):
            _LIB.openqpep_keccak_wipe(ctypes.byref(self._ctx))
        self._wiped = True

    def __enter__(self) -> "NativeKeccakSponge":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        self.wipe()
