"""
OpenQPEP Native C99 / SIMD Vectorized Acceleration Loader (libopenqpep) — Official Release 1.2.7.
Loads libopenqpep.so / .dylib / .dll via ctypes with zero-copy array.array buffer marshaling.
Seamlessly falls back to the bit-exact pure-Python reference engine when absent or disabled.
"""
import array
import ctypes
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
    if hasattr(lib, "openqpep_ntt_base_mul_acc_3329"):
        lib.openqpep_ntt_base_mul_acc_3329.argtypes = [_c_void_p, _c_void_p, _c_void_p]
        lib.openqpep_ntt_base_mul_acc_3329.restype = None
    if hasattr(lib, "openqpep_ntt_base_mul_8380417"):
        lib.openqpep_ntt_base_mul_8380417.argtypes = [_c_void_p, _c_void_p, _c_void_p]
        lib.openqpep_ntt_base_mul_8380417.restype = None
    if hasattr(lib, "openqpep_poly_add_qvs"):
        lib.openqpep_poly_add_qvs.argtypes = [_c_void_p, _c_void_p, _c_void_p]
        lib.openqpep_poly_add_qvs.restype = None
    if hasattr(lib, "openqpep_poly_sub_qvs"):
        lib.openqpep_poly_sub_qvs.argtypes = [_c_void_p, _c_void_p, _c_void_p]
        lib.openqpep_poly_sub_qvs.restype = None
    if hasattr(lib, "openqpep_qvs_decompose_poly"):
        lib.openqpep_qvs_decompose_poly.argtypes = [_c_void_p, _c_void_p, _c_void_p]
        lib.openqpep_qvs_decompose_poly.restype = ctypes.c_int
    if hasattr(lib, "openqpep_byte_encode_12"):
        lib.openqpep_byte_encode_12.argtypes = [_c_void_p, _c_void_p]
        lib.openqpep_byte_encode_12.restype = ctypes.c_int
    if hasattr(lib, "openqpep_byte_decode_12"):
        lib.openqpep_byte_decode_12.argtypes = [ctypes.c_char_p, _c_void_p]
        lib.openqpep_byte_decode_12.restype = ctypes.c_int
    if hasattr(lib, "openqpep_poly_compress_3329"):
        lib.openqpep_poly_compress_3329.argtypes = [_c_void_p, ctypes.c_uint32, _c_void_p, ctypes.c_size_t]
        lib.openqpep_poly_compress_3329.restype = ctypes.c_int
    if hasattr(lib, "openqpep_poly_decompress_3329"):
        lib.openqpep_poly_decompress_3329.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32, _c_void_p]
        lib.openqpep_poly_decompress_3329.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qlx_sample_ntt_3329"):
        lib.openqpep_qlx_sample_ntt_3329.argtypes = [ctypes.c_char_p, ctypes.c_uint8, ctypes.c_uint8, _c_void_p]
        lib.openqpep_qlx_sample_ntt_3329.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qlx_matvec_3329"):
        lib.openqpep_qlx_matvec_3329.argtypes = [
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int, _c_void_p, _c_void_p, _c_void_p
        ]
        lib.openqpep_qlx_matvec_3329.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qlx_inner_prod_3329"):
        lib.openqpep_qlx_inner_prod_3329.argtypes = [_c_void_p, _c_void_p, ctypes.c_uint32, _c_void_p]
        lib.openqpep_qlx_inner_prod_3329.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qvs_pack_poly24"):
        lib.openqpep_qvs_pack_poly24.argtypes = [_c_void_p, _c_void_p]
        lib.openqpep_qvs_pack_poly24.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qvs_unpack_poly24"):
        lib.openqpep_qvs_unpack_poly24.argtypes = [ctypes.c_char_p, _c_void_p]
        lib.openqpep_qvs_unpack_poly24.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qvs_sample_ntt"):
        lib.openqpep_qvs_sample_ntt.argtypes = [ctypes.c_char_p, ctypes.c_uint8, ctypes.c_uint8, _c_void_p]
        lib.openqpep_qvs_sample_ntt.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qvs_sample_mask_y"):
        lib.openqpep_qvs_sample_mask_y.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint16, _c_void_p]
        lib.openqpep_qvs_sample_mask_y.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qvs_sample_in_ball"):
        lib.openqpep_qvs_sample_in_ball.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32, _c_void_p]
        lib.openqpep_qvs_sample_in_ball.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qvs_expand_matrix"):
        lib.openqpep_qvs_expand_matrix.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, _c_void_p]
        lib.openqpep_qvs_expand_matrix.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qvs_matvec_precomputed"):
        lib.openqpep_qvs_matvec_precomputed.argtypes = [
            _c_void_p, ctypes.c_uint32, ctypes.c_uint32, _c_void_p, _c_void_p
        ]
        lib.openqpep_qvs_matvec_precomputed.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qvs_matvec"):
        lib.openqpep_qvs_matvec.argtypes = [
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, _c_void_p, _c_void_p, ctypes.c_int, _c_void_p
        ]
        lib.openqpep_qvs_matvec.restype = ctypes.c_int
    if hasattr(lib, "openqpep_plain_lwe_sample_noise"):
        lib.openqpep_plain_lwe_sample_noise.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t, _c_void_p
        ]
        lib.openqpep_plain_lwe_sample_noise.restype = ctypes.c_int
    if hasattr(lib, "openqpep_plain_lwe_expand_row"):
        lib.openqpep_plain_lwe_expand_row.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, _c_void_p]
        lib.openqpep_plain_lwe_expand_row.restype = ctypes.c_int
    if hasattr(lib, "openqpep_plain_lwe_keygen_matrix"):
        lib.openqpep_plain_lwe_keygen_matrix.argtypes = [
            ctypes.c_char_p, _c_void_p, _c_void_p, ctypes.c_uint32, ctypes.c_uint32, _c_void_p
        ]
        lib.openqpep_plain_lwe_keygen_matrix.restype = ctypes.c_int
    if hasattr(lib, "openqpep_plain_lwe_keygen_from_seeds"):
        lib.openqpep_plain_lwe_keygen_from_seeds.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            _c_void_p, ctypes.c_size_t, _c_void_p, ctypes.c_size_t,
        ]
        lib.openqpep_plain_lwe_keygen_from_seeds.restype = ctypes.c_int
    if hasattr(lib, "openqpep_plain_lwe_indcpa_enc"):
        lib.openqpep_plain_lwe_indcpa_enc.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p, _c_void_p, ctypes.c_size_t
        ]
        lib.openqpep_plain_lwe_indcpa_enc.restype = ctypes.c_int
    if hasattr(lib, "openqpep_plain_lwe_encaps"):
        lib.openqpep_plain_lwe_encaps.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, _c_void_p, ctypes.c_size_t, _c_void_p
        ]
        lib.openqpep_plain_lwe_encaps.restype = ctypes.c_int
    if hasattr(lib, "openqpep_plain_lwe_decaps"):
        lib.openqpep_plain_lwe_decaps.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, _c_void_p
        ]
        lib.openqpep_plain_lwe_decaps.restype = ctypes.c_int
    if hasattr(lib, "openqpep_gf2m10_mul"):
        lib.openqpep_gf2m10_mul.argtypes = [ctypes.c_uint16, ctypes.c_uint16]
        lib.openqpep_gf2m10_mul.restype = ctypes.c_uint16
    if hasattr(lib, "openqpep_gf2m10_sq"):
        lib.openqpep_gf2m10_sq.argtypes = [ctypes.c_uint16]
        lib.openqpep_gf2m10_sq.restype = ctypes.c_uint16
    if hasattr(lib, "openqpep_gf2m10_inv"):
        lib.openqpep_gf2m10_inv.argtypes = [ctypes.c_uint16]
        lib.openqpep_gf2m10_inv.restype = ctypes.c_uint16
    if hasattr(lib, "openqpep_gf2m10_sqrt"):
        lib.openqpep_gf2m10_sqrt.argtypes = [ctypes.c_uint16]
        lib.openqpep_gf2m10_sqrt.restype = ctypes.c_uint16
    if hasattr(lib, "openqpep_goppa_poly_eval"):
        lib.openqpep_goppa_poly_eval.argtypes = [_c_void_p, ctypes.c_size_t, ctypes.c_uint16]
        lib.openqpep_goppa_poly_eval.restype = ctypes.c_uint16
    if hasattr(lib, "openqpep_goppa_poly_eval_batch"):
        lib.openqpep_goppa_poly_eval_batch.argtypes = [
            _c_void_p, ctypes.c_size_t, _c_void_p, ctypes.c_size_t, _c_void_p
        ]
        lib.openqpep_goppa_poly_eval_batch.restype = ctypes.c_int
    if hasattr(lib, "openqpep_goppa_is_irreducible"):
        lib.openqpep_goppa_is_irreducible.argtypes = [_c_void_p, ctypes.c_uint32]
        lib.openqpep_goppa_is_irreducible.restype = ctypes.c_int
    if hasattr(lib, "openqpep_goppa_build_systematic_t"):
        lib.openqpep_goppa_build_systematic_t.argtypes = [_c_void_p, _c_void_p, _c_void_p]
        lib.openqpep_goppa_build_systematic_t.restype = ctypes.c_int
    if hasattr(lib, "openqpep_goppa_syndrome"):
        lib.openqpep_goppa_syndrome.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, _c_void_p]
        lib.openqpep_goppa_syndrome.restype = ctypes.c_int
    if hasattr(lib, "openqpep_goppa_chien_search"):
        lib.openqpep_goppa_chien_search.argtypes = [
            _c_void_p, ctypes.c_size_t, _c_void_p, _c_void_p, _c_void_p
        ]
        lib.openqpep_goppa_chien_search.restype = ctypes.c_int
    if hasattr(lib, "openqpep_goppa_patterson_decode"):
        lib.openqpep_goppa_patterson_decode.argtypes = [
            _c_void_p, _c_void_p, ctypes.c_char_p, _c_void_p, _c_void_p
        ]
        lib.openqpep_goppa_patterson_decode.restype = ctypes.c_int
    if hasattr(lib, "openqpep_gf2_127_mul"):
        lib.openqpep_gf2_127_mul.argtypes = [ctypes.c_char_p, ctypes.c_char_p, _c_void_p]
        lib.openqpep_gf2_127_mul.restype = ctypes.c_int
    if hasattr(lib, "openqpep_gf2_127_sq"):
        lib.openqpep_gf2_127_sq.argtypes = [ctypes.c_char_p, _c_void_p]
        lib.openqpep_gf2_127_sq.restype = ctypes.c_int
    if hasattr(lib, "openqpep_gf2_127_inv"):
        lib.openqpep_gf2_127_inv.argtypes = [ctypes.c_char_p, _c_void_p]
        lib.openqpep_gf2_127_inv.restype = ctypes.c_int
    if hasattr(lib, "openqpep_lrpc_ring_mul"):
        lib.openqpep_lrpc_ring_mul.argtypes = [ctypes.c_char_p, ctypes.c_char_p, _c_void_p]
        lib.openqpep_lrpc_ring_mul.restype = ctypes.c_int
    if hasattr(lib, "openqpep_lrpc_ring_inv"):
        lib.openqpep_lrpc_ring_inv.argtypes = [ctypes.c_char_p, _c_void_p]
        lib.openqpep_lrpc_ring_inv.restype = ctypes.c_int
    if hasattr(lib, "openqpep_gf256_inv"):
        lib.openqpep_gf256_inv.argtypes = [ctypes.c_uint8]
        lib.openqpep_gf256_inv.restype = ctypes.c_uint8
    if hasattr(lib, "openqpep_uov_solve_gf256_linear"):
        lib.openqpep_uov_solve_gf256_linear.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, _c_void_p]
        lib.openqpep_uov_solve_gf256_linear.restype = ctypes.c_int
    if hasattr(lib, "openqpep_uov_compute_p3"):
        lib.openqpep_uov_compute_p3.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, _c_void_p, ctypes.c_size_t
        ]
        lib.openqpep_uov_compute_p3.restype = ctypes.c_int
    if hasattr(lib, "openqpep_uov_eval_public_map"):
        lib.openqpep_uov_eval_public_map.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_char_p, _c_void_p,
        ]
        lib.openqpep_uov_eval_public_map.restype = ctypes.c_int
    if hasattr(lib, "openqpep_uov_sign_core"):
        lib.openqpep_uov_sign_core.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_uint32, ctypes.c_uint32, _c_void_p, _c_void_p,
        ]
        lib.openqpep_uov_sign_core.restype = ctypes.c_int
    if hasattr(lib, "openqpep_ct_select_u32"):
        lib.openqpep_ct_select_u32.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
        lib.openqpep_ct_select_u32.restype = ctypes.c_uint32
    if hasattr(lib, "openqpep_ct_mem_bounds_ok"):
        lib.openqpep_ct_mem_bounds_ok.argtypes = [ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t]
        lib.openqpep_ct_mem_bounds_ok.restype = ctypes.c_int
    if hasattr(lib, "openqpep_ct_cswap"):
        lib.openqpep_ct_cswap.argtypes = [ctypes.c_int, _c_void_p, _c_void_p, ctypes.c_size_t]
        lib.openqpep_ct_cswap.restype = None
    if hasattr(lib, "openqpep_wire_whiten_xor"):
        lib.openqpep_wire_whiten_xor.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_int, ctypes.c_char_p, _c_void_p, ctypes.c_size_t,
        ]
        lib.openqpep_wire_whiten_xor.restype = ctypes.c_int
    if hasattr(lib, "openqpep_wire_compute_mac"):
        lib.openqpep_wire_compute_mac.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, _c_void_p,
        ]
        lib.openqpep_wire_compute_mac.restype = ctypes.c_int
    if hasattr(lib, "openqpep_wire_v5_pack"):
        lib.openqpep_wire_v5_pack.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_uint8, ctypes.c_uint8, ctypes.c_char_p, ctypes.c_int,
            _c_void_p, ctypes.c_size_t,
        ]
        lib.openqpep_wire_v5_pack.restype = ctypes.c_int
    if hasattr(lib, "openqpep_wire_v5_unpack"):
        lib.openqpep_wire_v5_unpack.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_int, _c_void_p, ctypes.c_size_t, _c_void_p, _c_void_p, _c_void_p,
        ]
        lib.openqpep_wire_v5_unpack.restype = ctypes.c_int
    if hasattr(lib, "openqpep_wire_validate_tlv"):
        lib.openqpep_wire_validate_tlv.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint32, _c_void_p,
        ]
        lib.openqpep_wire_validate_tlv.restype = ctypes.c_int
    if hasattr(lib, "openqpep_cc512_derive_cmt4_subkeys"):
        lib.openqpep_cc512_derive_cmt4_subkeys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, _c_void_p]
        lib.openqpep_cc512_derive_cmt4_subkeys.restype = ctypes.c_int
    if hasattr(lib, "openqpep_cc512_cmt4_tag"):
        lib.openqpep_cc512_cmt4_tag.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t, _c_void_p,
        ]
        lib.openqpep_cc512_cmt4_tag.restype = ctypes.c_int
    if hasattr(lib, "openqpep_cc512_verify_cmt4_tag"):
        lib.openqpep_cc512_verify_cmt4_tag.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
        ]
        lib.openqpep_cc512_verify_cmt4_tag.restype = ctypes.c_int
    if hasattr(lib, "openqpep_cc512_siv_master_subkeys"):
        lib.openqpep_cc512_siv_master_subkeys.argtypes = [ctypes.c_char_p, _c_void_p]
        lib.openqpep_cc512_siv_master_subkeys.restype = ctypes.c_int
    if hasattr(lib, "openqpep_cc512_siv_synth"):
        lib.openqpep_cc512_siv_synth.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, _c_void_p,
        ]
        lib.openqpep_cc512_siv_synth.restype = ctypes.c_int
    if hasattr(lib, "openqpep_cc512_siv_msg_keys"):
        lib.openqpep_cc512_siv_msg_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, _c_void_p]
        lib.openqpep_cc512_siv_msg_keys.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_wots_chain"):
        lib.openqpep_qhs_wots_chain.argtypes = [
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint16, _c_void_p,
        ]
        lib.openqpep_qhs_wots_chain.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_wots_pk_from_sk_seed"):
        lib.openqpep_qhs_wots_pk_from_sk_seed.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, _c_void_p,
        ]
        lib.openqpep_qhs_wots_pk_from_sk_seed.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_wots_sign"):
        lib.openqpep_qhs_wots_sign.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, _c_void_p,
        ]
        lib.openqpep_qhs_wots_sign.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_wots_pk_from_sig"):
        lib.openqpep_qhs_wots_pk_from_sig.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, _c_void_p,
        ]
        lib.openqpep_qhs_wots_pk_from_sig.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_treehash_subtree"):
        lib.openqpep_qhs_treehash_subtree.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.c_int, _c_void_p, _c_void_p,
        ]
        lib.openqpep_qhs_treehash_subtree.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_fold_subtrees"):
        lib.openqpep_qhs_fold_subtrees.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.c_int, _c_void_p, _c_void_p,
        ]
        lib.openqpep_qhs_fold_subtrees.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_keygen_from_seeds"):
        lib.openqpep_qhs_keygen_from_seeds.argtypes = [
            ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p, _c_void_p, _c_void_p,
        ]
        lib.openqpep_qhs_keygen_from_seeds.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_sign_core"):
        lib.openqpep_qhs_sign_core.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_int, ctypes.c_char_p, _c_void_p, ctypes.c_size_t,
        ]
        lib.openqpep_qhs_sign_core.restype = ctypes.c_int
    if hasattr(lib, "openqpep_qhs_verify"):
        lib.openqpep_qhs_verify.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
        ]
        lib.openqpep_qhs_verify.restype = ctypes.c_int


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


def _wipe_i32_array(arr: array.array) -> None:
    if _LIB is not None and hasattr(_LIB, "openqpep_explicit_bzero") and len(arr) > 0:
        addr, count = arr.buffer_info()
        _LIB.openqpep_explicit_bzero(addr, count * arr.itemsize)


def native_ntt_base_mul_acc_3329(acc: List[int], a_hat: List[int], b_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_ntt_base_mul_acc_3329")):
        return None
    acc_arr = array.array("i", acc)
    a_arr = array.array("i", a_hat)
    b_arr = array.array("i", b_hat)
    try:
        _LIB.openqpep_ntt_base_mul_acc_3329(acc_arr.buffer_info()[0], a_arr.buffer_info()[0], b_arr.buffer_info()[0])
        return acc_arr.tolist()
    finally:
        _wipe_i32_array(acc_arr)
        _wipe_i32_array(a_arr)
        _wipe_i32_array(b_arr)


def native_poly_add_qvs(a: List[int], b: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_poly_add_qvs")):
        return None
    a_arr = array.array("i", a)
    b_arr = array.array("i", b)
    out = array.array("i", _ZERO_256_I32)
    try:
        _LIB.openqpep_poly_add_qvs(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
        return out.tolist()
    finally:
        _wipe_i32_array(a_arr)
        _wipe_i32_array(b_arr)
        _wipe_i32_array(out)


def native_poly_sub_qvs(a: List[int], b: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_poly_sub_qvs")):
        return None
    a_arr = array.array("i", a)
    b_arr = array.array("i", b)
    out = array.array("i", _ZERO_256_I32)
    try:
        _LIB.openqpep_poly_sub_qvs(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
        return out.tolist()
    finally:
        _wipe_i32_array(a_arr)
        _wipe_i32_array(b_arr)
        _wipe_i32_array(out)


def native_qvs_decompose_poly(poly: List[int]) -> Optional[Tuple[List[int], List[int]]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_decompose_poly")):
        return None
    p_arr = array.array("i", poly)
    r1_arr = array.array("i", _ZERO_256_I32)
    r0_arr = array.array("i", _ZERO_256_I32)
    try:
        rc = int(_LIB.openqpep_qvs_decompose_poly(p_arr.buffer_info()[0], r1_arr.buffer_info()[0], r0_arr.buffer_info()[0]))
        if rc != 0:
            raise ValueError(f"openqpep_qvs_decompose_poly failed with status {rc}.")
        return r1_arr.tolist(), r0_arr.tolist()
    finally:
        _wipe_i32_array(p_arr)
        _wipe_i32_array(r1_arr)
        _wipe_i32_array(r0_arr)


def native_byte_encode_12(poly: List[int]) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_byte_encode_12")):
        return None
    p_arr = array.array("i", poly)
    out = ctypes.create_string_buffer(384)
    try:
        rc = int(_LIB.openqpep_byte_encode_12(p_arr.buffer_info()[0], out))
        if rc != 0:
            raise ValueError(f"openqpep_byte_encode_12 failed with status {rc}.")
        return out.raw
    finally:
        _wipe_i32_array(p_arr)


def native_byte_decode_12(data: bytes) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_byte_decode_12")):
        return None
    raw = data if isinstance(data, bytes) else bytes(data)
    if len(raw) != 384:
        raise ValueError(f"byte_decode_12 requires exactly 384 bytes, got {len(raw)}.")
    out = array.array("i", _ZERO_256_I32)
    try:
        rc = int(_LIB.openqpep_byte_decode_12(raw, out.buffer_info()[0]))
        if rc != 0:
            raise ValueError(f"openqpep_byte_decode_12 failed with status {rc}.")
        return out.tolist()
    finally:
        _wipe_i32_array(out)


def native_poly_compress_3329(poly: List[int], d: int) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_poly_compress_3329")):
        return None
    if d < 1 or d > 12:
        raise ValueError(f"compress_poly bit width d must be in 1..12, got {d}.")
    p_arr = array.array("i", poly)
    out_len = 32 * d
    out = ctypes.create_string_buffer(out_len)
    try:
        rc = int(_LIB.openqpep_poly_compress_3329(p_arr.buffer_info()[0], d, out, out_len))
        if rc != 0:
            raise ValueError(f"openqpep_poly_compress_3329 failed with status {rc}.")
        return out.raw
    finally:
        _wipe_i32_array(p_arr)


def native_poly_decompress_3329(data: bytes, d: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_poly_decompress_3329")):
        return None
    if d < 1 or d > 12:
        raise ValueError(f"decompress_poly bit width d must be in 1..12, got {d}.")
    raw = data if isinstance(data, bytes) else bytes(data)
    if len(raw) != 32 * d:
        raise ValueError(f"decompress_poly requires exactly {32 * d} bytes for d={d}, got {len(raw)}.")
    out = array.array("i", _ZERO_256_I32)
    try:
        rc = int(_LIB.openqpep_poly_decompress_3329(raw, len(raw), d, out.buffer_info()[0]))
        if rc != 0:
            raise ValueError(f"openqpep_poly_decompress_3329 failed with status {rc}.")
        return out.tolist()
    finally:
        _wipe_i32_array(out)


def native_qlx_sample_ntt_3329(rho: bytes, row: int, col: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qlx_sample_ntt_3329")):
        return None
    raw_rho = rho if isinstance(rho, bytes) else bytes(rho)
    if len(raw_rho) != 32:
        return None
    out = array.array("i", _ZERO_256_I32)
    rc = int(_LIB.openqpep_qlx_sample_ntt_3329(raw_rho, row & 0xFF, col & 0xFF, out.buffer_info()[0]))
    if rc != 0:
        raise ValueError(f"openqpep_qlx_sample_ntt_3329 failed with status {rc}.")
    return out.tolist()


def native_qlx_matvec_3329(
    rho: bytes,
    k: int,
    transpose: bool,
    vec_hat: List[List[int]],
    add_hat: Optional[List[List[int]]] = None,
) -> Optional[List[List[int]]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qlx_matvec_3329")):
        return None
    raw_rho = rho if isinstance(rho, bytes) else bytes(rho)
    if len(raw_rho) != 32 or k <= 0 or len(vec_hat) != k:
        return None
    vec_flat = array.array("i")
    for p in vec_hat:
        vec_flat.extend(p)
    add_flat: Optional[array.array] = None
    add_ptr = None
    if add_hat is not None:
        if len(add_hat) != k:
            raise ValueError(f"add_hat length {len(add_hat)} does not match k={k}.")
        add_flat = array.array("i")
        for p in add_hat:
            add_flat.extend(p)
        add_ptr = add_flat.buffer_info()[0]
    out_flat = array.array("i", [0] * (k * 256))
    try:
        rc = int(
            _LIB.openqpep_qlx_matvec_3329(
                raw_rho,
                k,
                1 if transpose else 0,
                vec_flat.buffer_info()[0],
                add_ptr,
                out_flat.buffer_info()[0],
            )
        )
        if rc != 0:
            raise ValueError(f"openqpep_qlx_matvec_3329 failed with status {rc}.")
        return [out_flat[256 * i : 256 * (i + 1)].tolist() for i in range(k)]
    finally:
        _wipe_i32_array(vec_flat)
        if add_flat is not None:
            _wipe_i32_array(add_flat)
        _wipe_i32_array(out_flat)


def native_qlx_inner_prod_3329(a_vec_hat: List[List[int]], b_vec_hat: List[List[int]]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qlx_inner_prod_3329")):
        return None
    k = len(a_vec_hat)
    if k == 0 or len(b_vec_hat) != k:
        return None
    a_flat = array.array("i")
    for p in a_vec_hat:
        a_flat.extend(p)
    b_flat = array.array("i")
    for p in b_vec_hat:
        b_flat.extend(p)
    out = array.array("i", _ZERO_256_I32)
    try:
        rc = int(_LIB.openqpep_qlx_inner_prod_3329(a_flat.buffer_info()[0], b_flat.buffer_info()[0], k, out.buffer_info()[0]))
        if rc != 0:
            raise ValueError(f"openqpep_qlx_inner_prod_3329 failed with status {rc}.")
        return out.tolist()
    finally:
        _wipe_i32_array(a_flat)
        _wipe_i32_array(b_flat)
        _wipe_i32_array(out)


def native_qvs_pack_poly24(poly: List[int]) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_pack_poly24")):
        return None
    p_arr = array.array("i", poly)
    out = ctypes.create_string_buffer(768)
    try:
        rc = int(_LIB.openqpep_qvs_pack_poly24(p_arr.buffer_info()[0], out))
        if rc != 0:
            raise ValueError(f"openqpep_qvs_pack_poly24 failed with status {rc}.")
        return out.raw
    finally:
        _wipe_i32_array(p_arr)


def native_qvs_unpack_poly24(data: bytes) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_unpack_poly24")):
        return None
    raw = data if isinstance(data, bytes) else bytes(data)
    if len(raw) != 768:
        raise ValueError(f"unpack_poly24_qvs requires exactly 768 bytes, got {len(raw)}.")
    out = array.array("i", _ZERO_256_I32)
    try:
        rc = int(_LIB.openqpep_qvs_unpack_poly24(raw, out.buffer_info()[0]))
        if rc != 0:
            raise ValueError(f"openqpep_qvs_unpack_poly24 failed with status {rc}.")
        return out.tolist()
    finally:
        _wipe_i32_array(out)


def native_qvs_sample_ntt(rho: bytes, row: int, col: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_sample_ntt")):
        return None
    raw_rho = rho if isinstance(rho, bytes) else bytes(rho)
    if len(raw_rho) != 32:
        return None
    out = array.array("i", _ZERO_256_I32)
    rc = int(_LIB.openqpep_qvs_sample_ntt(raw_rho, row & 0xFF, col & 0xFF, out.buffer_info()[0]))
    if rc != 0:
        raise ValueError(f"openqpep_qvs_sample_ntt failed with status {rc}.")
    return out.tolist()


def native_qvs_sample_mask_y(seed: bytes, nonce: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_sample_mask_y")):
        return None
    raw_seed = seed if isinstance(seed, bytes) else bytes(seed)
    out = array.array("i", _ZERO_256_I32)
    try:
        rc = int(_LIB.openqpep_qvs_sample_mask_y(raw_seed if raw_seed else None, len(raw_seed), nonce & 0xFFFF, out.buffer_info()[0]))
        if rc != 0:
            raise ValueError(f"openqpep_qvs_sample_mask_y failed with status {rc}.")
        return out.tolist()
    finally:
        _wipe_i32_array(out)


def native_qvs_sample_in_ball(c_tilde: bytes, tau: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_sample_in_ball")):
        return None
    raw = c_tilde if isinstance(c_tilde, bytes) else bytes(c_tilde)
    out = array.array("i", _ZERO_256_I32)
    rc = int(_LIB.openqpep_qvs_sample_in_ball(raw if raw else None, len(raw), tau, out.buffer_info()[0]))
    if rc != 0:
        raise ValueError(f"openqpep_qvs_sample_in_ball failed with status {rc}.")
    return out.tolist()


def native_qvs_expand_matrix(rho: bytes, k: int, l: int) -> Optional[array.array]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_expand_matrix")):
        return None
    raw_rho = rho if isinstance(rho, bytes) else bytes(rho)
    if len(raw_rho) != 32 or k <= 0 or l <= 0:
        return None
    a_flat = array.array("i", [0] * (k * l * 256))
    rc = int(_LIB.openqpep_qvs_expand_matrix(raw_rho, k, l, a_flat.buffer_info()[0]))
    if rc != 0:
        raise ValueError(f"openqpep_qvs_expand_matrix failed with status {rc}.")
    return a_flat


def native_qvs_matvec_precomputed(
    a_hat_flat: array.array,
    k: int,
    l: int,
    vec_hat: List[List[int]],
) -> Optional[List[List[int]]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_matvec_precomputed")):
        return None
    if k <= 0 or l <= 0 or len(vec_hat) != l or len(a_hat_flat) != k * l * 256:
        return None
    vec_flat = array.array("i")
    for p in vec_hat:
        vec_flat.extend(p)
    out_flat = array.array("i", [0] * (k * 256))
    try:
        rc = int(
            _LIB.openqpep_qvs_matvec_precomputed(
                a_hat_flat.buffer_info()[0],
                k,
                l,
                vec_flat.buffer_info()[0],
                out_flat.buffer_info()[0],
            )
        )
        if rc != 0:
            raise ValueError(f"openqpep_qvs_matvec_precomputed failed with status {rc}.")
        return [out_flat[256 * i : 256 * (i + 1)].tolist() for i in range(k)]
    finally:
        _wipe_i32_array(vec_flat)
        _wipe_i32_array(out_flat)


def native_qvs_matvec(
    rho: bytes,
    k: int,
    l: int,
    vec_hat: List[List[int]],
    add_vec: Optional[List[List[int]]] = None,
    apply_inv_ntt: bool = False,
) -> Optional[List[List[int]]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qvs_matvec")):
        return None
    raw_rho = rho if isinstance(rho, bytes) else bytes(rho)
    if len(raw_rho) != 32 or k <= 0 or l <= 0 or len(vec_hat) != l:
        return None
    vec_flat = array.array("i")
    for p in vec_hat:
        vec_flat.extend(p)
    add_flat: Optional[array.array] = None
    add_ptr = None
    if add_vec is not None:
        if len(add_vec) != k:
            raise ValueError(f"add_vec length {len(add_vec)} does not match k={k}.")
        add_flat = array.array("i")
        for p in add_vec:
            add_flat.extend(p)
        add_ptr = add_flat.buffer_info()[0]
    out_flat = array.array("i", [0] * (k * 256))
    try:
        rc = int(
            _LIB.openqpep_qvs_matvec(
                raw_rho,
                k,
                l,
                vec_flat.buffer_info()[0],
                add_ptr,
                1 if apply_inv_ntt else 0,
                out_flat.buffer_info()[0],
            )
        )
        if rc != 0:
            raise ValueError(f"openqpep_qvs_matvec failed with status {rc}.")
        return [out_flat[256 * i : 256 * (i + 1)].tolist() for i in range(k)]
    finally:
        _wipe_i32_array(vec_flat)
        if add_flat is not None:
            _wipe_i32_array(add_flat)
        _wipe_i32_array(out_flat)


def _wipe_ctypes_buf(buf: ctypes.Array) -> None:
    if _LIB is not None and hasattr(_LIB, "openqpep_explicit_bzero") and len(buf) > 0:
        _LIB.openqpep_explicit_bzero(ctypes.addressof(buf), len(buf))


def native_plain_lwe_sample_noise(domain: bytes, seed: bytes, count: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_plain_lwe_sample_noise")):
        return None
    if count < 0:
        raise ValueError("count must be non-negative.")
    if count == 0:
        return []
    dom_b = domain if isinstance(domain, bytes) else bytes(domain)
    seed_b = seed if isinstance(seed, bytes) else bytes(seed)
    out = array.array("H", [0] * count)
    try:
        rc = int(
            _LIB.openqpep_plain_lwe_sample_noise(
                dom_b if dom_b else None,
                len(dom_b),
                seed_b if seed_b else None,
                len(seed_b),
                count,
                out.buffer_info()[0],
            )
        )
        if rc != 0:
            raise ValueError(f"openqpep_plain_lwe_sample_noise failed with status {rc}.")
        return out.tolist()
    finally:
        _wipe_i32_array(out)


def native_plain_lwe_expand_row(seed_a: bytes, row_idx: int, n: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_plain_lwe_expand_row")):
        return None
    raw_seed = seed_a if isinstance(seed_a, bytes) else bytes(seed_a)
    if len(raw_seed) != 32 or n <= 0:
        return None
    out = array.array("H", [0] * n)
    rc = int(_LIB.openqpep_plain_lwe_expand_row(raw_seed, row_idx & 0xFFFFFFFF, n, out.buffer_info()[0]))
    if rc != 0:
        raise ValueError(f"openqpep_plain_lwe_expand_row failed with status {rc}.")
    return out.tolist()


def native_plain_lwe_keygen_matrix(
    seed_a: bytes,
    s_flat: List[int],
    e_flat: List[int],
    n: int,
    nbar: int,
) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_plain_lwe_keygen_matrix")):
        return None
    raw_seed = seed_a if isinstance(seed_a, bytes) else bytes(seed_a)
    elems = n * nbar
    if len(raw_seed) != 32 or n <= 0 or nbar <= 0 or len(s_flat) != elems or len(e_flat) != elems:
        return None
    s_arr = array.array("H", s_flat)
    e_arr = array.array("H", e_flat)
    b_arr = array.array("H", [0] * elems)
    try:
        rc = int(
            _LIB.openqpep_plain_lwe_keygen_matrix(
                raw_seed,
                s_arr.buffer_info()[0],
                e_arr.buffer_info()[0],
                n,
                nbar,
                b_arr.buffer_info()[0],
            )
        )
        if rc != 0:
            raise ValueError(f"openqpep_plain_lwe_keygen_matrix failed with status {rc}.")
        return b_arr.tolist()
    finally:
        _wipe_i32_array(s_arr)
        _wipe_i32_array(e_arr)
        _wipe_i32_array(b_arr)


def native_plain_lwe_keygen_from_seeds(
    n: int,
    nbar: int,
    seed_a: bytes,
    seed_s: bytes,
    seed_z: bytes,
) -> Optional[Tuple[bytes, bytes]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_plain_lwe_keygen_from_seeds")):
        return None
    sa = seed_a if isinstance(seed_a, bytes) else bytes(seed_a)
    ss = seed_s if isinstance(seed_s, bytes) else bytes(seed_s)
    sz = seed_z if isinstance(seed_z, bytes) else bytes(seed_z)
    if len(sa) != 32 or len(ss) != 32 or len(sz) != 32 or n <= 0 or nbar <= 0:
        return None
    elems = n * nbar
    pk_len = 36 + 2 * elems
    sk_len = 36 + pk_len + 2 * elems
    pk_buf = ctypes.create_string_buffer(pk_len)
    sk_buf = ctypes.create_string_buffer(sk_len)
    try:
        rc = int(_LIB.openqpep_plain_lwe_keygen_from_seeds(n, nbar, sa, ss, sz, pk_buf, pk_len, sk_buf, sk_len))
        if rc != 0:
            raise ValueError(f"openqpep_plain_lwe_keygen_from_seeds failed with status {rc}.")
        return pk_buf.raw, sk_buf.raw
    finally:
        _wipe_ctypes_buf(sk_buf)


def native_plain_lwe_indcpa_enc(pk: bytes, msg16: bytes, coins32: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_plain_lwe_indcpa_enc")):
        return None
    pk_b = pk if isinstance(pk, bytes) else bytes(pk)
    m_b = msg16 if isinstance(msg16, bytes) else bytes(msg16)
    c_b = coins32 if isinstance(coins32, bytes) else bytes(coins32)
    if len(pk_b) < 36 or len(m_b) != 16 or len(c_b) != 32:
        return None
    n = pk_b[0] | (pk_b[1] << 8)
    nbar = pk_b[2] | (pk_b[3] << 8)
    ct_len = 2 * nbar * n + 2 * nbar * nbar
    ct_buf = ctypes.create_string_buffer(ct_len)
    rc = int(_LIB.openqpep_plain_lwe_indcpa_enc(pk_b, len(pk_b), m_b, c_b, ct_buf, ct_len))
    if rc != 0:
        raise ValueError(f"openqpep_plain_lwe_indcpa_enc failed with status {rc}.")
    return ct_buf.raw


def native_plain_lwe_encaps(pk: bytes, msg16: bytes) -> Optional[Tuple[bytes, bytes]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_plain_lwe_encaps")):
        return None
    pk_b = pk if isinstance(pk, bytes) else bytes(pk)
    m_b = msg16 if isinstance(msg16, bytes) else bytes(msg16)
    if len(pk_b) < 36 or len(m_b) != 16:
        return None
    n = pk_b[0] | (pk_b[1] << 8)
    nbar = pk_b[2] | (pk_b[3] << 8)
    ct_len = 2 * nbar * n + 2 * nbar * nbar
    ct_buf = ctypes.create_string_buffer(ct_len)
    ss_buf = ctypes.create_string_buffer(32)
    try:
        rc = int(_LIB.openqpep_plain_lwe_encaps(pk_b, len(pk_b), m_b, ct_buf, ct_len, ss_buf))
        if rc != 0:
            raise ValueError(f"openqpep_plain_lwe_encaps failed with status {rc}.")
        return ct_buf.raw, ss_buf.raw
    finally:
        _wipe_ctypes_buf(ss_buf)


def native_plain_lwe_decaps(sk: bytes, ct: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_plain_lwe_decaps")):
        return None
    sk_b = sk if isinstance(sk, bytes) else bytes(sk)
    ct_b = ct if isinstance(ct, bytes) else bytes(ct)
    ss_buf = ctypes.create_string_buffer(32)
    try:
        rc = int(_LIB.openqpep_plain_lwe_decaps(sk_b, len(sk_b), ct_b, len(ct_b), ss_buf))
        if rc != 0:
            raise ValueError(f"openqpep_plain_lwe_decaps failed with status {rc}.")
        return ss_buf.raw
    finally:
        _wipe_ctypes_buf(ss_buf)


def native_gf2m10_mul(a: int, b: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_gf2m10_mul")):
        return None
    return int(_LIB.openqpep_gf2m10_mul(a & 0x3FF, b & 0x3FF))


def native_gf2m10_sq(a: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_gf2m10_sq")):
        return None
    return int(_LIB.openqpep_gf2m10_sq(a & 0x3FF))


def native_gf2m10_inv(a: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_gf2m10_inv")):
        return None
    return int(_LIB.openqpep_gf2m10_inv(a & 0x3FF))


def native_gf2m10_sqrt(a: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_gf2m10_sqrt")):
        return None
    return int(_LIB.openqpep_gf2m10_sqrt(a & 0x3FF))


def native_goppa_poly_eval(poly: List[int], a: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_goppa_poly_eval")):
        return None
    if not poly:
        return 0
    p_arr = array.array("H", (c & 0x3FF for c in poly))
    try:
        return int(_LIB.openqpep_goppa_poly_eval(p_arr.buffer_info()[0], len(p_arr), a & 0x3FF))
    finally:
        _wipe_i32_array(p_arr)


def native_goppa_poly_eval_batch(poly: List[int], points: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_goppa_poly_eval_batch")):
        return None
    if not poly:
        raise ValueError("poly must be non-empty.")
    if not points:
        return []
    p_arr = array.array("H", (c & 0x3FF for c in poly))
    pt_arr = array.array("H", (x & 0x3FF for x in points))
    out_arr = array.array("H", [0] * len(points))
    try:
        rc = int(
            _LIB.openqpep_goppa_poly_eval_batch(
                p_arr.buffer_info()[0],
                len(p_arr),
                pt_arr.buffer_info()[0],
                len(pt_arr),
                out_arr.buffer_info()[0],
            )
        )
        if rc != 0:
            raise ValueError(f"openqpep_goppa_poly_eval_batch failed with status {rc}.")
        return out_arr.tolist()
    finally:
        _wipe_i32_array(p_arr)
        _wipe_i32_array(pt_arr)
        _wipe_i32_array(out_arr)


def native_goppa_is_irreducible(g: List[int], degree: int) -> Optional[bool]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_goppa_is_irreducible")):
        return None
    if degree < 1 or len(g) != degree + 1:
        return False
    g_arr = array.array("H", (c & 0x3FF for c in g))
    try:
        return bool(_LIB.openqpep_goppa_is_irreducible(g_arr.buffer_info()[0], degree))
    finally:
        _wipe_i32_array(g_arr)


def native_goppa_build_systematic_t(g: List[int], support: List[int]) -> Optional[Tuple[bool, bytes]]:
    """
    Returns None when native is unavailable; otherwise (True, t_bytes_28160) on invertible
    systematic reduction or (False, b"") if the left 320x320 block is singular.
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_goppa_build_systematic_t")):
        return None
    if len(g) != 33 or len(support) != 1024:
        raise ValueError("openqpep_goppa_build_systematic_t requires len(g)==33 and len(support)==1024.")
    g_arr = array.array("H", (c & 0x3FF for c in g))
    sup_arr = array.array("H", (a & 0x3FF for a in support))
    t_buf = ctypes.create_string_buffer(28160)
    try:
        rc = int(_LIB.openqpep_goppa_build_systematic_t(g_arr.buffer_info()[0], sup_arr.buffer_info()[0], t_buf))
        if rc == 0:
            return True, t_buf.raw
        if rc == -6:  # OPENQPEP_ERR_SINGULAR
            return False, b""
        raise ValueError(f"openqpep_goppa_build_systematic_t failed with status {rc}.")
    finally:
        _wipe_i32_array(g_arr)
        _wipe_i32_array(sup_arr)


def native_goppa_syndrome(t_bytes: bytes, err128: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_goppa_syndrome")):
        return None
    tb = t_bytes if isinstance(t_bytes, bytes) else bytes(t_bytes)
    eb = err128 if isinstance(err128, bytes) else bytes(err128)
    if len(tb) != 28160 or len(eb) != 128:
        raise ValueError(f"openqpep_goppa_syndrome requires t_bytes=28160 and err128=128, got {len(tb)}, {len(eb)}.")
    syn_buf = ctypes.create_string_buffer(40)
    rc = int(_LIB.openqpep_goppa_syndrome(tb, len(tb), eb, syn_buf))
    if rc != 0:
        raise ValueError(f"openqpep_goppa_syndrome failed with status {rc}.")
    return syn_buf.raw


def native_goppa_chien_search(sigma: List[int], support: List[int]) -> Optional[Tuple[bytes, int]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_goppa_chien_search")):
        return None
    if not sigma or len(support) != 1024:
        raise ValueError("openqpep_goppa_chien_search requires non-empty sigma and len(support)==1024.")
    sig_arr = array.array("H", (c & 0x3FF for c in sigma))
    sup_arr = array.array("H", (a & 0x3FF for a in support))
    err_buf = ctypes.create_string_buffer(128)
    wt = ctypes.c_uint32(0)
    try:
        rc = int(
            _LIB.openqpep_goppa_chien_search(
                sig_arr.buffer_info()[0],
                len(sig_arr),
                sup_arr.buffer_info()[0],
                err_buf,
                ctypes.byref(wt),
            )
        )
        if rc != 0:
            raise ValueError(f"openqpep_goppa_chien_search failed with status {rc}.")
        return err_buf.raw, int(wt.value)
    finally:
        _wipe_i32_array(sig_arr)
        _wipe_i32_array(sup_arr)
        _wipe_ctypes_buf(err_buf)


def native_goppa_patterson_decode(
    g: List[int],
    support: List[int],
    syn40: bytes,
) -> Optional[Tuple[bool, bytes, int]]:
    """
    Returns None when native is unavailable; otherwise (decoded_ok, err128, found_wt).
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_goppa_patterson_decode")):
        return None
    sb = syn40 if isinstance(syn40, bytes) else bytes(syn40)
    if len(g) != 33 or len(support) != 1024 or len(sb) != 40:
        raise ValueError("openqpep_goppa_patterson_decode requires len(g)==33, len(support)==1024, len(syn40)==40.")
    g_arr = array.array("H", (c & 0x3FF for c in g))
    sup_arr = array.array("H", (a & 0x3FF for a in support))
    err_buf = ctypes.create_string_buffer(128)
    wt = ctypes.c_uint32(0)
    try:
        rc = int(
            _LIB.openqpep_goppa_patterson_decode(
                g_arr.buffer_info()[0],
                sup_arr.buffer_info()[0],
                sb,
                err_buf,
                ctypes.byref(wt),
            )
        )
        if rc == 0:
            return True, err_buf.raw, int(wt.value)
        if rc == -3:  # OPENQPEP_ERR_AUTH_FAIL (algebraic decode rejected)
            return False, err_buf.raw, int(wt.value)
        raise ValueError(f"openqpep_goppa_patterson_decode failed with status {rc}.")
    finally:
        _wipe_i32_array(g_arr)
        _wipe_i32_array(sup_arr)
        _wipe_ctypes_buf(err_buf)


def native_gf2_127_mul(a: int, b: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_gf2_127_mul")):
        return None
    a_b = (a & ((1 << 127) - 1)).to_bytes(16, "little")
    b_b = (b & ((1 << 127) - 1)).to_bytes(16, "little")
    out = ctypes.create_string_buffer(16)
    rc = int(_LIB.openqpep_gf2_127_mul(a_b, b_b, out))
    if rc != 0:
        raise ValueError(f"openqpep_gf2_127_mul failed with status {rc}.")
    return int.from_bytes(out.raw, "little")


def native_gf2_127_sq(a: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_gf2_127_sq")):
        return None
    a_b = (a & ((1 << 127) - 1)).to_bytes(16, "little")
    out = ctypes.create_string_buffer(16)
    rc = int(_LIB.openqpep_gf2_127_sq(a_b, out))
    if rc != 0:
        raise ValueError(f"openqpep_gf2_127_sq failed with status {rc}.")
    return int.from_bytes(out.raw, "little")


def native_gf2_127_inv(a: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_gf2_127_inv")):
        return None
    a_b = (a & ((1 << 127) - 1)).to_bytes(16, "little")
    out = ctypes.create_string_buffer(16)
    rc = int(_LIB.openqpep_gf2_127_inv(a_b, out))
    if rc != 0:
        raise ValueError(f"openqpep_gf2_127_inv failed with status {rc}.")
    return int.from_bytes(out.raw, "little")


def native_lrpc_ring_mul(a_bytes: bytes, b_bytes: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_lrpc_ring_mul")):
        return None
    ab = a_bytes if isinstance(a_bytes, bytes) else bytes(a_bytes)
    bb = b_bytes if isinstance(b_bytes, bytes) else bytes(b_bytes)
    if len(ab) != 752 or len(bb) != 752:
        raise ValueError(f"openqpep_lrpc_ring_mul requires 752-byte polys, got {len(ab)}, {len(bb)}.")
    out = ctypes.create_string_buffer(752)
    try:
        rc = int(_LIB.openqpep_lrpc_ring_mul(ab, bb, out))
        if rc != 0:
            raise ValueError(f"openqpep_lrpc_ring_mul failed with status {rc}.")
        return out.raw
    finally:
        _wipe_ctypes_buf(out)


def native_lrpc_ring_inv(a_bytes: bytes) -> Optional[Tuple[bool, bytes]]:
    """
    Returns None when native is unavailable; otherwise (True, inv752) on success
    or (False, b"") when `a_bytes` is non-invertible in GF(2^127)[X]/(X^47+X^5+1).
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_lrpc_ring_inv")):
        return None
    ab = a_bytes if isinstance(a_bytes, bytes) else bytes(a_bytes)
    if len(ab) != 752:
        raise ValueError(f"openqpep_lrpc_ring_inv requires 752-byte poly, got {len(ab)}.")
    out = ctypes.create_string_buffer(752)
    try:
        rc = int(_LIB.openqpep_lrpc_ring_inv(ab, out))
        if rc == 0:
            return True, out.raw
        if rc == -6:  # OPENQPEP_ERR_SINGULAR
            return False, b""
        raise ValueError(f"openqpep_lrpc_ring_inv failed with status {rc}.")
    finally:
        _wipe_ctypes_buf(out)


def native_gf256_inv(a: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_gf256_inv")):
        return None
    return int(_LIB.openqpep_gf256_inv(a & 0xFF))


def native_uov_solve_gf256_linear(mat_flat: bytes, rhs: bytes, m: int) -> Optional[Tuple[bool, bytes]]:
    """
    Returns None when native is unavailable; otherwise (True, sol_bytes) on success
    or (False, b"") when the m x m linear system over GF(256) is singular.
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_uov_solve_gf256_linear")):
        return None
    mb = mat_flat if isinstance(mat_flat, bytes) else bytes(mat_flat)
    rb = rhs if isinstance(rhs, bytes) else bytes(rhs)
    if m <= 0 or len(mb) != m * m or len(rb) != m:
        raise ValueError(f"Invalid linear system dimensions for m={m}.")
    sol = ctypes.create_string_buffer(m)
    try:
        rc = int(_LIB.openqpep_uov_solve_gf256_linear(mb, rb, m, sol))
        if rc == 0:
            return True, sol.raw
        if rc == -6:  # OPENQPEP_ERR_SINGULAR
            return False, b""
        raise ValueError(f"openqpep_uov_solve_gf256_linear failed with status {rc}.")
    finally:
        _wipe_ctypes_buf(sol)


def native_uov_compute_p3(seed_pk: bytes, seed_sk: bytes, v: int, m: int) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_uov_compute_p3")):
        return None
    spk = seed_pk if isinstance(seed_pk, bytes) else bytes(seed_pk)
    ssk = seed_sk if isinstance(seed_sk, bytes) else bytes(seed_sk)
    if len(spk) != 32 or len(ssk) != 32 or v <= 0 or m <= 0:
        return None
    p3_len = m * ((m * (m + 1)) // 2)
    p3_buf = ctypes.create_string_buffer(p3_len)
    rc = int(_LIB.openqpep_uov_compute_p3(spk, ssk, v, m, p3_buf, p3_len))
    if rc != 0:
        raise ValueError(f"openqpep_uov_compute_p3 failed with status {rc}.")
    return p3_buf.raw


def native_uov_eval_public_map(
    seed_pk: bytes,
    p3_bytes: bytes,
    v: int,
    m: int,
    sv: bytes,
    so: bytes,
) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_uov_eval_public_map")):
        return None
    spk = seed_pk if isinstance(seed_pk, bytes) else bytes(seed_pk)
    p3b = p3_bytes if isinstance(p3_bytes, bytes) else bytes(p3_bytes)
    svb = sv if isinstance(sv, bytes) else bytes(sv)
    sob = so if isinstance(so, bytes) else bytes(so)
    if len(spk) != 32 or len(svb) != v or len(sob) != m:
        return None
    out = ctypes.create_string_buffer(m)
    rc = int(_LIB.openqpep_uov_eval_public_map(spk, p3b, len(p3b), v, m, svb, sob, out))
    if rc != 0:
        raise ValueError(f"openqpep_uov_eval_public_map failed with status {rc}.")
    return out.raw


def native_uov_sign_core(
    seed_pk: bytes,
    seed_sk: bytes,
    salt: bytes,
    target: bytes,
    v: int,
    m: int,
) -> Optional[Tuple[bool, bytes, bytes]]:
    """
    Returns None when native is unavailable; otherwise (True, sv_bytes, so_bytes) on success
    or (False, b"", b"") if no invertible oil system was found within 64 vinegar attempts.
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_uov_sign_core")):
        return None
    spk = seed_pk if isinstance(seed_pk, bytes) else bytes(seed_pk)
    ssk = seed_sk if isinstance(seed_sk, bytes) else bytes(seed_sk)
    sb = salt if isinstance(salt, bytes) else bytes(salt)
    tb = target if isinstance(target, bytes) else bytes(target)
    if len(spk) != 32 or len(ssk) != 32 or len(sb) != 16 or len(tb) != m:
        return None
    sv_buf = ctypes.create_string_buffer(v)
    so_buf = ctypes.create_string_buffer(m)
    try:
        rc = int(_LIB.openqpep_uov_sign_core(spk, ssk, sb, tb, v, m, sv_buf, so_buf))
        if rc == 0:
            return True, sv_buf.raw, so_buf.raw
        if rc == -6:  # OPENQPEP_ERR_SINGULAR
            return False, b"", b""
        raise ValueError(f"openqpep_uov_sign_core failed with status {rc}.")
    finally:
        _wipe_ctypes_buf(sv_buf)
        _wipe_ctypes_buf(so_buf)


def native_ct_select_u32(cond: int, a: int, b: int) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_ct_select_u32")):
        return None
    return int(_LIB.openqpep_ct_select_u32(cond & 0xFFFFFFFF, a & 0xFFFFFFFF, b & 0xFFFFFFFF))


def native_ct_mem_bounds_ok(offset: int, span: int, total: int) -> Optional[bool]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_ct_mem_bounds_ok")):
        return None
    if offset < 0 or span < 0 or total < 0:
        return False
    return bool(_LIB.openqpep_ct_mem_bounds_ok(offset, span, total))


def native_ct_cmov(cond: bool, a: bytes, b: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_ct_cmov")):
        return None
    ab = a if isinstance(a, bytes) else bytes(a)
    bb = b if isinstance(b, bytes) else bytes(b)
    if len(ab) != len(bb):
        raise ValueError("ct_cmov requires equal-length byte buffers.")
    n = len(ab)
    if n == 0:
        return b""
    out = ctypes.create_string_buffer(n)
    try:
        _LIB.openqpep_ct_cmov(1 if cond else 0, out, ab, bb, n)
        return out.raw
    finally:
        _wipe_ctypes_buf(out)


def native_ct_cswap(cond: bool, a: bytes, b: bytes) -> Optional[Tuple[bytes, bytes]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_ct_cswap")):
        return None
    ab = a if isinstance(a, bytes) else bytes(a)
    bb = b if isinstance(b, bytes) else bytes(b)
    if len(ab) != len(bb):
        raise ValueError("ct_cswap requires equal-length byte buffers.")
    n = len(ab)
    if n == 0:
        return b"", b""
    buf_a = ctypes.create_string_buffer(ab, n)
    buf_b = ctypes.create_string_buffer(bb, n)
    try:
        _LIB.openqpep_ct_cswap(1 if cond else 0, buf_a, buf_b, n)
        return buf_a.raw, buf_b.raw
    finally:
        _wipe_ctypes_buf(buf_a)
        _wipe_ctypes_buf(buf_b)


def native_wire_whiten_xor(
    hdr8: bytes,
    nonce16: bytes,
    label: bytes,
    data: bytes,
    *,
    is_v51: bool = False,
) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_wire_whiten_xor")):
        return None
    hb = hdr8 if isinstance(hdr8, bytes) else bytes(hdr8)
    nb = nonce16 if isinstance(nonce16, bytes) else bytes(nonce16)
    lb = label if isinstance(label, bytes) else bytes(label)
    db = data if isinstance(data, bytes) else bytes(data)
    if len(hb) != 8 or len(nb) != 16:
        raise ValueError("openqpep_wire_whiten_xor requires 8-byte header and 16-byte nonce.")
    if len(db) == 0:
        rc = int(_LIB.openqpep_wire_whiten_xor(hb, nb, lb if lb else None, len(lb), 1 if is_v51 else 0, None, None, 0))
        if rc != 0:
            raise ValueError(f"openqpep_wire_whiten_xor failed with status {rc}.")
        return b""
    out = ctypes.create_string_buffer(len(db))
    rc = int(
        _LIB.openqpep_wire_whiten_xor(
            hb, nb, lb if lb else None, len(lb), 1 if is_v51 else 0, db, out, len(db)
        )
    )
    if rc != 0:
        raise ValueError(f"openqpep_wire_whiten_xor failed with status {rc}.")
    return out.raw


def native_wire_compute_mac(
    hdr8: bytes,
    nonce16: bytes,
    label: bytes,
    whitened: bytes,
    *,
    is_v51: bool = False,
) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_wire_compute_mac")):
        return None
    hb = hdr8 if isinstance(hdr8, bytes) else bytes(hdr8)
    nb = nonce16 if isinstance(nonce16, bytes) else bytes(nonce16)
    lb = label if isinstance(label, bytes) else bytes(label)
    wb = whitened if isinstance(whitened, bytes) else bytes(whitened)
    if len(hb) != 8 or len(nb) != 16:
        raise ValueError("openqpep_wire_compute_mac requires 8-byte header and 16-byte nonce.")
    mac = ctypes.create_string_buffer(32)
    rc = int(
        _LIB.openqpep_wire_compute_mac(
            hb, nb, lb if lb else None, len(lb), 1 if is_v51 else 0, wb if wb else None, len(wb), mac
        )
    )
    if rc != 0:
        raise ValueError(f"openqpep_wire_compute_mac failed with status {rc}.")
    return mac.raw


def native_wire_v5_pack(
    body: bytes,
    label: bytes,
    packet_type: int,
    flags: int,
    nonce16: bytes,
    *,
    is_v51: bool = False,
) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_wire_v5_pack")):
        return None
    bb = body if isinstance(body, bytes) else bytes(body)
    lb = label if isinstance(label, bytes) else bytes(label)
    nb = nonce16 if isinstance(nonce16, bytes) else bytes(nonce16)
    if len(nb) != 16:
        raise ValueError("openqpep_wire_v5_pack requires a 16-byte nonce.")
    total_len = len(bb) + 56
    frame = ctypes.create_string_buffer(total_len)
    rc = int(
        _LIB.openqpep_wire_v5_pack(
            bb if bb else None,
            len(bb),
            lb if lb else None,
            len(lb),
            packet_type & 0xFF,
            flags & 0xFF,
            nb,
            1 if is_v51 else 0,
            frame,
            total_len,
        )
    )
    if rc != 0:
        raise ValueError(f"openqpep_wire_v5_pack failed with status {rc}.")
    return frame.raw


def native_wire_v5_unpack(
    frame: bytes,
    label: bytes,
    *,
    expect_v51: bool = False,
) -> Optional[Tuple[int, bytes, int, int]]:
    """
    Returns None when native is unavailable; otherwise (status_rc, body_bytes, packet_type, flags).
    Status codes match openqpep.h:
      0 (OPENQPEP_OK), -3 (OPENQPEP_ERR_AUTH_FAIL), -4 (OPENQPEP_ERR_LEGACY),
      -7 (OPENQPEP_ERR_WIRE_FORMAT), -2 (OPENQPEP_ERR_INVALID_LEN).
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_wire_v5_unpack")):
        return None
    fb = frame if isinstance(frame, bytes) else bytes(frame)
    lb = label if isinstance(label, bytes) else bytes(label)
    body_cap = len(fb) - 56 if len(fb) >= 56 else 0
    body_buf = ctypes.create_string_buffer(body_cap) if body_cap > 0 else None
    body_len = ctypes.c_size_t(0)
    ptype = ctypes.c_uint8(0)
    flags = ctypes.c_uint8(0)
    try:
        rc = int(
            _LIB.openqpep_wire_v5_unpack(
                fb if fb else None,
                len(fb),
                lb if lb else None,
                len(lb),
                1 if expect_v51 else 0,
                body_buf,
                body_cap,
                ctypes.byref(body_len),
                ctypes.byref(ptype),
                ctypes.byref(flags),
            )
        )
        if rc != 0:
            return rc, b"", 0, 0
        out_bytes = body_buf.raw[: body_len.value] if (body_buf is not None and body_len.value > 0) else b""
        return 0, out_bytes, int(ptype.value), int(flags.value)
    finally:
        if body_buf is not None:
            _wipe_ctypes_buf(body_buf)


def native_wire_validate_tlv(
    raw: bytes,
    *,
    require_canonical_order: bool = True,
    max_fields: int = 256,
) -> Optional[Tuple[bool, int]]:
    """
    Returns None when native is unavailable; otherwise (is_valid, field_count).
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_wire_validate_tlv")):
        return None
    rb = raw if isinstance(raw, bytes) else bytes(raw)
    cnt = ctypes.c_uint32(0)
    rc = int(
        _LIB.openqpep_wire_validate_tlv(
            rb if rb else None,
            len(rb),
            1 if require_canonical_order else 0,
            max_fields & 0xFFFFFFFF,
            ctypes.byref(cnt),
        )
    )
    if rc == 0:
        return True, int(cnt.value)
    return False, 0


def native_cc512_derive_cmt4_subkeys(key64: bytes, nonce24: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_cc512_derive_cmt4_subkeys")):
        return None
    kb = key64 if isinstance(key64, bytes) else bytes(key64)
    nb = nonce24 if isinstance(nonce24, bytes) else bytes(nonce24)
    if len(kb) != 64 or len(nb) != 24:
        return None
    out = ctypes.create_string_buffer(96)
    try:
        rc = int(_LIB.openqpep_cc512_derive_cmt4_subkeys(kb, nb, out))
        if rc != 0:
            raise ValueError(f"openqpep_cc512_derive_cmt4_subkeys failed with status {rc}.")
        return out.raw
    finally:
        _wipe_ctypes_buf(out)


def native_cc512_cmt4_tag(k_commit32: bytes, nonce24: bytes, aad: bytes, ct_outer: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_cc512_cmt4_tag")):
        return None
    kc = k_commit32 if isinstance(k_commit32, bytes) else bytes(k_commit32)
    nb = nonce24 if isinstance(nonce24, bytes) else bytes(nonce24)
    ab = aad if isinstance(aad, bytes) else bytes(aad)
    cb = ct_outer if isinstance(ct_outer, bytes) else bytes(ct_outer)
    if len(kc) != 32 or len(nb) != 24:
        return None
    tag = ctypes.create_string_buffer(32)
    rc = int(
        _LIB.openqpep_cc512_cmt4_tag(
            kc, nb, ab if ab else None, len(ab), cb if cb else None, len(cb), tag
        )
    )
    if rc != 0:
        raise ValueError(f"openqpep_cc512_cmt4_tag failed with status {rc}.")
    return tag.raw


def native_cc512_verify_cmt4_tag(
    k_commit32: bytes,
    nonce24: bytes,
    aad: bytes,
    ct_outer: bytes,
    expected_tag32: bytes,
) -> Optional[bool]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_cc512_verify_cmt4_tag")):
        return None
    kc = k_commit32 if isinstance(k_commit32, bytes) else bytes(k_commit32)
    nb = nonce24 if isinstance(nonce24, bytes) else bytes(nonce24)
    ab = aad if isinstance(aad, bytes) else bytes(aad)
    cb = ct_outer if isinstance(ct_outer, bytes) else bytes(ct_outer)
    tb = expected_tag32 if isinstance(expected_tag32, bytes) else bytes(expected_tag32)
    if len(kc) != 32 or len(nb) != 24 or len(tb) != 32:
        return False
    rc = int(
        _LIB.openqpep_cc512_verify_cmt4_tag(
            kc, nb, ab if ab else None, len(ab), cb if cb else None, len(cb), tb
        )
    )
    if rc == 0:
        return True
    if rc == -3:  # OPENQPEP_ERR_AUTH_FAIL
        return False
    raise ValueError(f"openqpep_cc512_verify_cmt4_tag failed with status {rc}.")


def native_cc512_siv_master_subkeys(key64: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_cc512_siv_master_subkeys")):
        return None
    kb = key64 if isinstance(key64, bytes) else bytes(key64)
    if len(kb) != 64:
        return None
    out = ctypes.create_string_buffer(128)
    try:
        rc = int(_LIB.openqpep_cc512_siv_master_subkeys(kb, out))
        if rc != 0:
            raise ValueError(f"openqpep_cc512_siv_master_subkeys failed with status {rc}.")
        return out.raw
    finally:
        _wipe_ctypes_buf(out)


def native_cc512_siv_synth(
    k_siv_mac64: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext: bytes,
) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_cc512_siv_synth")):
        return None
    km = k_siv_mac64 if isinstance(k_siv_mac64, bytes) else bytes(k_siv_mac64)
    nb = nonce if isinstance(nonce, bytes) else bytes(nonce)
    ab = aad if isinstance(aad, bytes) else bytes(aad)
    pb = plaintext if isinstance(plaintext, bytes) else bytes(plaintext)
    if len(km) != 64:
        return None
    siv = ctypes.create_string_buffer(32)
    rc = int(
        _LIB.openqpep_cc512_siv_synth(
            km,
            nb if nb else None,
            len(nb),
            ab if ab else None,
            len(ab),
            pb if pb else None,
            len(pb),
            siv,
        )
    )
    if rc != 0:
        raise ValueError(f"openqpep_cc512_siv_synth failed with status {rc}.")
    return siv.raw


def native_cc512_siv_msg_keys(k_enc_root64: bytes, siv32: bytes) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_cc512_siv_msg_keys")):
        return None
    kr = k_enc_root64 if isinstance(k_enc_root64, bytes) else bytes(k_enc_root64)
    sb = siv32 if isinstance(siv32, bytes) else bytes(siv32)
    if len(kr) != 64 or len(sb) != 32:
        return None
    out = ctypes.create_string_buffer(88)
    try:
        rc = int(_LIB.openqpep_cc512_siv_msg_keys(kr, sb, out))
        if rc != 0:
            raise ValueError(f"openqpep_cc512_siv_msg_keys failed with status {rc}.")
        return out.raw
    finally:
        _wipe_ctypes_buf(out)


def native_qhs_wots_chain(
    in32: bytes,
    start: int,
    steps: int,
    pub_seed32: bytes,
    leaf_idx: int,
    chain_idx: int,
) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_wots_chain")):
        return None
    ib = in32 if isinstance(in32, bytes) else bytes(in32)
    pb = pub_seed32 if isinstance(pub_seed32, bytes) else bytes(pub_seed32)
    if len(ib) != 32 or len(pb) != 32:
        raise ValueError("openqpep_qhs_wots_chain requires 32-byte input and 32-byte pub_seed.")
    out = ctypes.create_string_buffer(32)
    try:
        rc = int(_LIB.openqpep_qhs_wots_chain(ib, start, steps, pb, leaf_idx & 0xFFFFFFFF, chain_idx & 0xFFFF, out))
        if rc != 0:
            raise ValueError(f"openqpep_qhs_wots_chain failed with status {rc}.")
        return out.raw
    finally:
        _wipe_ctypes_buf(out)


def native_qhs_wots_pk_from_sk_seed(sk_seed32: bytes, pub_seed32: bytes, leaf_idx: int) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_wots_pk_from_sk_seed")):
        return None
    sb = sk_seed32 if isinstance(sk_seed32, bytes) else bytes(sk_seed32)
    pb = pub_seed32 if isinstance(pub_seed32, bytes) else bytes(pub_seed32)
    if len(sb) != 32 or len(pb) != 32:
        raise ValueError("openqpep_qhs_wots_pk_from_sk_seed requires 32-byte seeds.")
    out = ctypes.create_string_buffer(32)
    rc = int(_LIB.openqpep_qhs_wots_pk_from_sk_seed(sb, pb, leaf_idx & 0xFFFFFFFF, out))
    if rc != 0:
        raise ValueError(f"openqpep_qhs_wots_pk_from_sk_seed failed with status {rc}.")
    return out.raw


def native_qhs_wots_sign(
    sk_seed32: bytes,
    pub_seed32: bytes,
    leaf_idx: int,
    msg_digest32: bytes,
) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_wots_sign")):
        return None
    sb = sk_seed32 if isinstance(sk_seed32, bytes) else bytes(sk_seed32)
    pb = pub_seed32 if isinstance(pub_seed32, bytes) else bytes(pub_seed32)
    mb = msg_digest32 if isinstance(msg_digest32, bytes) else bytes(msg_digest32)
    if len(sb) != 32 or len(pb) != 32 or len(mb) != 32:
        raise ValueError("openqpep_qhs_wots_sign requires 32-byte seeds and 32-byte digest.")
    sig = ctypes.create_string_buffer(2144)
    try:
        rc = int(_LIB.openqpep_qhs_wots_sign(sb, pb, leaf_idx & 0xFFFFFFFF, mb, sig))
        if rc != 0:
            raise ValueError(f"openqpep_qhs_wots_sign failed with status {rc}.")
        return sig.raw
    finally:
        _wipe_ctypes_buf(sig)


def native_qhs_wots_pk_from_sig(
    wots_sig: bytes,
    msg_digest32: bytes,
    pub_seed32: bytes,
    leaf_idx: int,
) -> Optional[bytes]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_wots_pk_from_sig")):
        return None
    wb = wots_sig if isinstance(wots_sig, bytes) else bytes(wots_sig)
    mb = msg_digest32 if isinstance(msg_digest32, bytes) else bytes(msg_digest32)
    pb = pub_seed32 if isinstance(pub_seed32, bytes) else bytes(pub_seed32)
    if len(wb) != 2144 or len(mb) != 32 or len(pb) != 32:
        raise ValueError("openqpep_qhs_wots_pk_from_sig requires 2144-byte sig and 32-byte digest/seed.")
    out = ctypes.create_string_buffer(32)
    rc = int(_LIB.openqpep_qhs_wots_pk_from_sig(wb, mb, pb, leaf_idx & 0xFFFFFFFF, out))
    if rc != 0:
        raise ValueError(f"openqpep_qhs_wots_pk_from_sig failed with status {rc}.")
    return out.raw


def native_qhs_treehash_subtree(
    sk_seed32: bytes,
    pub_seed32: bytes,
    start_leaf: int,
    subtree_height: int,
    *,
    target_leaf: int = 0,
    capture_auth: bool = False,
) -> Optional[Tuple[bytes, bytes]]:
    """
    Thread-safe zero-heap O(h) TreeHash returning `(subtree_root32, auth_bytes)`.
    Releases the Python GIL during C99 execution for multi-core parallel Merkle tree construction.
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_treehash_subtree")):
        return None
    sb = sk_seed32 if isinstance(sk_seed32, bytes) else bytes(sk_seed32)
    pb = pub_seed32 if isinstance(pub_seed32, bytes) else bytes(pub_seed32)
    if len(sb) != 32 or len(pb) != 32 or subtree_height < 0 or subtree_height > 20:
        raise ValueError("Invalid arguments to openqpep_qhs_treehash_subtree.")
    auth_len = subtree_height * 32 if capture_auth else 0
    auth_buf = ctypes.create_string_buffer(auth_len) if auth_len > 0 else None
    root_buf = ctypes.create_string_buffer(32)
    rc = int(
        _LIB.openqpep_qhs_treehash_subtree(
            sb,
            pb,
            start_leaf & 0xFFFFFFFF,
            subtree_height,
            target_leaf & 0xFFFFFFFF,
            1 if capture_auth else 0,
            auth_buf,
            root_buf,
        )
    )
    if rc != 0:
        raise ValueError(f"openqpep_qhs_treehash_subtree failed with status {rc}.")
    return root_buf.raw, (auth_buf.raw if auth_buf is not None else b"")


def native_qhs_fold_subtrees(
    pub_seed32: bytes,
    subtree_roots: bytes,
    top_height: int,
    *,
    target_subtree_idx: int = 0,
    capture_auth: bool = False,
) -> Optional[Tuple[bytes, bytes]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_fold_subtrees")):
        return None
    pb = pub_seed32 if isinstance(pub_seed32, bytes) else bytes(pub_seed32)
    rb = subtree_roots if isinstance(subtree_roots, bytes) else bytes(subtree_roots)
    if len(pb) != 32 or top_height < 0 or top_height > 20 or len(rb) != (1 << top_height) * 32:
        raise ValueError("Invalid arguments to openqpep_qhs_fold_subtrees.")
    auth_len = top_height * 32 if capture_auth else 0
    auth_buf = ctypes.create_string_buffer(auth_len) if auth_len > 0 else None
    root_buf = ctypes.create_string_buffer(32)
    rc = int(
        _LIB.openqpep_qhs_fold_subtrees(
            pb,
            rb,
            top_height,
            target_subtree_idx & 0xFFFFFFFF,
            1 if capture_auth else 0,
            auth_buf,
            root_buf,
        )
    )
    if rc != 0:
        raise ValueError(f"openqpep_qhs_fold_subtrees failed with status {rc}.")
    return root_buf.raw, (auth_buf.raw if auth_buf is not None else b"")


def native_qhs_keygen_from_seeds(
    height: int,
    sk_seed32: bytes,
    pub_seed32: bytes,
) -> Optional[Tuple[bytes, bytes]]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_keygen_from_seeds")):
        return None
    sb = sk_seed32 if isinstance(sk_seed32, bytes) else bytes(sk_seed32)
    pb = pub_seed32 if isinstance(pub_seed32, bytes) else bytes(pub_seed32)
    if len(sb) != 32 or len(pb) != 32 or height < 0 or height > 20:
        raise ValueError("Invalid arguments to openqpep_qhs_keygen_from_seeds.")
    pk_buf = ctypes.create_string_buffer(65)
    sk_buf = ctypes.create_string_buffer(97)
    try:
        rc = int(_LIB.openqpep_qhs_keygen_from_seeds(height, sb, pb, pk_buf, sk_buf))
        if rc != 0:
            raise ValueError(f"openqpep_qhs_keygen_from_seeds failed with status {rc}.")
        return pk_buf.raw, sk_buf.raw
    finally:
        _wipe_ctypes_buf(sk_buf)


def native_qhs_sign_core(
    sk97: bytes,
    message: bytes,
    *,
    hedged: bool = True,
    rnd32: Optional[bytes] = None,
) -> Optional[Tuple[int, bytes]]:
    """
    Returns None when native is unavailable; otherwise `(status_rc, sig_bytes)`.
    Status codes: 0 (OPENQPEP_OK), -5 (OPENQPEP_ERR_FAULT_GUARD).
    """
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_sign_core")):
        return None
    sk_b = sk97 if isinstance(sk97, bytes) else bytes(sk97)
    msg_b = message if isinstance(message, bytes) else bytes(message)
    if len(sk_b) != 97:
        raise ValueError("Invalid QHS-512 secret key length (expected 97 bytes).")
    height = sk_b[0]
    if height > 20:
        raise ValueError(f"QHS-512 tree height {height} exceeds maximum supported height 20.")
    rnd_b: Optional[bytes] = None
    if hedged:
        if rnd32 is None:
            raise ValueError("Hedged native_qhs_sign_core requires 32-byte rnd32.")
        rnd_b = rnd32 if isinstance(rnd32, bytes) else bytes(rnd32)
        if len(rnd_b) != 32:
            raise ValueError("QHS-512 hedged signing rnd must be exactly 32 bytes.")
    sig_len = 2180 + height * 32
    sig_buf = ctypes.create_string_buffer(sig_len)
    try:
        rc = int(
            _LIB.openqpep_qhs_sign_core(
                sk_b,
                msg_b if msg_b else None,
                len(msg_b),
                1 if hedged else 0,
                rnd_b,
                sig_buf,
                sig_len,
            )
        )
        if rc == 0:
            return 0, sig_buf.raw
        if rc == -5:  # OPENQPEP_ERR_FAULT_GUARD
            return rc, b""
        raise ValueError(f"openqpep_qhs_sign_core failed with status {rc}.")
    finally:
        _wipe_ctypes_buf(sig_buf)


def native_qhs_verify(pk65: bytes, message: bytes, signature: bytes) -> Optional[bool]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_qhs_verify")):
        return None
    pk_b = pk65 if isinstance(pk65, bytes) else bytes(pk65)
    msg_b = message if isinstance(message, bytes) else bytes(message)
    sig_b = signature if isinstance(signature, bytes) else bytes(signature)
    if len(pk_b) != 65:
        return False
    rc = int(
        _LIB.openqpep_qhs_verify(
            pk_b,
            msg_b if msg_b else None,
            len(msg_b),
            sig_b if sig_b else None,
            len(sig_b),
        )
    )
    if rc == 0:
        return True
    if rc == -3:  # OPENQPEP_ERR_AUTH_FAIL
        return False
    raise ValueError(f"openqpep_qhs_verify failed with status {rc}.")
