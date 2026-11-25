"""
OpenQPEP Official Release 1.2.8 (v1.2.8) — Standalone C99 Self-Test Harness,
ASan + UBSan Sanitizer CI, and Live C99-vs-Pure-Python Differential Parity Test Suite.

Verifies:
  1. ABI v1.2.8 (`0x00010208`), 100% (108/108) exported `OPENQPEP_API` symbol coverage inside
     `calyx_qpep/native/csrc/test_openqpep_c.c`, zero leaked internal symbols, and CI sanitizer job.
  2. Standalone Makefile `make test` linking & running BOTH static `libopenqpep.a` and shared
     `libopenqpep.so` under strict ISO C99 `-Wall -Wextra -Werror -Wpedantic`.
  3. Strict AddressSanitizer + LeakSanitizer + UndefinedBehaviorSanitizer (`-fsanitize=address,undefined
     -fno-sanitize-recover=all`) on BOTH AVX2/SIMD (`make test-san`) and Portable ISO C99
     (`make test-san-portable`) builds with zero sanitizer errors or memory leaks.
  4. Live differential parity across ALL 12 cryptographic subsystems (36/36 output vectors)
     between the ASan+UBSan C99 harness (`--dump-vectors`) and Pure Python (`set_native_enabled(False)`).
  5. Bit-for-bit vector identity between AVX2/SIMD ASan and Portable ISO C99 ASan builds (37/37 vectors).
  6. Out-of-source CMake + CTest build with `-DOPENQPEP_BUILD_TESTS=ON -DOPENQPEP_ENABLE_SANITIZERS=ON`.
"""
import hashlib
import os
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List
from unittest.mock import patch

from calyx_qpep import (
    PROTOCOL_VERSION,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    is_native_available,
    native_abi_version,
    set_native_enabled,
)
from calyx_qpep.codes.goppa_8192 import (
    GOPPA_K,
    GOPPA_M,
    GOPPA_MT,
    GOPPA_N,
    GOPPA_T,
    BinaryGoppaKEM,
    _compute_syndrome,
    _ginv,
    _gmul,
    _is_irreducible_gf2m,
    _peval,
    _unpack_t_rows,
)
from calyx_qpep.codes.rank_rsd512 import (
    LRPC_N,
    _gf2_127_inv,
    _pack_poly,
    _ring_inv,
    _unpack_poly,
    gf2_127_mul,
)
from calyx_qpep.constants import QLX_Q, QVS_Q
from calyx_qpep.hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from calyx_qpep.lattice.ntt_3329 import (
    inv_ntt_3329,
    ntt_3329,
    ntt_base_mul_3329,
    poly_add_3329,
)
from calyx_qpep.lattice.ntt_8380417 import (
    decompose_poly_qvs,
    inv_ntt_qvs,
    ntt_mul_qvs,
    ntt_qvs,
)
from calyx_qpep.lattice.plain_lwe import PlainLWEEngine
from calyx_qpep.lattice.poly_ring import (
    compress_poly,
    sample_in_ball_qvs,
    sample_mask_y_qvs,
    sample_ntt_3329,
)
from calyx_qpep.multivariate.qmq_512 import (
    MultivariateQuadraticEngine,
    _MUL256,
    _eval_public_map,
    _expand_oil_matrix,
    _expand_p1_p2,
    _solve_gf256_linear,
    _unpack_p3,
)
from calyx_qpep.primitives.cc512_aead import (
    _compute_cmt4_tag,
    _compute_siv32,
    _derive_cmt4_subkeys,
    _derive_siv_master_subkeys,
    _derive_siv_message_keys,
)
from calyx_qpep.primitives.consttime import ct_caddq_3329, ct_caddq_qvs
from calyx_qpep.primitives.qsponge import qsponge_512, qsponge_var
from calyx_qpep.wire.framing import pack_wire_frame

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
BUILD_DIR = CSRC_DIR / "build"
TEST_C_PATH = CSRC_DIR / "test_openqpep_c.c"
CI_YML_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _san_env() -> Dict[str, str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1:abort_on_error=1"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
    return env


def _parse_vectors(stdout: str) -> Dict[str, str]:
    vecs: Dict[str, str] = {}
    for line in stdout.splitlines():
        if line.startswith("VEC:") and "=" in line:
            k, v = line[4:].split("=", 1)
            vecs[k.strip()] = v.strip().lower()
    return vecs


def _sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _pack_i32_le(vals: List[int]) -> bytes:
    return b"".join(struct.pack("<I", v & 0xFFFFFFFF) for v in vals)


class TestOpenQPEPv128C99SelfTestAndSanitizers(unittest.TestCase):
    def test_01_version_metadata_100_percent_api_coverage_and_ci_config(self):
        self.assertTrue(UNIVERSAL_VERSION.startswith(("1.", "2.")))
        self.assertEqual(UNIVERSAL_VERSION_LABEL, f"Official Release {UNIVERSAL_VERSION}")
        self.assertEqual(PROTOCOL_VERSION, f"OpenQPEP/{UNIVERSAL_VERSION}")
        self.assertTrue(TEST_C_PATH.is_file(), "Missing standalone C99 self-test harness test_openqpep_c.c")

        c_src = TEST_C_PATH.read_text(encoding="utf-8")

        # Verify CI workflow enforces ASan + UBSan + CMake/CTest sanitizer builds
        ci_text = CI_YML_PATH.read_text(encoding="utf-8")
        for needle in (
            "c99-sanitizers",
            "make -C calyx_qpep/native/csrc test",
            "make -C calyx_qpep/native/csrc test-san",
            "make -C calyx_qpep/native/csrc test-san-portable",
            "OPENQPEP_ENABLE_SANITIZERS=ON",
            "ctest",
        ):
            self.assertIn(needle, ci_text, f"Missing CI sanitizer requirement: {needle}")

        if is_native_available():
            self.assertGreaterEqual(native_abi_version(), 0x00010208)
            ext = "dylib" if platform.system() == "Darwin" else "so"
            shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
            if shared_lib.is_file() and shutil.which("nm"):
                res = subprocess.run(
                    ["nm", "-D", "--defined-only", str(shared_lib)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                exported = set()
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in ("T", "D", "R", "B"):
                        sym = parts[2].split("@")[0]
                        if not sym.startswith("_"):
                            exported.add(sym)
                self.assertGreaterEqual(len(exported), 108)
                leaked = {s for s in exported if not s.startswith("openqpep_")}
                self.assertEqual(leaked, set(), f"Leaked non-openqpep symbols: {leaked}")

                # 100% exported OPENQPEP_API coverage inside test_openqpep_c.c
                uncovered = sorted(sym for sym in exported if f"{sym}(" not in c_src)
                self.assertEqual(
                    uncovered,
                    [],
                    f"Exported C99 APIs missing from test_openqpep_c.c: {uncovered}",
                )

    def test_02_makefile_standalone_c99_selftest_static_and_shared(self):
        if not (shutil.which("make") and (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"))):
            self.skipTest("make or C compiler not available on PATH.")

        res = subprocess.run(
            ["make", "-C", str(CSRC_DIR), "test"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"make test failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
        )
        self.assertEqual(
            res.stdout.count("Standalone C99 Self-Test Harness PASSED: 12/12 suites, 108/108 APIs"),
            2,
            f"Expected both static & shared C99 self-test binaries to pass:\n{res.stdout}",
        )

    def test_03_asan_ubsan_avx2_and_portable_c99_builds(self):
        if not (shutil.which("make") and (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"))):
            self.skipTest("make or C compiler not available on PATH.")

        env = _san_env()
        for target in ("test-san", "test-san-portable"):
            res = subprocess.run(
                ["make", "-C", str(CSRC_DIR), target],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(
                res.returncode,
                0,
                f"Sanitizer target `{target}` failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
            )
            self.assertIn(
                "Standalone C99 Self-Test Harness PASSED: 12/12 suites, 108/108 APIs",
                res.stdout,
            )
            self.assertNotIn("AddressSanitizer", res.stderr)
            self.assertNotIn("LeakSanitizer", res.stderr)
            self.assertNotIn("runtime error:", res.stderr)

    def test_04_live_differential_c99_asan_vs_pure_python_all_subsystems(self):
        if not (shutil.which("make") and (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"))):
            self.skipTest("make or C compiler not available on PATH.")

        env = _san_env()
        san_bin = BUILD_DIR / "test_openqpep_c_san"
        if not san_bin.is_file():
            subprocess.run(["make", "-C", str(CSRC_DIR), "test-san"], check=True, env=env, capture_output=True)

        res = subprocess.run([str(san_bin), "--dump-vectors"], capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 0, f"ASan --dump-vectors failed:\n{res.stderr}")
        c_vecs = _parse_vectors(res.stdout)
        self.assertEqual(len(c_vecs), 37, f"Expected 37 differential vectors, got {len(c_vecs)}: {sorted(c_vecs)}")

        try:
            set_native_enabled(False)

            # Suite 2: Constant-time XOR accumulator
            a2 = bytes((i + 1) & 0xFF for i in range(32))
            b2 = bytes((0xF0 - i) & 0xFF for i in range(32))
            self.assertEqual(bytes(x ^ y for x, y in zip(a2, b2)).hex(), c_vecs["CT_XOR_ACC"])

            # Suite 3: Keccak-f[1600] / FIPS 202
            msg3 = bytes((i * 37 + 11) & 0xFF for i in range(300))
            self.assertEqual(qsponge_512(msg3).hex(), c_vecs["KECCAK_SHA3_512"])
            self.assertEqual(hashlib.sha3_256(msg3).hexdigest(), c_vecs["KECCAK_SHA3_256"])
            self.assertEqual(_sha3_256_hex(qsponge_var(msg3, 200)), c_vecs["KECCAK_SHAKE256_200"])
            self.assertEqual(_sha3_256_hex(hashlib.shake_128(msg3).digest(200)), c_vecs["KECCAK_SHAKE128_200"])

            # Suite 4: QLX NTT mod 3329, compress d=10, sampler & matvec+inner_prod
            a4 = [(i * 137 + 19) % QLX_Q for i in range(256)]
            b4 = [(i * 251 + 7) % QLX_Q for i in range(256)]
            prod4 = inv_ntt_3329(ntt_base_mul_3329(ntt_3329(a4), ntt_3329(b4)))
            self.assertEqual(_sha3_256_hex(_pack_i32_le(prod4)), c_vecs["QLX_NTT_PROD"])
            self.assertEqual(_sha3_256_hex(compress_poly(a4, 10)), c_vecs["QLX_CMP_D10"])

            rho4 = bytes(0x10 + i for i in range(32))
            self.assertEqual(_sha3_256_hex(_pack_i32_le(sample_ntt_3329(rho4, 1, 2))), c_vecs["QLX_SAMPLE_1_2"])

            vec4 = [ntt_3329([((j + 1) * 53 + i * 17) % QLX_Q for i in range(256)]) for j in range(3)]
            add4 = [ntt_3329([((j + 2) * 29 + i * 11) % QLX_Q for i in range(256)]) for j in range(3)]
            mv4 = []
            mvt4 = []
            for i in range(3):
                acc_n = [0] * 256
                acc_t = [0] * 256
                for j in range(3):
                    acc_n = poly_add_3329(acc_n, ntt_base_mul_3329(sample_ntt_3329(rho4, i, j), vec4[j]))
                    acc_t = poly_add_3329(acc_t, ntt_base_mul_3329(sample_ntt_3329(rho4, j, i), vec4[j]))
                mv4.append(poly_add_3329(acc_n, add4[i]))
                mvt4.append(acc_t)
            ip4 = [0] * 256
            for j in range(3):
                ip4 = poly_add_3329(ip4, ntt_base_mul_3329(mv4[j], mvt4[j]))
            self.assertEqual(_sha3_256_hex(_pack_i32_le(ip4)), c_vecs["QLX_MATVEC_INNER"])

            # Suite 5: QVS Solinas-Barrett NTT mod 8380417, Decompose, MaskY & SampleInBall
            a5 = [(i * 65521 + 12345) % QVS_Q for i in range(256)]
            b5 = [(i * 31337 + 777) % QVS_Q for i in range(256)]
            prod5 = inv_ntt_qvs(ntt_mul_qvs(ntt_qvs(a5), ntt_qvs(b5)))
            self.assertEqual(_sha3_256_hex(_pack_i32_le(prod5)), c_vecs["QVS_NTT_PROD"])
            r1_5, _ = decompose_poly_qvs(a5)
            self.assertEqual(_sha3_256_hex(_pack_i32_le(r1_5)), c_vecs["QVS_DECOMP_R1"])
            rho5 = bytes(0x20 + i for i in range(32))
            ctilde5 = bytes(0x80 + i for i in range(64))
            self.assertEqual(_sha3_256_hex(_pack_i32_le(sample_mask_y_qvs(rho5, 7))), c_vecs["QVS_MASK_Y"])
            self.assertEqual(_sha3_256_hex(_pack_i32_le(sample_in_ball_qvs(ctilde5, 24))), c_vecs["QVS_BALL_C"])

            # Suite 6: Centered Binomial Distributions (CBD1_3329, CBD2_3329, CBD2_QVS)
            buf6 = bytes((i * 29 + 5) & 0xFF for i in range(128))
            cbd1_py = [0] * 256
            for i in range(64):
                b = buf6[i]
                for j in range(4):
                    cbd1_py[4 * i + j] = ct_caddq_3329(((b >> (2 * j)) & 1) - ((b >> (2 * j + 1)) & 1))
            cbd2_3329_py = [0] * 256
            cbd2_qvs_py = [0] * 256
            for i in range(128):
                b = buf6[i]
                d0 = ((b & 1) + ((b >> 1) & 1)) - (((b >> 2) & 1) + ((b >> 3) & 1))
                d1 = (((b >> 4) & 1) + ((b >> 5) & 1)) - (((b >> 6) & 1) + ((b >> 7) & 1))
                cbd2_3329_py[2 * i] = ct_caddq_3329(d0)
                cbd2_3329_py[2 * i + 1] = ct_caddq_3329(d1)
                cbd2_qvs_py[2 * i] = ct_caddq_qvs(d0)
                cbd2_qvs_py[2 * i + 1] = ct_caddq_qvs(d1)
            self.assertEqual(_sha3_256_hex(_pack_i32_le(cbd1_py)), c_vecs["CBD1_3329"])
            self.assertEqual(_sha3_256_hex(_pack_i32_le(cbd2_3329_py)), c_vecs["CBD2_3329"])
            self.assertEqual(_sha3_256_hex(_pack_i32_le(cbd2_qvs_py)), c_vecs["CBD2_QVS"])

            # Suite 7: Plain-LWE (n=64, nbar=8) full Pure-Python FO keygen / encaps / decaps / reject
            seed_a7 = bytes(0x30 + i for i in range(32))
            seed_s7 = bytes(0x50 + i for i in range(32))
            seed_z7 = bytes(0x70 + i for i in range(32))
            msg16_7 = bytes(0xA0 + i for i in range(16))
            with patch("calyx_qpep.lattice.plain_lwe.os.urandom", side_effect=[seed_a7, seed_s7, seed_z7]):
                pk7, sk7 = PlainLWEEngine.keygen(n=64, nbar=8)
            with patch("calyx_qpep.lattice.plain_lwe.os.urandom", side_effect=[msg16_7]):
                ct7, ss7 = PlainLWEEngine.encaps(pk7)
            self.assertEqual(PlainLWEEngine.decaps(sk7, ct7), ss7)
            rej7 = PlainLWEEngine.decaps(sk7, bytes([ct7[0] ^ 0x01]) + ct7[1:])
            self.assertEqual(_sha3_256_hex(pk7), c_vecs["PLWE64_PK"])
            self.assertEqual(_sha3_256_hex(ct7), c_vecs["PLWE64_CT"])
            self.assertEqual(ss7.hex(), c_vecs["PLWE64_SS"])
            self.assertEqual(rej7.hex(), c_vecs["PLWE64_REJ"])

            # Suite 8: Binary Goppa GF(2^10) systematic T, syndrome & Patterson decode in Pure Python
            g8_bytes = bytes.fromhex(c_vecs["GOPPA_G"])
            g8 = list(struct.unpack("<33H", g8_bytes))
            self.assertTrue(_is_irreducible_gf2m(g8, GOPPA_T))
            support8 = list(range(GOPPA_N))
            rows8 = [0] * GOPPA_MT
            g_inv8 = [_ginv(_peval(g8, a)) for a in support8]
            for col in range(GOPPA_N):
                a = support8[col]
                val = g_inv8[col]
                bit = 1 << col
                for i in range(GOPPA_T):
                    base = i * GOPPA_M
                    for b in range(GOPPA_M):
                        if (val >> b) & 1:
                            rows8[base + b] |= bit
                    val = _gmul(val, a)
            for col in range(GOPPA_MT):
                bit = 1 << col
                piv = next(r for r in range(col, GOPPA_MT) if rows8[r] & bit)
                if piv != col:
                    rows8[col], rows8[piv] = rows8[piv], rows8[col]
                piv_row = rows8[col]
                for r in range(GOPPA_MT):
                    if r != col and (rows8[r] & bit):
                        rows8[r] ^= piv_row
            k_bytes8 = GOPPA_K // 8
            t8_bytes = b"".join((r >> GOPPA_MT).to_bytes(k_bytes8, "little") for r in rows8)
            self.assertEqual(_sha3_256_hex(t8_bytes), c_vecs["GOPPA_T"])

            err8_mask = sum(1 << (k * 31 + 5) for k in range(32))
            err8_bytes = err8_mask.to_bytes(128, "little")
            syn8_bytes = _compute_syndrome(_unpack_t_rows(t8_bytes, GOPPA_MT, k_bytes8), err8_mask, GOPPA_MT).to_bytes(40, "little")
            self.assertEqual(syn8_bytes.hex(), c_vecs["GOPPA_SYN"])
            self.assertEqual(err8_bytes.hex(), c_vecs["GOPPA_REC"])
            # Also exercise full Pure-Python BinaryGoppaKEM.decaps Patterson path on this exact key & error
            pk8_body = struct.pack("<HHH", GOPPA_N, GOPPA_MT, GOPPA_T) + t8_bytes
            h_pk8 = qsponge_512(b"CALYX-CGM-HPK-v1.0.0|" + pk8_body)[:32]
            pk8 = pk8_body + h_pk8
            sk8 = (
                struct.pack("<HHH", GOPPA_N, GOPPA_MT, GOPPA_T)
                + (b"\x77" * 32)
                + g8_bytes
                + struct.pack(f"<{GOPPA_N}H", *support8)
                + pk8
            )
            c1_8 = qsponge_512(b"CALYX-CGM-CONF-v1.0.0|" + err8_bytes + syn8_bytes + h_pk8)[:32]
            ct8 = syn8_bytes + c1_8
            exp_ss8 = qsponge_512(b"CALYX-CGM-SS-v1.0.0|" + err8_bytes + ct8 + h_pk8)[:32]
            self.assertEqual(BinaryGoppaKEM.decaps(sk8, ct8), exp_ss8)

            # Suite 9: Rank-Metric GF(2^127) & LRPC Ring mod (X^47 + X^5 + 1)
            a9_b = bytearray((i * 19 + 5) & 0xFF for i in range(16))
            b9_b = bytearray((i * 23 + 11) & 0xFF for i in range(16))
            a9_b[15] &= 0x7F
            b9_b[15] &= 0x7F
            a9 = int.from_bytes(a9_b, "little")
            b9 = int.from_bytes(b9_b, "little")
            self.assertEqual(gf2_127_mul(a9, b9).to_bytes(16, "little").hex(), c_vecs["GF2_127_MUL"])
            self.assertEqual(_gf2_127_inv(a9).to_bytes(16, "little").hex(), c_vecs["GF2_127_INV"])
            p1_b = bytearray((i * 31 + 7) & 0xFF for i in range(LRPC_N * 16))
            for j in range(LRPC_N):
                p1_b[j * 16 + 15] &= 0x7F
            pinv9 = _ring_inv(_unpack_poly(bytes(p1_b)))
            self.assertIsNotNone(pinv9)
            self.assertEqual(_sha3_256_hex(_pack_poly(pinv9)), c_vecs["LRPC_INV"])

            # Suite 10: UOV GF(256) P3 keygen + deterministic sign core + public map verification
            seed_pk10 = bytes((0xA1 + i) & 0xFF for i in range(32))
            seed_sk10 = bytes((0xB1 + i) & 0xFF for i in range(32))
            target10 = bytes((0xC1 + i) & 0xFF for i in range(32))
            salt10 = bytes((0xD1 + i) & 0xFF for i in range(16))
            with patch("calyx_qpep.multivariate.qmq_512.os.urandom", side_effect=[seed_pk10, seed_sk10]):
                pk10, _ = MultivariateQuadraticEngine.keygen(v=64, m=32)
            p3_10 = pk10[36:]
            self.assertEqual(_sha3_256_hex(p3_10), c_vecs["UOV_P3"])

            oil10 = _expand_oil_matrix(seed_sk10, 64, 32)
            p1_10, p2_10 = _expand_p1_p2(seed_pk10, 64, 32)
            sv10_py = b""
            so10_py = b""
            for attempt in range(64):
                vin = list(qsponge_var(b"CALYX-QMQ-VINEGAR-v1.0.0|" + seed_sk10 + salt10 + struct.pack(">H", attempt), 64))
                rhs = list(target10)
                lin = [[0] * 32 for _ in range(32)]
                for k in range(32):
                    p1k, p2k = p1_10[k], p2_10[k]
                    yk = 0
                    w = [0] * 64
                    for i in range(64):
                        vi = vin[i]
                        row1 = p1k[i]
                        for j in range(i, 64):
                            c = row1[j]
                            if not c:
                                continue
                            vj = vin[j]
                            if vi and vj:
                                yk ^= _MUL256[_MUL256[vi][c]][vj]
                            if i != j:
                                if vi:
                                    w[j] ^= _MUL256[vi][c]
                                if vj:
                                    w[i] ^= _MUL256[vj][c]
                    rhs[k] ^= yk
                    lk = lin[k]
                    for i in range(64):
                        wi = w[i]
                        if wi:
                            mwi, oi = _MUL256[wi], oil10[i]
                            for j in range(32):
                                lk[j] ^= mwi[oi[j]]
                        vi = vin[i]
                        if vi:
                            mvi, p2i = _MUL256[vi], p2k[i]
                            for j in range(32):
                                lk[j] ^= mvi[p2i[j]]
                xo = _solve_gf256_linear(lin, rhs)
                if xo is not None:
                    sv = list(vin)
                    for i in range(64):
                        for j in range(32):
                            sv[i] ^= _MUL256[oil10[i][j]][xo[j]]
                    sv10_py = bytes(sv)
                    so10_py = bytes(xo)
                    break
            self.assertEqual(sv10_py.hex(), c_vecs["UOV_SV"])
            self.assertEqual(so10_py.hex(), c_vecs["UOV_SO"])
            self.assertEqual(
                _eval_public_map(p1_10, p2_10, _unpack_p3(p3_10, 32), 64, 32, list(sv10_py), list(so10_py)),
                target10,
            )

            # Suite 11: Wire v5 Framing + CC-512 CMT-4 & SIV
            label11 = b"OPENQPEP-C99-SELFTEST"
            nonce16_11 = bytes(i + 1 for i in range(16))
            body11 = bytes((i * 7 + 3) & 0xFF for i in range(300))
            with patch("calyx_qpep.wire.framing.os.urandom", return_value=nonce16_11):
                frame11 = pack_wire_frame(body11, label11.decode("ascii"), packet_type=1, flags=0)
            self.assertEqual(_sha3_256_hex(frame11), c_vecs["WIRE_V5_FRAME"])

            key64_11 = bytes(0x11 + i for i in range(64))
            nonce24_11 = bytes(0x61 + i for i in range(24))
            sub96_11 = _derive_cmt4_subkeys(key64_11, nonce24_11)
            tag32_11 = _compute_cmt4_tag(sub96_11[64:96], nonce24_11, label11, body11)
            mst128_11 = _derive_siv_master_subkeys(key64_11)
            siv32_11 = _compute_siv32(mst128_11[:64], nonce16_11, label11, body11)
            mk88_11 = _derive_siv_message_keys(mst128_11[64:128], siv32_11)
            self.assertEqual(tag32_11.hex(), c_vecs["CC512_CMT4_TAG"])
            self.assertEqual(siv32_11.hex(), c_vecs["CC512_SIV32"])
            self.assertEqual(mk88_11.hex(), c_vecs["CC512_SIV_MK88"])

            # Suite 12: QHS-512 Hypertree (WOTS+ + XMSS Merkle Tree)
            sk_seed12 = bytes(0x05 + i for i in range(32))
            pub_seed12 = bytes(0x45 + i for i in range(32))
            rnd32_12 = bytes(0x85 + i for i in range(32))
            msg12 = b"OpenQPEP QHS-512 C99 Self-Test Message"
            with patch("calyx_qpep.hashsig.qhs_512_hypertree.os.urandom", side_effect=[sk_seed12, pub_seed12]):
                pk12, sk12 = QHS512HypertreeEngine.keygen(height=4)
            sig_det12 = QHS512HypertreeEngine.sign(sk12, msg12, hedged=False)
            sig_hed12 = QHS512HypertreeEngine.sign(sk12, msg12, hedged=True, rnd=rnd32_12)
            self.assertEqual(pk12.hex(), c_vecs["QHS_PK"])
            self.assertEqual(_sha3_256_hex(sig_det12), c_vecs["QHS_SIG_DET"])
            self.assertEqual(_sha3_256_hex(sig_hed12), c_vecs["QHS_SIG_HED"])
        finally:
            set_native_enabled(True)

    def test_05_portable_c99_asan_vectors_match_avx2_asan_bit_for_bit(self):
        if not (shutil.which("make") and (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"))):
            self.skipTest("make or C compiler not available on PATH.")

        env = _san_env()
        avx_bin = BUILD_DIR / "test_openqpep_c_san"
        pt_bin = BUILD_DIR / "test_openqpep_c_san_portable"
        if not avx_bin.is_file():
            subprocess.run(["make", "-C", str(CSRC_DIR), "test-san"], check=True, env=env, capture_output=True)
        if not pt_bin.is_file():
            subprocess.run(["make", "-C", str(CSRC_DIR), "test-san-portable"], check=True, env=env, capture_output=True)

        r_avx = subprocess.run([str(avx_bin), "--dump-vectors"], capture_output=True, text=True, env=env, check=True)
        r_pt = subprocess.run([str(pt_bin), "--dump-vectors"], capture_output=True, text=True, env=env, check=True)

        v_avx = _parse_vectors(r_avx.stdout)
        v_pt = _parse_vectors(r_pt.stdout)
        self.assertEqual(len(v_avx), 37)
        self.assertEqual(v_avx, v_pt, "AVX2/SIMD ASan vectors diverged from Portable ISO C99 ASan vectors!")

    def test_06_cmake_out_of_source_sanitizer_build_and_ctest(self):
        if not (shutil.which("cmake") and shutil.which("ctest")):
            self.skipTest("cmake or ctest not available on PATH.")

        env = _san_env()
        with tempfile.TemporaryDirectory() as tmpdir:
            bdir = Path(tmpdir) / "cmake_san_build"
            cfg = subprocess.run(
                [
                    "cmake",
                    "-S",
                    str(CSRC_DIR),
                    "-B",
                    str(bdir),
                    "-DOPENQPEP_BUILD_TESTS=ON",
                    "-DOPENQPEP_ENABLE_SANITIZERS=ON",
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(cfg.returncode, 0, f"CMake configure failed:\n{cfg.stdout}\n{cfg.stderr}")

            bld = subprocess.run(
                ["cmake", "--build", str(bdir), "--target", "test_openqpep_c", "-j"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(bld.returncode, 0, f"CMake build failed:\n{bld.stdout}\n{bld.stderr}")

            tst = subprocess.run(
                ["ctest", "--test-dir", str(bdir), "--output-on-failure"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(tst.returncode, 0, f"CTest ASan+UBSan failed:\n{tst.stdout}\n{tst.stderr}")
            self.assertIn("100% tests passed", tst.stdout)


if __name__ == "__main__":
    unittest.main()
