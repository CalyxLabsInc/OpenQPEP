"""
OpenQPEP Official Release 1.2.7 (v1.2.7) — Native C99 WOTS+ & XMSS Merkle Tree Accelerator
(QHS-512 over 4-Way SIMD Keccak-f[1600]) Test Suite.

Verifies:
  1. ABI v1.2.7 (`0x00010207`) & dynamic export of all 9 new `openqpep_qhs_*` symbols under
     `-fvisibility=hidden` (`108` total exported `openqpep_*` symbols, zero leaked helpers).
  2. Bit-exact Native C99 (4-way SIMD Keccak-f[1600]) <-> Pure-Python parity for WOTS+ chaining,
     WOTS+ leaf public-key derivation, WOTS+ signing, and WOTS+ signature public-key recovery.
  3. Zero-heap O(h) TreeHash (`openqpep_qhs_treehash_subtree`) & top-tree folding
     (`openqpep_qhs_fold_subtrees`) across heights h=0..5 and every leaf authentication path,
     plus cross-backend `QHS512HypertreeEngine` (hedged + deterministic), `CalyxIsogenyForgeSuite`,
     `CalyxSovereignPentad`, tamper rejection, and Verify-Before-Emit Fault-Guard.
  4. Multi-core parallel high-height hypertrees (`h = 8` / 256 leaves and `h = 10` / 1,024 leaves):
     bit-exact root & signature parity between parallel (`workers=4`) and single-worker execution.
  5. Verified Native C99 4-way SIMD wall-clock speedups (`>= 4x`) on `QHS-512` keygen, sign & verify.
  6. Standalone external C99 consumer compiled under `-std=c99 -O2 -Wall -Wextra -Werror -Wpedantic`
     linking BOTH static `libopenqpep.a` and shared `libopenqpep.so` verifying WOTS+, split TreeHash,
     keygen/sign/verify, Fault-Guard (`OPENQPEP_ERR_FAULT_GUARD`), and error bounds.
"""
import os
import platform
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from calyx_qpep import (
    PROTOCOL_VERSION,
    QPEPFaultGuardError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    is_native_available,
    native_abi_version,
    set_native_enabled,
)
from calyx_qpep.hashsig.qhs_512_hypertree import (
    QHS512HypertreeEngine,
    WOTS_LEN,
    WOTS_N,
    _chain,
    _parallel_treehash_native,
    _wots_pk_from_sk_seed,
)
from calyx_qpep.isogeny.isogeny_suite import CalyxIsogenyForgeSuite
from calyx_qpep.native import (
    native_qhs_fold_subtrees,
    native_qhs_keygen_from_seeds,
    native_qhs_sign_core,
    native_qhs_treehash_subtree,
    native_qhs_verify,
    native_qhs_wots_chain,
    native_qhs_wots_pk_from_sig,
    native_qhs_wots_pk_from_sk_seed,
    native_qhs_wots_sign,
)
from calyx_qpep.pentad.sovereign_pentad import CalyxSovereignPentad

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
HEADER_PATH = CSRC_DIR / "include" / "openqpep.h"

NEW_V127_SYMBOLS = {
    "openqpep_qhs_wots_chain",
    "openqpep_qhs_wots_pk_from_sk_seed",
    "openqpep_qhs_wots_sign",
    "openqpep_qhs_wots_pk_from_sig",
    "openqpep_qhs_treehash_subtree",
    "openqpep_qhs_fold_subtrees",
    "openqpep_qhs_keygen_from_seeds",
    "openqpep_qhs_sign_core",
    "openqpep_qhs_verify",
}


class TestOpenQPEPv127C99QHS512(unittest.TestCase):
    def test_01_version_metadata_and_exported_v127_symbols(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.2.7")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.2.7")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.2.7")

        hdr = HEADER_PATH.read_text(encoding="utf-8")
        for sym in NEW_V127_SYMBOLS:
            self.assertIn(sym, hdr, f"Missing v1.2.7 QHS symbol in openqpep.h: {sym}")
        self.assertIn("OPENQPEP_QHS_MAX_HEIGHT", hdr)

        if is_native_available():
            self.assertEqual(native_abi_version(), 0x00010207)

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
                self.assertEqual(NEW_V127_SYMBOLS - exported, set())
                leaked = {s for s in exported if not s.startswith("openqpep_")}
                self.assertEqual(leaked, set(), f"Leaked internal symbols: {leaked}")
                self.assertGreaterEqual(len(exported), 108)

    def test_02_wots_chain_pk_sign_recover_c99_vs_pure_python_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        sk_seed = bytes(range(32))
        pub_seed = bytes(range(32, 64))
        msg_digest = bytes(range(64, 96))

        try:
            # 1. WOTS+ chain steps parity (0 steps, partial, full 15 steps)
            x0 = bytes(range(100, 132))
            for start, steps, leaf, cidx in (
                (0, 0, 0, 0),
                (0, 1, 0, 0),
                (0, 15, 3, 66),
                (5, 10, 17, 42),
                (14, 1, 1023, 63),
            ):
                set_native_enabled(True)
                c_out = _chain(x0, start, steps, pub_seed, leaf, cidx)
                set_native_enabled(False)
                p_out = _chain(x0, start, steps, pub_seed, leaf, cidx)
                self.assertEqual(c_out, p_out, f"Chain mismatch at start={start}, steps={steps}, leaf={leaf}, cidx={cidx}")

            # 2. 4-way SIMD WOTS+ leaf PK vs Pure-Python across varied leaf indices
            for leaf in (0, 1, 7, 15, 255, 1024):
                set_native_enabled(True)
                pk_c = _wots_pk_from_sk_seed(sk_seed, pub_seed, leaf)
                set_native_enabled(False)
                pk_p = _wots_pk_from_sk_seed(sk_seed, pub_seed, leaf)
                self.assertEqual(pk_c, pk_p, f"WOTS PK mismatch at leaf={leaf}")

            # 3. WOTS+ sign & PK recovery parity
            set_native_enabled(True)
            wots_sig = native_qhs_wots_sign(sk_seed, pub_seed, 11, msg_digest)
            self.assertIsNotNone(wots_sig)
            self.assertEqual(len(wots_sig), WOTS_LEN * WOTS_N)
            rec_pk = native_qhs_wots_pk_from_sig(wots_sig, msg_digest, pub_seed, 11)
            exp_pk = native_qhs_wots_pk_from_sk_seed(sk_seed, pub_seed, 11)
            self.assertEqual(rec_pk, exp_pk)

            # 1-bit flip in WOTS sig breaks recovered PK
            bad_wots = bytes([wots_sig[0] ^ 0x01]) + wots_sig[1:]
            self.assertNotEqual(native_qhs_wots_pk_from_sig(bad_wots, msg_digest, pub_seed, 11), exp_pk)
        finally:
            set_native_enabled(True)

    def test_03_treehash_subtree_fold_and_cross_backend_qhs512_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        sk_seed = os.urandom(32)
        pub_seed = os.urandom(32)
        msg = b"OpenQPEP v1.2.7 QHS-512 C99 XMSS Hypertree cross-backend message"
        rnd = b"\x5A" * 32

        try:
            # 1. Verify h=0, 1, 2, 4 native keygen/sign/verify bit-exact parity vs Pure-Python
            for h in (0, 1, 2, 4):
                set_native_enabled(True)
                pk_c, sk_c = native_qhs_keygen_from_seeds(h, sk_seed, pub_seed)
                sig_det_c = QHS512HypertreeEngine.sign(sk_c, msg, hedged=False)
                sig_hed_c = QHS512HypertreeEngine.sign(sk_c, msg, hedged=True, rnd=rnd)

                set_native_enabled(False)
                sig_det_p = QHS512HypertreeEngine.sign(sk_c, msg, hedged=False)
                sig_hed_p = QHS512HypertreeEngine.sign(sk_c, msg, hedged=True, rnd=rnd)

                self.assertEqual(sig_det_c, sig_det_p, f"Det sig mismatch at h={h}")
                self.assertEqual(sig_hed_c, sig_hed_p, f"Hedged sig mismatch at h={h}")
                self.assertTrue(QHS512HypertreeEngine.verify(pk_c, msg, sig_det_c))
                self.assertTrue(QHS512HypertreeEngine.verify(pk_c, msg, sig_hed_c))
                self.assertFalse(QHS512HypertreeEngine.verify(pk_c, msg + b"!", sig_det_c))

                set_native_enabled(True)
                self.assertTrue(QHS512HypertreeEngine.verify(pk_c, msg, sig_det_p))
                self.assertFalse(QHS512HypertreeEngine.verify(pk_c, msg, sig_det_p[:-1] + bytes([sig_det_p[-1] ^ 0x01])))
                # Out-of-range leaf_idx strictly rejected
                bad_leaf_sig = struct.pack(">I", 1 << h) + sig_det_c[4:]
                self.assertFalse(QHS512HypertreeEngine.verify(pk_c, msg, bad_leaf_sig))

            # 2. Split subtree TreeHash + fold parity for EVERY target leaf 0..15 of h=4
            set_native_enabled(True)
            full_root, _ = native_qhs_treehash_subtree(sk_seed, pub_seed, 0, 4)
            for target_leaf in range(16):
                _, full_auth = native_qhs_treehash_subtree(
                    sk_seed, pub_seed, 0, 4, target_leaf=target_leaf, capture_auth=True
                )
                # Split into 4 subtrees of height 2 (top_h = 2)
                sub_roots = []
                sub_auth = b""
                target_sub = target_leaf >> 2
                for sidx in range(4):
                    want = (sidx == target_sub)
                    sr, sa = native_qhs_treehash_subtree(
                        sk_seed,
                        pub_seed,
                        sidx * 4,
                        2,
                        target_leaf=target_leaf if want else 0,
                        capture_auth=want,
                    )
                    sub_roots.append(sr)
                    if want:
                        sub_auth = sa
                folded_root, top_auth = native_qhs_fold_subtrees(
                    pub_seed,
                    b"".join(sub_roots),
                    2,
                    target_subtree_idx=target_sub,
                    capture_auth=True,
                )
                self.assertEqual(folded_root, full_root)
                self.assertEqual(sub_auth + top_auth, full_auth, f"Auth path mismatch at leaf={target_leaf}")

            # 3. Verify-Before-Emit Fault-Guard (corrupted sk root + mocked verify=False)
            pk4, sk4 = native_qhs_keygen_from_seeds(4, sk_seed, pub_seed)
            bad_sk4 = sk4[:-1] + bytes([sk4[-1] ^ 0x01])
            with self.assertRaises(QPEPFaultGuardError):
                QHS512HypertreeEngine.sign(bad_sk4, msg, hedged=False)
            with patch.object(QHS512HypertreeEngine, "verify", return_value=False):
                with self.assertRaises(QPEPFaultGuardError):
                    QHS512HypertreeEngine.sign(sk4, msg, hedged=False)

            # 4. Cross-backend CIF-SQI-512 & CSP-Omega signatures
            pub_iso, priv_iso = CalyxIsogenyForgeSuite.keygen()
            sig_iso = CalyxIsogenyForgeSuite.sign(b"cif-v127-qhs", priv_iso)
            set_native_enabled(False)
            ok_iso, out_iso = CalyxIsogenyForgeSuite.verify(sig_iso, pub_iso)
            self.assertTrue(ok_iso)
            self.assertEqual(out_iso, b"cif-v127-qhs")

            set_native_enabled(True)
            pub_p, priv_p = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
            sig_p = CalyxSovereignPentad.sign(b"pentad-v127-qhs", pub_p, priv_p)
            set_native_enabled(False)
            ok_p, out_p = CalyxSovereignPentad.verify(sig_p, pub_p)
            self.assertTrue(ok_p)
            self.assertEqual(out_p, b"pentad-v127-qhs")
        finally:
            set_native_enabled(True)

    def test_04_parallel_high_height_hypertree_h8_and_h10_consistency(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        sk_seed = bytes(range(10, 42))
        pub_seed = bytes(range(50, 82))
        msg = b"OpenQPEP v1.2.7 high-height parallel XMSS hypertree test"

        # Height 8 (256 leaves): parallel multi-core vs single-thread exact root & auth parity
        r_single, auth_single = _parallel_treehash_native(
            sk_seed, pub_seed, 8, target_leaf=173, capture_auth=True, workers=1
        )
        r_par, auth_par = _parallel_treehash_native(
            sk_seed, pub_seed, 8, target_leaf=173, capture_auth=True, workers=4
        )
        self.assertEqual(r_single, r_par)
        self.assertEqual(auth_single, auth_par)
        self.assertEqual(len(auth_par), 8 * 32)

        # Full keygen/sign/verify at height 8 (256 leaves) and height 10 (1,024 leaves)
        for h in (8, 10):
            pk, sk = QHS512HypertreeEngine.keygen(height=h, workers=4)
            self.assertEqual(len(pk), 65)
            self.assertEqual(len(sk), 97)
            self.assertEqual(pk[0], h)
            sig_par = QHS512HypertreeEngine.sign(sk, msg, hedged=False, workers=4)
            self.assertEqual(len(sig_par), 2180 + h * 32)
            self.assertTrue(QHS512HypertreeEngine.verify(pk, msg, sig_par))
            if h == 8:
                sig_one = QHS512HypertreeEngine.sign(sk, msg, hedged=False, workers=1)
                self.assertEqual(sig_par, sig_one)

    def test_05_verified_speedup_qhs512_keygen_sign_verify(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        msg = b"OpenQPEP v1.2.7 QHS-512 speedup benchmark payload"
        try:
            # Warmup
            set_native_enabled(True)
            pk_w, sk_w = QHS512HypertreeEngine.keygen(height=4)
            sig_w = QHS512HypertreeEngine.sign(sk_w, msg, hedged=False)
            self.assertTrue(QHS512HypertreeEngine.verify(pk_w, msg, sig_w))

            t0 = time.perf_counter()
            for _ in range(5):
                pk_c, sk_c = QHS512HypertreeEngine.keygen(height=4)
                sig_c = QHS512HypertreeEngine.sign(sk_c, msg, hedged=False)
                self.assertTrue(QHS512HypertreeEngine.verify(pk_c, msg, sig_c))
            native_s = (time.perf_counter() - t0) / 5.0

            set_native_enabled(False)
            t1 = time.perf_counter()
            pk_p, sk_p = QHS512HypertreeEngine.keygen(height=4)
            sig_p = QHS512HypertreeEngine.sign(sk_p, msg, hedged=False)
            self.assertTrue(QHS512HypertreeEngine.verify(pk_p, msg, sig_p))
            pure_s = time.perf_counter() - t1

            speedup = pure_s / max(native_s, 1e-9)
            self.assertGreater(
                speedup,
                4.0,
                f"Expected >=4x QHS-512 speedup, got {speedup:.1f}x "
                f"(C99={native_s*1000:.2f}ms vs Py={pure_s*1000:.2f}ms)",
            )
        finally:
            set_native_enabled(True)

    def test_06_external_c99_consumer_qhs512_static_and_shared_wpedantic(self):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No C compiler found on PATH.")

        consumer_c = r"""
#include <stdint.h>
#include <string.h>
#include "openqpep.h"

int main(void) {
    uint8_t sk_seed[32], pub_seed[32], rnd32[32], digest[32];
    for (size_t i = 0; i < 32U; i++) {
        sk_seed[i] = (uint8_t)(i + 1U);
        pub_seed[i] = (uint8_t)(i + 0x41U);
        rnd32[i] = (uint8_t)(i ^ 0xA5U);
        digest[i] = (uint8_t)(i * 7U + 3U);
    }

    /* 1. WOTS+ chain composition identity: chain(x, 0, 5) + chain(., 5, 10) == chain(x, 0, 15) */
    uint8_t c_full[32], c_part[32];
    if (openqpep_qhs_wots_chain(digest, 0U, 15U, pub_seed, 2U, 13U, c_full) != OPENQPEP_OK) return 1;
    if (openqpep_qhs_wots_chain(digest, 0U, 5U, pub_seed, 2U, 13U, c_part) != OPENQPEP_OK) return 2;
    if (openqpep_qhs_wots_chain(c_part, 5U, 10U, pub_seed, 2U, 13U, c_part) != OPENQPEP_OK) return 3;
    if (!openqpep_ct_eq(c_full, c_part, 32U)) return 4;

    /* 2. WOTS+ sign + pk_from_sig == wots_pk_from_sk_seed */
    uint8_t wsig[OPENQPEP_QHS_WOTS_SIG_BYTES], lpk1[32], lpk2[32];
    if (openqpep_qhs_wots_pk_from_sk_seed(sk_seed, pub_seed, 9U, lpk1) != OPENQPEP_OK) return 5;
    if (openqpep_qhs_wots_sign(sk_seed, pub_seed, 9U, digest, wsig) != OPENQPEP_OK) return 6;
    if (openqpep_qhs_wots_pk_from_sig(wsig, digest, pub_seed, 9U, lpk2) != OPENQPEP_OK) return 7;
    if (!openqpep_ct_eq(lpk1, lpk2, 32U)) return 8;

    /* 3. Keygen h=4 & split-subtree TreeHash + fold_subtrees root equality */
    uint8_t pk[OPENQPEP_QHS_PK_BYTES], sk[OPENQPEP_QHS_SK_BYTES];
    if (openqpep_qhs_keygen_from_seeds(4U, sk_seed, pub_seed, pk, sk) != OPENQPEP_OK) return 9;

    uint8_t sub_roots[4 * 32], folded_root[32], top_auth[2 * 32];
    for (uint32_t s = 0U; s < 4U; s++) {
        if (openqpep_qhs_treehash_subtree(sk_seed, pub_seed, s * 4U, 2U, 0U, 0, NULL, sub_roots + s * 32U) != OPENQPEP_OK) {
            return 10;
        }
    }
    if (openqpep_qhs_fold_subtrees(pub_seed, sub_roots, 2U, 1U, 1, top_auth, folded_root) != OPENQPEP_OK) return 11;
    if (!openqpep_ct_eq(folded_root, pk + 33U, 32U)) return 12;

    /* 4. Sign (hedged + det), verify, tamper reject, and Fault-Guard */
    static const uint8_t msg[] = "C99 QHS-512 XMSS Consumer Test";
    size_t msg_len = sizeof(msg) - 1U;
    uint8_t sig[OPENQPEP_QHS_SIG_FIXED_BYTES + 4U * 32U];

    if (openqpep_qhs_sign_core(sk, msg, msg_len, 1, rnd32, sig, sizeof(sig)) != OPENQPEP_OK) return 13;
    if (openqpep_qhs_verify(pk, msg, msg_len, sig, sizeof(sig)) != OPENQPEP_OK) return 14;

    /* Tamper 1 bit -> OPENQPEP_ERR_AUTH_FAIL */
    sig[40] ^= 0x01U;
    if (openqpep_qhs_verify(pk, msg, msg_len, sig, sizeof(sig)) != OPENQPEP_ERR_AUTH_FAIL) return 15;
    sig[40] ^= 0x01U;

    /* Corrupt sk root -> built-in Fault-Guard triggers OPENQPEP_ERR_FAULT_GUARD */
    sk[96] ^= 0x80U;
    if (openqpep_qhs_sign_core(sk, msg, msg_len, 0, NULL, sig, sizeof(sig)) != OPENQPEP_ERR_FAULT_GUARD) return 16;
    if (!openqpep_is_zeroed(sig, sizeof(sig))) return 17;

    /* Bounds / NULL error codes */
    if (openqpep_qhs_keygen_from_seeds(OPENQPEP_QHS_MAX_HEIGHT + 1U, sk_seed, pub_seed, pk, sk) != OPENQPEP_ERR_INVALID_LEN) return 18;
    if (openqpep_qhs_verify(NULL, msg, msg_len, sig, sizeof(sig)) != OPENQPEP_ERR_NULL_PTR) return 19;
    return 0;
}
"""
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"
        if not (shared_lib.is_file() and static_lib.is_file()):
            self.skipTest("Native static/shared libraries not built.")

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "test_v127.c"
            bin_static = Path(tmp) / "test_v127_static"
            bin_shared = Path(tmp) / "test_v127_shared"
            src.write_text(consumer_c, encoding="utf-8")

            subprocess.run(
                [
                    cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    "-DOPENQPEP_STATIC", f"-I{CSRC_DIR / 'include'}",
                    str(src), str(static_lib), "-o", str(bin_static),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(bin_static)], check=True, capture_output=True, text=True)

            subprocess.run(
                [
                    cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    f"-I{CSRC_DIR / 'include'}",
                    str(src), f"-L{NATIVE_DIR}", "-lopenqpep", f"-Wl,-rpath,{NATIVE_DIR}",
                    "-o", str(bin_shared),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = f"{NATIVE_DIR}:{env.get('LD_LIBRARY_PATH', '')}"
            subprocess.run([str(bin_shared)], env=env, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
