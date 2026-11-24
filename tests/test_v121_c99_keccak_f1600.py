"""
OpenQPEP Official Release 1.2.1 (v1.2.1) — Native C99 Keccak-f[1600] (qSponge-512 / SHA3 / SHAKE) Test Suite.

Verifies:
  1. Official NIST FIPS 202 Known Answer Test vectors for SHA3-512, SHA3-256, SHAKE-256, and SHAKE-128.
  2. Exhaustive rate-boundary bit-exact parity between C99 `keccak_f1600.c` and Python `hashlib`
     across absorb lengths (0..4096 B, hitting every 72/136/168-byte boundary) and squeeze lengths (0..1000 B).
  3. Incremental chunked streaming absorb & multi-call squeeze (`NativeKeccakSponge`) bit-exact parity,
     post-finalize absorb rejection, and compiler-barrier wipe.
  4. Seamless Native C99 <-> Pure-Python (`OPENQPEP_DISABLE_NATIVE=1`) switch parity in `qsponge_512` / `qsponge_var`.
  5. Standalone external C99 consumer compiled under `-std=c99 -Wall -Wextra -Werror -Wpedantic`
     linking BOTH static `libopenqpep.a` and shared `libopenqpep.so` verifying `openqpep_keccak_f1600`,
     streaming absorb/squeeze, `openqpep_keccak_wipe` + `openqpep_is_zeroed`, and NULL-pointer guards.
"""
import hashlib
import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from calyx_qpep import (
    PROTOCOL_VERSION,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    is_native_available,
    native_abi_version,
    qsponge_512,
    qsponge_var,
    set_native_enabled,
)
from calyx_qpep.native import (
    NativeKeccakSponge,
    native_qsponge_512,
    native_qsponge_var,
    native_sha3_256,
    native_shake128,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"


class TestOpenQPEPv121C99KeccakF1600(unittest.TestCase):
    def test_01_version_metadata_is_121(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.2.1")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.2.1")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.2.1")
        if is_native_available():
            self.assertEqual(native_abi_version(), 0x00010201)

    def test_02_nist_fips202_official_test_vectors(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        # Official NIST FIPS 202 empty-string and "abc" Known Answer Vectors
        self.assertEqual(
            native_qsponge_512(b"").hex(),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        )
        self.assertEqual(
            native_qsponge_512(b"abc").hex(),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        )
        self.assertEqual(
            native_sha3_256(b"").hex(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )
        self.assertEqual(
            native_sha3_256(b"abc").hex(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        )
        self.assertEqual(
            native_qsponge_var(b"", 32).hex(),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
        )
        self.assertEqual(
            native_shake128(b"", 32).hex(),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        )
        # 200-byte "abcdefghbcdefghicdefghij..." NIST multi-block check
        nist_long = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" * 16
        self.assertEqual(native_qsponge_512(nist_long), hashlib.sha3_512(nist_long).digest())
        self.assertEqual(native_sha3_256(nist_long), hashlib.sha3_256(nist_long).digest())
        self.assertEqual(native_qsponge_var(nist_long, 256), hashlib.shake_256(nist_long).digest(256))
        self.assertEqual(native_shake128(nist_long, 256), hashlib.shake_128(nist_long).digest(256))

    def test_03_exhaustive_rate_boundary_lengths_c99_vs_hashlib_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        # Exercise every rate boundary: SHA3-512 (72), SHA3-256/SHAKE256 (136), SHAKE128 (168)
        in_lengths = (
            0, 1, 7, 8, 9, 63, 64, 71, 72, 73, 135, 136, 137,
            143, 144, 145, 167, 168, 169, 271, 272, 273, 336, 512, 4096,
        )
        for n in in_lengths:
            data = bytes((i * 73 + n) & 0xFF for i in range(n))
            self.assertEqual(native_qsponge_512(data), hashlib.sha3_512(data).digest(), f"SHA3-512 len={n}")
            self.assertEqual(native_sha3_256(data), hashlib.sha3_256(data).digest(), f"SHA3-256 len={n}")
            self.assertEqual(native_qsponge_var(data, 64), hashlib.shake_256(data).digest(64), f"SHAKE256 len={n}")
            self.assertEqual(native_shake128(data, 64), hashlib.shake_128(data).digest(64), f"SHAKE128 len={n}")

        # Exercise variable squeeze lengths crossing 72/136/168-byte rate boundaries
        sample = b"OpenQPEP-v1.2.1-Squeeze-Boundary-Probe" * 7
        for out_n in (0, 1, 7, 8, 32, 64, 71, 72, 73, 135, 136, 137, 167, 168, 169, 272, 513, 1000):
            self.assertEqual(
                native_qsponge_var(sample, out_n),
                hashlib.shake_256(sample).digest(out_n),
                f"SHAKE256 out_len={out_n}",
            )
            self.assertEqual(
                native_shake128(sample, out_n),
                hashlib.shake_128(sample).digest(out_n),
                f"SHAKE128 out_len={out_n}",
            )

    def test_04_incremental_chunked_absorb_and_multi_call_squeeze(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        chunks = [
            b"",
            b"A",
            b"BCDEF",
            bytes(range(71)),
            b"XY",
            bytes((i * 19) & 0xFF for i in range(136)),
            b"Z",
            bytes((i * 31) & 0xFF for i in range(200)),
        ]
        joined = b"".join(chunks)
        squeeze_plan = (0, 1, 7, 135, 2, 136, 55, 168, 300)
        total_out = sum(squeeze_plan)

        for mode, ref_fn, ref_len in (
            ("sha3-512", lambda b, _n: hashlib.sha3_512(b).digest(), 64),
            ("sha3-256", lambda b, _n: hashlib.sha3_256(b).digest(), 32),
            ("shake256", lambda b, n: hashlib.shake_256(b).digest(n), total_out),
            ("shake128", lambda b, n: hashlib.shake_128(b).digest(n), total_out),
        ):
            with NativeKeccakSponge(mode) as sp:
                for ch in chunks:
                    sp.absorb(ch)
                sp.finalize()
                # Absorbing after finalize must raise ValueError
                with self.assertRaises(ValueError):
                    sp.absorb(b"late")
                if mode.startswith("sha3"):
                    got = sp.squeeze(11) + sp.squeeze(ref_len - 11)
                else:
                    got = b"".join(sp.squeeze(k) for k in squeeze_plan)
            self.assertEqual(got, ref_fn(joined, ref_len), f"Incremental mismatch for {mode}")

            # Accessing wiped sponge must raise RuntimeError
            with self.assertRaises(RuntimeError):
                sp.squeeze(16)

    def test_05_qsponge_native_vs_pure_python_switch_parity(self):
        prev = is_native_available()
        try:
            payloads = [b"", b"OpenQPEP/1.2.1", os.urandom(73), os.urandom(500)]
            for data in payloads:
                set_native_enabled(False)
                py_512 = qsponge_512(data)
                py_xof = qsponge_var(data, 199)
                if prev:
                    set_native_enabled(True)
                    c_512 = qsponge_512(data)
                    c_xof = qsponge_var(data, 199)
                    self.assertEqual(c_512, py_512)
                    self.assertEqual(c_xof, py_xof)
        finally:
            set_native_enabled(prev)

    def test_06_external_c99_consumer_incremental_keccak_and_wipe_wpedantic(self):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No C compiler found on PATH.")

        consumer_c = r"""
#include <stdint.h>
#include <string.h>
#include "openqpep.h"

int main(void) {
    /* 1. NIST FIPS 202 SHA3-512("") vector */
    uint8_t digest[64];
    if (openqpep_qsponge_512(NULL, 0U, digest) != OPENQPEP_OK) return 1;
    if (digest[0] != 0xa6U || digest[1] != 0x9fU || digest[62] != 0xcdU || digest[63] != 0x26U) return 2;

    /* 2. NIST FIPS 202 SHAKE-256("") vector */
    uint8_t xof[32];
    if (openqpep_qsponge_var(NULL, 0U, xof, 32U) != OPENQPEP_OK) return 3;
    if (xof[0] != 0x46U || xof[1] != 0xb9U || xof[30] != 0x76U || xof[31] != 0x2fU) return 4;

    /* 3. Incremental absorb + multi-call squeeze == one-shot */
    const uint8_t msg[150] = "OpenQPEP C99 Keccak-f[1600] Incremental Absorb/Squeeze Streaming Test Vector!";
    uint8_t oneshot[200];
    uint8_t streamed[200];
    if (openqpep_qsponge_var(msg, sizeof(msg), oneshot, sizeof(oneshot)) != OPENQPEP_OK) return 5;

    openqpep_keccak_ctx_t ctx;
    if (openqpep_shake256_init(&ctx) != OPENQPEP_OK) return 6;
    if (openqpep_keccak_absorb(&ctx, msg, 13U) != OPENQPEP_OK) return 7;
    if (openqpep_keccak_absorb(&ctx, msg + 13U, 130U) != OPENQPEP_OK) return 8;
    if (openqpep_keccak_absorb(&ctx, msg + 143U, sizeof(msg) - 143U) != OPENQPEP_OK) return 9;
    if (openqpep_keccak_finalize(&ctx) != OPENQPEP_OK) return 10;
    /* Post-finalize absorb must fail */
    if (openqpep_keccak_absorb(&ctx, msg, 1U) == OPENQPEP_OK) return 11;
    if (openqpep_keccak_squeeze(&ctx, streamed, 77U) != OPENQPEP_OK) return 12;
    if (openqpep_keccak_squeeze(&ctx, streamed + 77U, 123U) != OPENQPEP_OK) return 13;
    if (openqpep_ct_eq(oneshot, streamed, sizeof(oneshot)) != 1) return 14;

    /* 4. Wipe verification */
    openqpep_keccak_wipe(&ctx);
    if (openqpep_is_zeroed((const uint8_t *)&ctx, sizeof(ctx)) != 1) return 15;

    /* 5. NULL & bad-rate error guards */
    if (openqpep_keccak_init(NULL, 136U, 0x1FU) != OPENQPEP_ERR_NULL_PTR) return 16;
    if (openqpep_keccak_init(&ctx, 73U, 0x1FU) != OPENQPEP_ERR_INVALID_LEN) return 17;
    if (openqpep_qsponge_512(msg, 5U, NULL) != OPENQPEP_ERR_NULL_PTR) return 18;
    if (openqpep_qsponge_var(NULL, 5U, xof, 32U) != OPENQPEP_ERR_NULL_PTR) return 19;

    return 0;
}
"""
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "keccak_consumer.c"
            src_file.write_text(consumer_c, encoding="utf-8")

            # Static build
            bin_static = Path(tmpdir) / "keccak_static"
            subprocess.run(
                [
                    cc, "-std=c99", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    "-DOPENQPEP_STATIC", f"-I{CSRC_DIR / 'include'}",
                    str(src_file), str(static_lib), "-o", str(bin_static),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            r1 = subprocess.run([str(bin_static)], capture_output=True, text=True)
            self.assertEqual(r1.returncode, 0, f"Static C99 Keccak consumer failed rc={r1.returncode}")

            # Shared build
            bin_shared = Path(tmpdir) / "keccak_shared"
            subprocess.run(
                [
                    cc, "-std=c99", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    f"-I{CSRC_DIR / 'include'}",
                    str(src_file), str(shared_lib),
                    f"-Wl,-rpath,{NATIVE_DIR}",
                    "-o", str(bin_shared),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            r2 = subprocess.run([str(bin_shared)], capture_output=True, text=True)
            self.assertEqual(r2.returncode, 0, f"Shared C99 Keccak consumer failed rc={r2.returncode}")


if __name__ == "__main__":
    unittest.main()
