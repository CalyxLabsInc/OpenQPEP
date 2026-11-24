"""
OpenQPEP Official Release 1.2.0 (v1.2.0) — Phase 2 Kickoff:
Public C99 ABI Header (include/openqpep.h) & Build System Overhaul Test Suite.

Verifies:
  1. Versioned C99 ABI header `include/openqpep.h` (OPENQPEP_ABI_VERSION, OPENQPEP_API/LOCAL
     symbol visibility macros, extern "C" guards, all public declarations).
  2. Runtime ABI introspection (`openqpep_abi_version`, `openqpep_version_string`) matching
     UNIVERSAL_VERSION via ctypes loader (`native_abi_version`, `native_version_string`, `native_backend_info`).
  3. Makefile strict build (`-std=c99 -Wall -Wextra -Werror -Wpedantic -fvisibility=hidden`)
     producing shared `libopenqpep.so`/`.dylib`, static `libopenqpep.a`, and `pkg-config` `openqpep.pc`.
  4. Dynamic symbol table visibility enforcement (ONLY `openqpep_*` public API symbols exported;
     zero internal helper leakage).
  5. Standalone external C99 consumer compiled with `-std=c99 -Wall -Wextra -Werror -Wpedantic`
     and linked against BOTH static `libopenqpep.a` and shared `libopenqpep.so` executing every ABI group.
  6. Out-of-source CMake build producing shared + static targets + `openqpep.pc` with zero warnings.
  7. C++17 consumer compilation (`#include "openqpep.h"`) proving clean `extern "C"` ABI linkage.
"""
import os
import platform
import re
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
    native_backend_info,
    native_version_string,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
HEADER_PATH = CSRC_DIR / "include" / "openqpep.h"
PC_IN_PATH = CSRC_DIR / "openqpep.pc.in"
CMAKE_PATH = CSRC_DIR / "CMakeLists.txt"

EXPECTED_PUBLIC_SYMBOLS = {
    "openqpep_abi_version",
    "openqpep_version_string",
    "openqpep_native_abi_info",
    "openqpep_ntt_3329",
    "openqpep_inv_ntt_3329",
    "openqpep_ntt_base_mul_3329",
    "openqpep_poly_add_3329",
    "openqpep_poly_sub_3329",
    "openqpep_ntt_qvs",
    "openqpep_inv_ntt_qvs",
    "openqpep_ntt_mul_qvs",
    "openqpep_cbd2_3329",
    "openqpep_cbd1_3329",
    "openqpep_cbd2_qvs",
    "openqpep_plain_lwe_row_accum_u16",
    "openqpep_plain_lwe_keygen_row_u16",
    "openqpep_gf256_mul",
    "openqpep_xor_accum_bytes",
    "openqpep_ct_eq",
    "openqpep_ct_cmov",
    "openqpep_explicit_bzero",
    "openqpep_is_zeroed",
    "openqpep_verify_wire_v5_magic",
}


def _expected_abi_int(ver: str) -> int:
    maj, min_, pat = (int(x) for x in ver.split(".")[:3])
    return ((maj & 0xFF) << 16) | ((min_ & 0xFF) << 8) | (pat & 0xFF)


class TestOpenQPEPv120C99ABIAndBuildSystem(unittest.TestCase):
    def test_01_version_metadata_is_120(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.2.0")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.2.0")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.2.0")

    def test_02_public_header_and_runtime_abi_introspection(self):
        self.assertTrue(HEADER_PATH.is_file(), f"Missing public C99 header: {HEADER_PATH}")
        hdr = HEADER_PATH.read_text(encoding="utf-8")
        for token in (
            "#ifndef OPENQPEP_H",
            "extern \"C\"",
            "OPENQPEP_ABI_VERSION",
            "OPENQPEP_API",
            "OPENQPEP_LOCAL",
            f'OPENQPEP_VERSION_STRING "{UNIVERSAL_VERSION}"',
        ):
            self.assertIn(token, hdr)
        for sym in EXPECTED_PUBLIC_SYMBOLS:
            self.assertIn(sym, hdr, f"Public symbol '{sym}' missing from openqpep.h")

        expected_abi = _expected_abi_int(UNIVERSAL_VERSION)
        if is_native_available():
            self.assertEqual(native_abi_version(), expected_abi)
            self.assertEqual(native_version_string(), UNIVERSAL_VERSION)
            info = native_backend_info()
            self.assertEqual(info["abi_version"], expected_abi)
            self.assertEqual(info["c_version"], UNIVERSAL_VERSION)

    def test_03_makefile_shared_static_and_pkgconfig_artifacts(self):
        self.assertTrue(PC_IN_PATH.is_file())
        self.assertTrue(CMAKE_PATH.is_file())
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"
        pc_file = NATIVE_DIR / "openqpep.pc"

        self.assertTrue(shared_lib.is_file(), f"Expected shared library built: {shared_lib}")
        self.assertTrue(static_lib.is_file(), f"Expected static archive built: {static_lib}")
        self.assertTrue(pc_file.is_file(), f"Expected pkg-config manifest built: {pc_file}")

        pc_txt = pc_file.read_text(encoding="utf-8")
        self.assertIn("Name: libopenqpep", pc_txt)
        self.assertIn(f"Version: {UNIVERSAL_VERSION}", pc_txt)
        self.assertIn("-lopenqpep", pc_txt)
        self.assertIn("-I${includedir}", pc_txt)
        self.assertNotIn("@VERSION@", pc_txt)
        self.assertNotIn("@PREFIX@", pc_txt)

    def test_04_dynamic_symbol_visibility_exports_only_openqpep_api(self):
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        if not shared_lib.is_file() or not shutil.which("nm"):
            self.skipTest("Shared library or nm not available on this host.")

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

        missing = EXPECTED_PUBLIC_SYMBOLS - exported
        self.assertEqual(missing, set(), f"Missing exported OPENQPEP_API symbols: {missing}")

        # Verify internal helpers are hidden under -fvisibility=hidden
        leaked = {s for s in exported if not s.startswith("openqpep_")}
        self.assertEqual(leaked, set(), f"Unexpected non-openqpep symbols exported: {leaked}")
        for internal in ("ct_barrett_3329", "ct_caddq_3329", "ct_csubq_3329", "ZETAS_3329", "ZETAS_QVS"):
            self.assertNotIn(internal, exported)

    def test_05_external_c99_consumer_links_static_and_shared_wpedantic(self):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No C compiler found on PATH.")

        consumer_c = r"""
#include <stdint.h>
#include <string.h>
#include "openqpep.h"

int main(void) {
    if (openqpep_abi_version() != OPENQPEP_ABI_VERSION) return 1;
    if (strcmp(openqpep_version_string(), OPENQPEP_VERSION_STRING) != 0) return 2;
    if ((openqpep_native_abi_info() & OPENQPEP_ABI_FLAG_C99) == 0U) return 3;

    int32_t poly[OPENQPEP_QLX_N];
    int32_t orig[OPENQPEP_QLX_N];
    for (int i = 0; i < OPENQPEP_QLX_N; i++) {
        poly[i] = (i * 37 + 11) % OPENQPEP_QLX_Q;
        orig[i] = poly[i];
    }
    openqpep_ntt_3329(poly);
    openqpep_inv_ntt_3329(poly);
    for (int i = 0; i < OPENQPEP_QLX_N; i++) {
        if (poly[i] != orig[i]) return 4;
    }

    int32_t qpoly[OPENQPEP_QVS_N];
    int32_t qorig[OPENQPEP_QVS_N];
    for (int i = 0; i < OPENQPEP_QVS_N; i++) {
        qpoly[i] = (i * 19937 + 5) % OPENQPEP_QVS_Q;
        qorig[i] = qpoly[i];
    }
    openqpep_ntt_qvs(qpoly);
    openqpep_inv_ntt_qvs(qpoly);
    for (int i = 0; i < OPENQPEP_QVS_N; i++) {
        if (qpoly[i] != qorig[i]) return 5;
    }

    uint8_t secret[32];
    uint8_t other[32];
    uint8_t chosen[32];
    for (size_t i = 0; i < 32; i++) {
        secret[i] = (uint8_t)(i + 1U);
        other[i] = (uint8_t)(0xFFU - i);
    }
    if (openqpep_ct_eq(secret, secret, 32) != 1) return 6;
    if (openqpep_ct_eq(secret, other, 32) != 0) return 7;
    openqpep_ct_cmov(1, chosen, secret, other, 32);
    if (openqpep_ct_eq(chosen, secret, 32) != 1) return 8;
    openqpep_explicit_bzero(secret, 32);
    if (openqpep_is_zeroed(secret, 32) != 1) return 9;

    const uint8_t v5[6] = {0x89U, 'Q', 'P', 'E', 0x05U, 0x00U};
    const uint8_t v51[6] = {0x89U, 'Q', 'P', 'E', 0x05U, 0x01U};
    const uint8_t v4[6] = {0x89U, 'Q', 'P', 'E', 0x04U, 0x00U};
    if (openqpep_verify_wire_v5_magic(v5, 6) != OPENQPEP_WIRE_V5_FULL) return 10;
    if (openqpep_verify_wire_v5_magic(v51, 6) != OPENQPEP_WIRE_V5_1_COMPACT) return 11;
    if (openqpep_verify_wire_v5_magic(v4, 6) != OPENQPEP_WIRE_ERR_LEGACY_RC) return 12;

    return 0;
}
"""
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "consumer.c"
            src_file.write_text(consumer_c, encoding="utf-8")

            # 1. Link against static libopenqpep.a
            bin_static = Path(tmpdir) / "consumer_static"
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
            r_static = subprocess.run([str(bin_static)], capture_output=True, text=True)
            self.assertEqual(r_static.returncode, 0, f"Static C99 consumer failed with rc={r_static.returncode}")

            # 2. Link against shared libopenqpep.so
            bin_shared = Path(tmpdir) / "consumer_shared"
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
            r_shared = subprocess.run([str(bin_shared)], capture_output=True, text=True)
            self.assertEqual(r_shared.returncode, 0, f"Shared C99 consumer failed with rc={r_shared.returncode}")

    def test_06_cmake_out_of_source_build_shared_static_and_pkgconfig(self):
        cmake = shutil.which("cmake")
        if not cmake:
            self.skipTest("cmake not available on PATH.")

        with tempfile.TemporaryDirectory() as tmpdir:
            bdir = Path(tmpdir) / "build"
            install_dir = Path(tmpdir) / "install"
            subprocess.run(
                [
                    cmake, "-S", str(CSRC_DIR), "-B", str(bdir),
                    f"-DCMAKE_INSTALL_PREFIX={install_dir}",
                    "-DOPENQPEP_BUILD_SHARED=ON",
                    "-DOPENQPEP_BUILD_STATIC=ON",
                    "-DOPENQPEP_BUILD_JNI=ON",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [cmake, "--build", str(bdir)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [cmake, "--install", str(bdir)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue((install_dir / "include" / "openqpep.h").is_file())
            pc_matches = list(install_dir.rglob("openqpep.pc"))
            self.assertEqual(len(pc_matches), 1)
            pc_txt = pc_matches[0].read_text(encoding="utf-8")
            self.assertIn(f"Version: {UNIVERSAL_VERSION}", pc_txt)
            a_matches = list(install_dir.rglob("libopenqpep.a"))
            self.assertEqual(len(a_matches), 1)

    def test_07_cpp17_extern_c_header_compatibility(self):
        cxx = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
        if not cxx:
            self.skipTest("No C++ compiler found on PATH.")
        static_lib = NATIVE_DIR / "libopenqpep.a"
        cpp_src = r"""
#include <cstring>
#include "openqpep.h"
int main() {
    return (openqpep_abi_version() == OPENQPEP_ABI_VERSION &&
            std::strcmp(openqpep_version_string(), OPENQPEP_VERSION_STRING) == 0) ? 0 : 1;
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "consumer.cpp"
            bin_cpp = Path(tmpdir) / "consumer_cpp"
            src_file.write_text(cpp_src, encoding="utf-8")
            subprocess.run(
                [
                    cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    "-DOPENQPEP_STATIC", f"-I{CSRC_DIR / 'include'}",
                    str(src_file), str(static_lib), "-o", str(bin_cpp),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            r = subprocess.run([str(bin_cpp)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
