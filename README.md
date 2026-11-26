# OpenQPEP by Calyx Labs Inc. — Official Release `v1.2.9` (`OpenQPEP/1.2.9`)

**Protocol Version:** `OpenQPEP/1.2.9` (`Official Release 1.2.9`, PEP 440 `1.2.9`, **Phase 2 Complete — Native C99 / SIMD SDK Benchmark Refresh & 100% Native/Pure-Python Parity Gate**, upgraded from **Official Release `1.2.8`**)  
**Creator & Lead Architect:** Tristen Martinez (Calyx Labs Inc., Cleveland, Ohio)  
**Repository:** https://github.com/CalyxLabsInc/OpenQPEP  
**Public Key Directory & QPEP-KT:** https://qpepkeys.calyxlabsinc.org  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

OpenQPEP is a modern, quantum-proof encryption, authentication, and messaging protocol engineered to replace legacy OpenPGP (RFC 4880 / RFC 9580) as a worldwide standard—with provable multi-assumption post-quantum security, constant-time native C99/Rust/WASM/Go performance, and 100% deterministic Known Answer Test (KAT) verification.

## Official Release `v1.2.9` Highlights (Phase 2 Consolidation — Performance Benchmark Refresh & Native/Pure-Python Parity Gate)

- **100% Official `v1.0.x`–`v1.2.x` Interoperability (`1.0.0`–`1.2.8` ↔ `1.2.9`):** Preserves complete Wire Format v5 (`\x89QPE\x05\x00`), Compact TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), and `kdf_version: 4` compatibility across all Official Public Stable Releases while continuing to hard-reject all retired pre-release formats (`-rc`, `-pc`, `-beta`, Wire v1–v4, `kdf_version < 4`) with `QPEPLegacyProtocolError`.
- **Phase 2 Complete Native C99 / SIMD SDK (`libopenqpep v1.2.9`, `OPENQPEP_ABI_VERSION = 0x00010209U`, `108/108` Exported APIs):**
  - **Refreshed 10-Suite Comparative Benchmark Harness (`benchmarks/bench_suites.py`, `benchmarks/benchmark_results.json`):** Process-isolated Native C99/SIMD (`libopenqpep` AVX2) vs Pure-Python (`OPENQPEP_DISABLE_NATIVE=1`) telemetry measuring keygen, encaps/encrypt, decaps/decrypt, sign, verify, total speedup, and independent Peak RSS across all 10 suites (`37.24–40.72 MiB` Peak RSS, up to **`118.27x`** total suite speedup and **`406.2x`** keygen speedup).
  - **Locked 100% Native C99 ↔ Pure-Python Parity Gate (`tests/test_v129_c99_parity.py`, `.github/workflows/ci.yml`):** Enforces 10/10 Golden KAT identity across both backends with zero `mlock` leaks, full bidirectional Native↔Pure-Python cross-backend encrypt/decrypt & sign/verify across all 10 suites, deterministic byte-exact parity across all 9 accelerated primitive families under `deterministic_urandom`, and CI enforcement of both Phase 1 (`test_v119_phase1_audit.py`) and Phase 2 (`test_v129_c99_parity.py`) gates alongside `ASan`+`LSan`+`UBSan` sanitizers.
  - **Complete Phase 2 C99 Stack (`v1.2.0`–`v1.2.9`):** Public ABI header `include/openqpep.h`, strict ISO C99 `-Wall -Wextra -Werror -Wpedantic -fvisibility=hidden` Makefile & CMake builds (`libopenqpep.so` + `libopenqpep.a` + `openqpep.pc`), standalone 24-round `keccak_f1600.c`, KyberSlash-free `poly_ring_c.c` + fused `ntt_3329.c` + Solinas-Barrett `ntt_8380417.c`, O(1)-RAM row-streamed `plain_lwe_c.c`, branchless $\mathrm{GF}(2^{10})$ Binary Goppa & Patterson `goppa_c.c`, branchless $\mathrm{GF}(2^{127})$ LRPC & constant-time Gauss-Jordan UOV $\mathrm{GF}(256)$ `rank_uov_c.c`, zero-heap Wire v5/v5.1 + streaming `CC-512` CMT-4/SIV + constant-time `wire_c.c`/`pentad_accel.c`, 4-way AVX2/portable SIMD `QHS-512` WOTS+ & parallel XMSS `qhs_c.c`, and standalone 108/108-API ASan/UBSan self-test harness `test_openqpep_c.c`.
- **Phase 1 Complete Hardening Baseline (`v1.1.1`–`v1.1.9`):**
  - 9-threat active adversarial attack simulator (`openqpep audit`: `83/83` attacks defended across FO malleability, universal multi-suite fault injection, stream truncation/reorder/flags, suite/legacy downgrade, Ed448 `E[4]` small-order & X448 low-order, RFC 4648 §3.5 canonical Base64 / armor / TLV DoS, duplicate JSON keys / 2,000-level JSON depth bombs / Unicode homograph & Bidi UIDs, and Ratchet/MLS/Sphinx replay + CMT-4 + KDF OOM-bomb + 1,000:1 zip-bomb defenses).
  - Bit-exact RFC 9106 `QPKD-Argon2id` across `argon2-cffi`, OpenSSL 3.2+, and Pure-Python; KyberSlash-immune branchless lattice arithmetic (AST-guarded); FIPS 204-style hedged signatures & Verify-Before-Emit Fault-Guard across all 10 suites; CMT-4 `CC-512` + `CC-512-SIV`; OS `mlock`/`MADV_DONTDUMP` guard-page secret arenas; and permanent AST zero-broad-`except` enforcement.

## Verified Phase 2 Performance Benchmarks (`v1.2.9` Native C99/AVX2 vs Pure-Python)

Measured via `python3 benchmarks/bench_suites.py --compare --isolate` (process-isolated Peak RSS, x86_64 Linux GCC 15.2 `-O3 -mavx2`, stored in [benchmarks/benchmark_results.json](benchmarks/benchmark_results.json)):

| Suite (`v1.2.9`) | Hardware Tier | Keygen (C99 / Py) | Encaps (C99 / Py) | Decaps (C99 / Py) | Sign (C99 / Py) | Verify (C99 / Py) | Total Speedup | Peak RSS |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **QLX-4096** *(Default)* | All Devices | **7.97** / 1,949.59 ms | **5.70** / 101.77 ms | **8.13** / 118.68 ms | **12.55** / 85.28 ms | **2.87** / 31.26 ms | **61.43x** | 37.24 MiB |
| **QLX-768** | All Devices | **1.97** / 689.49 ms | **1.11** / 9.21 ms | **1.67** / 13.24 ms | **3.88** / 27.17 ms | **1.02** / 9.62 ms | **77.59x** | 37.24 MiB |
| **QLX-1024** | All Devices | **2.55** / 855.73 ms | **1.36** / 13.23 ms | **2.14** / 19.06 ms | **3.98** / 37.42 ms | **1.27** / 13.59 ms | **83.10x** | 37.24 MiB |
| **QLX-2048** | All Devices | **4.40** / 1,787.43 ms | **2.63** / 34.58 ms | **3.68** / 44.81 ms | **9.51** / 102.78 ms | **2.26** / 22.07 ms | **88.60x** | 37.24 MiB |
| **QLX-16384** | HIGH-TIER (`>= 12 GB`) | **24.07** / 4,619.85 ms | **21.95** / 416.56 ms | **24.38** / 450.14 ms | **71.16** / 1,662.21 ms | **6.06** / 76.72 ms | **48.95x** | 39.36 MiB |
| **CRT-RSD512** | All Devices | **2.65** / 589.43 ms | **1.14** / 62.32 ms | **2.43** / 160.12 ms | **0.60** / 8.02 ms | **0.14** / 3.26 ms | **118.27x** | 39.54 MiB |
| **CGM-8192** | HIGH-TIER (`>= 12 GB`) | **24.17** / 811.32 ms | **0.61** / 0.76 ms | **1.47** / 10.49 ms | **6.50** / 35.17 ms | **0.39** / 0.96 ms | **25.91x** | 39.54 MiB |
| **CULC-2048** | HIGH-TIER (`>= 12 GB`) | **29.47** / 332.25 ms | **1.66** / 7.14 ms | **2.64** / 17.14 ms | **7.52** / 35.77 ms | **0.74** / 1.44 ms | **9.37x** | 40.04 MiB |
| **CIF-SQI-512** *(QHS-512 C99; CSIDH Py)* | All Devices | 342.12 / 306.82 ms | 637.99 / 432.93 ms | 217.97 / 214.15 ms | **6.88** / 35.53 ms | **0.61** / 1.44 ms | **5.16x** *(Sign)* | 39.54 MiB |
| **CSP-Omega** *(4/5 C99; CSIDH Py)* | HIGH-TIER (`>= 12 GB`) | **429.23** / 706.01 ms | 515.34 / 439.27 ms | 249.80 / 234.85 ms | **5,877.24** / 10,884.41 ms | **2,040.02** / 2,211.84 ms | **1.59x** | 40.72 MiB |

## All 10 Canonical OpenQPEP Post-Quantum Suites (`v1.2.9`)

| Canonical Suite Name | KEM + Signature | Mathematical Family | Hardware Classification |
| :--- | :--- | :--- | :--- |
| **Calyx Lattice-Apex: QLX-4096 + QVS-256 (4,096-Dim Module-LWE — All Devices)** | `QLX-4096` + `QVS-256` | Module-LWE (`k=16`) + Hybrid X448 | **All Devices** |
| **Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)** | `QLX-768` + `QVS-65` | Module-LWE (`k=3`) + Hybrid X448 | **All Devices** |
| **Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)** | `QLX-1024` + `QVS-87` | Module-LWE (`k=4`) + Hybrid X448 | **All Devices** |
| **Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)** | `QLX-2048` + `QVS-128` | Module-LWE (`k=8`) + Hybrid X448 | **All Devices** |
| **Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)** | `CIF-SQI-512` + `QHS-512` | CSIDH-512 Isogeny + Stateless Hash Hypertree | **All Devices** |
| **Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (All-Devices Signature Default — All Devices)** | `CRT-RSD512` + `QMQ-512` | LRPC Rank-Metric Code + UOV Multivariate | **All Devices** |
| **Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)** | `QLX-16384` + `QVS-1024` | 4-Manifold Module-LWE (`k=64`) + `16×14` QVS | **HIGH-TIER (`>= 12 GB RAM`)** |
| **Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)** | `CGM-8192` + `QHS-512` | Binary Goppa Patterson + Hash Hypertree | **HIGH-TIER (`>= 12 GB RAM`)** |
| **Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)** | `CULC-2048` + `CGM-8192` | Plain-LWE + Binary Goppa Patterson | **HIGH-TIER (`>= 12 GB RAM`)** |
| **Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (High-Tier Signature Default — HIGH-TIER HARDWARE ONLY)** | `CSP-Omega` + `QHS-512` | 5-Family Combiner + X448 | **HIGH-TIER (`>= 12 GB RAM`)** |

## Quickstart & Conformance Verification

```bash
# 1. Build Native C99 / SIMD SDK & Run Standalone C99 Self-Test Harness + ASan/UBSan Gate
make -C calyx_qpep/native/csrc clean all test test-san test-san-portable

# 2. Install OpenQPEP Official Release 1.2.9
pip install -e .

# 3. Verify All 10 Deterministic Golden KAT Suites (Native C99 & Pure-Python)
python3 -m calyx_qpep.cli verify-vectors
OPENQPEP_DISABLE_NATIVE=1 python3 -m calyx_qpep.cli verify-vectors

# 4. Run 10-Suite Comparative Native C99 vs Pure-Python Benchmark Harness
python3 benchmarks/bench_suites.py --compare --isolate

# 5. Run Active Adversarial Attack Simulator & 5-Language Interop Audit
python3 -m calyx_qpep.cli audit

# 6. Run Full Cryptographic, C99 ABI, Fuzzing & Phase 1+2 Test Suite
python3 -m unittest discover -s tests -v

# 7. Launch Interactive Shell or Scriptable CLI
openqpep --version
openqpep
```

## Specifications & Documentation

- [WIRE_FORMAT_V5_SPEC.md](WIRE_FORMAT_V5_SPEC.md) — Official Binary Wire Format v5 / Compact TLV v5.1 / Stream v5 Specification
- [specs/OPENQPEP_v1.2.9_OFFICIAL_RELEASE_SPEC.md](specs/OPENQPEP_v1.2.9_OFFICIAL_RELEASE_SPEC.md) — Official Release `v1.2.9` Phase 2 Frozen Wire v5 & C99 SDK ABI Specification
- [calyx_qpep/native/csrc/include/openqpep.h](calyx_qpep/native/csrc/include/openqpep.h) — Public C99/C++ SDK ABI Header
- [benchmarks/benchmark_results.json](benchmarks/benchmark_results.json) — Verified 10-Suite Native C99 vs Pure-Python Comparative Benchmarks
- [CHANGELOG.md](CHANGELOG.md) — Official Release Changelog
- [docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Mathematical & Cryptographic Specification
- [docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — OpenQPEP vs. OpenPGP Security Comparison
- [docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — `.qpkrf` Key Ring & Wire Format Guide
- [docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — CLI, Client Ecosystem & Key Transparency Guide
