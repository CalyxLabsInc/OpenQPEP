# OpenQPEP by Calyx Labs Inc. — Official Release `v1.2.2` (`OpenQPEP/1.2.2`)

**Protocol Version:** `OpenQPEP/1.2.2` (`Official Release 1.2.2`, PEP 440 `1.2.2`, **Phase 2 Native C99 SDK — Polynomial Ring & Matrix-Vector Engine**, upgraded from **Official Release `1.2.1`**)  
**Creator & Lead Architect:** Tristen Martinez (Calyx Labs Inc., Cleveland, Ohio)  
**Repository:** https://github.com/CalyxLabsInc/OpenQPEP  
**Public Key Directory & QPEP-KT:** https://qpepkeys.calyxlabsinc.org  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

OpenQPEP is a modern, quantum-proof encryption, authentication, and messaging protocol engineered to replace legacy OpenPGP (RFC 4880 / RFC 9580) as a worldwide standard—with provable multi-assumption post-quantum security, constant-time native C99/Rust/WASM/Go performance, and 100% deterministic Known Answer Test (KAT) verification.

## Official Release `v1.2.2` Highlights (Native C99 Polynomial Ring & Matrix-Vector Engine — `QLX` + `QVS`)

- **100% Official `v1.0.x`–`v1.2.x` Interoperability (`1.0.0`–`1.2.1` ↔ `1.2.2`):** Preserves complete Wire Format v5 (`\x89QPE\x05\x00`), Compact TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), and `kdf_version: 4` compatibility across all Official Public Stable Releases while continuing to hard-reject all retired pre-release formats (`-rc`, `-pc`, `-beta`, Wire v1–v4, `kdf_version < 4`) with `QPEPLegacyProtocolError`.
- **Native C99 Polynomial Ring, Compression & Matrix-Vector Engine (`poly_ring_c.c`, `ntt_3329.c`, `ntt_8380417.c`):**
  - Added `calyx_qpep/native/csrc/poly_ring_c.c` exporting 20 new `OPENQPEP_API` functions (`OPENQPEP_ABI_VERSION = 0x00010202U`, `57` total exported symbols, zero leaked internal helpers): KyberSlash-free fixed-point `openqpep_poly_compress_3329` / `openqpep_poly_decompress_3329`, branchless `openqpep_byte_encode_12` / `openqpep_byte_decode_12`, streaming zero-heap QLX NTT matrix-vector multiply (`openqpep_qlx_matvec_3329`, `openqpep_qlx_inner_prod_3329`, `openqpep_qlx_sample_ntt_3329`, `openqpep_ntt_base_mul_acc_3329`), and full QVS ring codecs, samplers & matrix-vector engines (`openqpep_qvs_pack_poly24` / `unpack_poly24`, `sample_ntt`, `sample_mask_y`, `sample_in_ball`, `expand_matrix`, `matvec_precomputed`, `qvs_matvec`, `decompose_poly`, `poly_add_qvs`, `poly_sub_qvs`, `ntt_base_mul_8380417`).
  - Eliminated ALL variable-time `% QVS_Q` divisions from `ntt_8380417.c` using exact 64-bit branchless Solinas reduction modulo `8380417 = 2^23 - 2^13 + 1` with compiler-barrier zeroization (`openqpep_explicit_bzero`) on every stack secret buffer.
  - Wired transparent native C99 acceleration into `poly_ring.py`, `ntt_8380417.py`, `qlx_kem.py`, and `qvs_dsa.py` delivering multi-fold real wall-clock speedups on `QLX-4096`, `QLX-16384`, `QVS-256`, and `QVS-1024` with 100% bit-exact Pure-Python fallback under `OPENQPEP_DISABLE_NATIVE=1`.
- **Zero-Dependency Native C99 Keccak-f[1600] & Versioned SDK ABI (`v1.2.0`–`v1.2.1`):**
  - Standalone constant-time unrolled 24-round C99 `openqpep_keccak_f1600` sponge (`keccak_f1600.c`) powering `qSponge-512` / `SHA3-512` / `SHA3-256` / `SHAKE-256` / `SHAKE-128`, canonical public C99/C++ header `include/openqpep.h`, and strict `-std=c99 -Wall -Wextra -Werror -Wpedantic -fvisibility=hidden` Makefile & CMake builds (`libopenqpep.so` + `libopenqpep.a` + `openqpep.pc`).
- **Phase 1 Complete Hardening Baseline (`v1.1.1`–`v1.1.9`):**
  - 9-threat active adversarial attack simulator (`openqpep audit`: `83/83` attacks defended across FO malleability, universal multi-suite fault injection, stream truncation/reorder/flags, suite/legacy downgrade, Ed448 `E[4]` small-order & X448 low-order, RFC 4648 §3.5 canonical Base64 / armor / TLV DoS, duplicate JSON keys / 2,000-level JSON depth bombs / Unicode homograph & Bidi UIDs, and Ratchet/MLS/Sphinx replay + CMT-4 + KDF OOM-bomb + 1,000:1 zip-bomb defenses).
  - Bit-exact RFC 9106 `QPKD-Argon2id` across `argon2-cffi`, OpenSSL 3.2+, and Pure-Python with cgroup-aware memory ceilings and calibrated per-device benchmarking.
  - KyberSlash-immune division-free branchless lattice arithmetic across Python, C99, and Rust (AST-guarded), FIPS 204-style hedged signatures & Verify-Before-Emit Fault-Guard across all 10 suites, CMT-4 `CC-512` + `CC-512-SIV`, OS `mlock`/`MADV_DONTDUMP` guard-page secret arenas, and permanent AST zero-broad-`except` enforcement.
- **10 Cryptographically Genuine Post-Quantum Suites:**
  - **5 Structured Module-LWE + HGC-448 Suites:** `QLX-768`, `QLX-1024`, `QLX-2048`, `QLX-4096` (default), `QLX-16384` paired with `QVS-65`..`QVS-1024`.
  - **5 Genuine Beyond-LWE Suites:** **CSIDH-512** Supersingular Isogeny (`CIF-SQI-512`), **LRPC / ROLLO-I** Rank-Metric Syndrome Decoding (`CRT-RSD512`) + **UOV** Multivariate Quadratic (`QMQ-512`), **Classic McEliece / Niederreiter Binary Goppa Patterson** (`CGM-8192`), **Zero-Ring Plain-LWE + Goppa** (`CULC-2048`), and **5-Family Citadel** (`CSP-Omega`).
- **Complete Hardened Sub-Protocol Stack:** `QPEP-Ratchet`, `QPEP-MLS` (256-member TreeKEM), `QPEP-AKE`, `QPEP-KT`, `QVS-Ring`, `DeniableVault`, `ThresholdKEM`, `Sphinx-PQ`, `LT-QR`, `BlindSearchVault`, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.

## All 10 Canonical OpenQPEP Post-Quantum Suites (`v1.2.2`)

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
# 1. Build Native C99 / SIMD SDK (shared + static + pkg-config, zero warnings with -Wpedantic -Werror)
make -C calyx_qpep/native/csrc clean all

# 2. Install OpenQPEP Official Release 1.2.2
pip install -e .

# 3. Verify All 10 Deterministic Golden KAT Suites (Native C99 & Pure-Python)
python3 -m calyx_qpep.cli verify-vectors
OPENQPEP_DISABLE_NATIVE=1 python3 -m calyx_qpep.cli verify-vectors

# 4. Run Active Adversarial Attack Simulator & 5-Language Interop Audit
python3 -m calyx_qpep.cli audit

# 5. Run Full Cryptographic, C99 ABI, Fuzzing & Phase 1+2 Test Suite
python3 -m unittest discover -s tests -v

# 6. Launch Interactive Shell or Scriptable CLI
openqpep --version
openqpep
```

## Specifications & Documentation

- [WIRE_FORMAT_V5_SPEC.md](WIRE_FORMAT_V5_SPEC.md) — Official Binary Wire Format v5 / Compact TLV v5.1 / Stream v5 Specification
- [specs/OPENQPEP_v1.2.2_OFFICIAL_RELEASE_SPEC.md](specs/OPENQPEP_v1.2.2_OFFICIAL_RELEASE_SPEC.md) — Official Release `v1.2.2` Frozen Wire v5 & C99 SDK ABI Specification
- [calyx_qpep/native/csrc/include/openqpep.h](calyx_qpep/native/csrc/include/openqpep.h) — Public C99/C++ SDK ABI Header
- [CHANGELOG.md](CHANGELOG.md) — Official Release Changelog
- [docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Mathematical & Cryptographic Specification
- [docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — OpenQPEP vs. OpenPGP Security Comparison
- [docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — `.qpkrf` Key Ring & Wire Format Guide
- [docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — CLI, Client Ecosystem & Key Transparency Guide
