# OpenQPEP by Calyx Labs Inc. — Official Release `v1.2.4` (`OpenQPEP/1.2.4`)

**Protocol Version:** `OpenQPEP/1.2.4` (`Official Release 1.2.4`, PEP 440 `1.2.4`, **Phase 2 Native C99 SDK — Binary Goppa GF($2^{10}$) & Syndrome Accelerator**, upgraded from **Official Release `1.2.3`**)  
**Creator & Lead Architect:** Tristen Martinez (Calyx Labs Inc., Cleveland, Ohio)  
**Repository:** https://github.com/CalyxLabsInc/OpenQPEP  
**Public Key Directory & QPEP-KT:** https://qpepkeys.calyxlabsinc.org  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

OpenQPEP is a modern, quantum-proof encryption, authentication, and messaging protocol engineered to replace legacy OpenPGP (RFC 4880 / RFC 9580) as a worldwide standard—with provable multi-assumption post-quantum security, constant-time native C99/Rust/WASM/Go performance, and 100% deterministic Known Answer Test (KAT) verification.

## Official Release `v1.2.4` Highlights (Native C99 Binary Goppa $\mathrm{GF}(2^{10})$ & Syndrome Accelerator — `CGM-8192`)

- **100% Official `v1.0.x`–`v1.2.x` Interoperability (`1.0.0`–`1.2.3` ↔ `1.2.4`):** Preserves complete Wire Format v5 (`\x89QPE\x05\x00`), Compact TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), and `kdf_version: 4` compatibility across all Official Public Stable Releases while continuing to hard-reject all retired pre-release formats (`-rc`, `-pc`, `-beta`, Wire v1–v4, `kdf_version < 4`) with `QPEPLegacyProtocolError`.
- **Native C99 Binary Goppa $\mathrm{GF}(2^{10})$ & Syndrome Accelerator (`calyx_qpep/native/csrc/goppa_c.c`, `goppa_8192.py`):**
  - Implemented 100% branchless, table-free, cache-timing-immune $\mathrm{GF}(2^{10})$ field arithmetic mod $x^{10} + x^3 + 1$ (`0x409`): carry-less multiplication (`openqpep_gf2m10_mul`), bit-interleaved squaring (`openqpep_gf2m10_sq`), optimal addition-chain Fermat inversion (`openqpep_gf2m10_inv`), and Frobenius square root (`openqpep_gf2m10_sqrt`), verified across all $1024 \times 1024 = 1,048,576$ field pairs.
  - Added constant-time Horner evaluation (`openqpep_goppa_poly_eval`, `openqpep_goppa_poly_eval_batch`), Rabin irreducibility testing (`openqpep_goppa_is_irreducible`), word-aligned 64-bit parity-check RREF (`openqpep_goppa_build_systematic_t`), branchless 64-bit word-packed syndrome multiplication (`openqpep_goppa_syndrome`), constant-iteration Chien search (`openqpep_goppa_chien_search`), and full Patterson algebraic decoding (`openqpep_goppa_patterson_decode`) with `openqpep_explicit_bzero` secret scrubbing (`OPENQPEP_ABI_VERSION = 0x00010204U`, `75` total exported `OPENQPEP_API` symbols, zero leaked internal helpers).
  - Accelerates `CGM-8192`, `CULC-2048`, and `CSP-Omega` keygen/encaps/decaps transparently while preserving 100% bit-exact Pure-Python fallback under `OPENQPEP_DISABLE_NATIVE=1`.
- **Native C99 Plain-LWE, Polynomial Ring, Keccak-f[1600] & Versioned SDK ABI (`v1.2.0`–`v1.2.3`):**
  - Row-streamed O(1)-RAM C99 Plain-LWE accelerator (`plain_lwe_c.c`), KyberSlash-free polynomial ring & streaming matrix-vector engine (`poly_ring_c.c`, fused `ntt_3329.c`, 100% division-free Solinas-Barrett `ntt_8380417.c`), standalone 24-round constant-time `openqpep_keccak_f1600` sponge (`keccak_f1600.c`), canonical public C99/C++ header `include/openqpep.h`, and strict `-std=c99 -Wall -Wextra -Werror -Wpedantic -fvisibility=hidden` Makefile & CMake builds (`libopenqpep.so` + `libopenqpep.a` + `openqpep.pc`).
- **Phase 1 Complete Hardening Baseline (`v1.1.1`–`v1.1.9`):**
  - 9-threat active adversarial attack simulator (`openqpep audit`: `83/83` attacks defended across FO malleability, universal multi-suite fault injection, stream truncation/reorder/flags, suite/legacy downgrade, Ed448 `E[4]` small-order & X448 low-order, RFC 4648 §3.5 canonical Base64 / armor / TLV DoS, duplicate JSON keys / 2,000-level JSON depth bombs / Unicode homograph & Bidi UIDs, and Ratchet/MLS/Sphinx replay + CMT-4 + KDF OOM-bomb + 1,000:1 zip-bomb defenses).
  - Bit-exact RFC 9106 `QPKD-Argon2id` across `argon2-cffi`, OpenSSL 3.2+, and Pure-Python with cgroup-aware memory ceilings and calibrated per-device benchmarking.
  - KyberSlash-immune division-free branchless lattice arithmetic across Python, C99, and Rust (AST-guarded), FIPS 204-style hedged signatures & Verify-Before-Emit Fault-Guard across all 10 suites, CMT-4 `CC-512` + `CC-512-SIV`, OS `mlock`/`MADV_DONTDUMP` guard-page secret arenas, and permanent AST zero-broad-`except` enforcement.
- **10 Cryptographically Genuine Post-Quantum Suites:**
  - **5 Structured Module-LWE + HGC-448 Suites:** `QLX-768`, `QLX-1024`, `QLX-2048`, `QLX-4096` (default), `QLX-16384` paired with `QVS-65`..`QVS-1024`.
  - **5 Genuine Beyond-LWE Suites:** **CSIDH-512** Supersingular Isogeny (`CIF-SQI-512`), **LRPC / ROLLO-I** Rank-Metric Syndrome Decoding (`CRT-RSD512`) + **UOV** Multivariate Quadratic (`QMQ-512`), **Classic McEliece / Niederreiter Binary Goppa Patterson** (`CGM-8192`), **Zero-Ring Plain-LWE + Goppa** (`CULC-2048`), and **5-Family Citadel** (`CSP-Omega`).
- **Complete Hardened Sub-Protocol Stack:** `QPEP-Ratchet`, `QPEP-MLS` (256-member TreeKEM), `QPEP-AKE`, `QPEP-KT`, `QVS-Ring`, `DeniableVault`, `ThresholdKEM`, `Sphinx-PQ`, `LT-QR`, `BlindSearchVault`, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.

## All 10 Canonical OpenQPEP Post-Quantum Suites (`v1.2.4`)

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

# 2. Install OpenQPEP Official Release 1.2.4
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
- [specs/OPENQPEP_v1.2.4_OFFICIAL_RELEASE_SPEC.md](specs/OPENQPEP_v1.2.4_OFFICIAL_RELEASE_SPEC.md) — Official Release `v1.2.4` Frozen Wire v5 & C99 SDK ABI Specification
- [calyx_qpep/native/csrc/include/openqpep.h](calyx_qpep/native/csrc/include/openqpep.h) — Public C99/C++ SDK ABI Header
- [CHANGELOG.md](CHANGELOG.md) — Official Release Changelog
- [docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Mathematical & Cryptographic Specification
- [docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — OpenQPEP vs. OpenPGP Security Comparison
- [docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — `.qpkrf` Key Ring & Wire Format Guide
- [docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — CLI, Client Ecosystem & Key Transparency Guide
