# OpenQPEP Official Release 1.2.0 (`v1.2.0`) — Frozen Global Specification (Phase 2 Native C99 SDK Kickoff)

**Release Channel:** `RELEASE` (Official Public Release — Phase 2 Native C99 SDK)  
**Version:** `1.2.0` (`OpenQPEP/1.2.0`, PEP 440 `1.2.0`)  
**C99 ABI Version:** `OPENQPEP_ABI_VERSION = 0x00010200U` (`libopenqpep.so.1` / `libopenqpep.a` / `openqpep.pc`)  
**Publisher:** Calyx Labs Inc. (`support@calyxlabsinc.org`)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

## Official Release 1.2.0 Permanent Public Baseline

- **100% Official `v1.0.x`–`v1.2.x` Interoperability & Zero Pre-Release Backwards Compatibility:** Official Release `1.2.0` maintains full Wire Format v5/v5.1, Stream v5, signature verification, and `kdf_version: 4` key-ring interoperability with all Official Stable Public Releases (`v1.0.0`–`v1.1.9`). All pre-release Release Candidate (`-rc`: `\x89QPE\x04\x00`, `\x89QPE\x04\x01`, `kdf_version: 3`), Production Candidate (`-pc`: `\x89QPE\x03\x00`, `\x89QPE\x03\x01`, `kdf_version: 2`), Beta (`-beta`: `\x89QPE\x01\x01`, `\x01\x09`, `\x02\x00`, `kdf_version: 1`), and legacy stream (`\x89QPS\x02\x07`) artifacts are **strictly rejected** with `QPEPLegacyProtocolError`.
- **Public C99/C++ ABI Header (`include/openqpep.h`) & Cross-Platform SDK Build System (`v1.2.0`):** Defines stable versioned `OPENQPEP_ABI_VERSION`, runtime introspection (`openqpep_abi_version()`, `openqpep_version_string()`, `openqpep_native_abi_info()`), cross-platform `OPENQPEP_API` / `OPENQPEP_LOCAL` symbol visibility macros enforced via `-fvisibility=hidden`, strict ISO C99 `-std=c99 -Wall -Wextra -Werror -Wpedantic -Wstrict-prototypes -Wmissing-prototypes` builds across both Makefile and CMake, shared (`libopenqpep.so`/`.dylib`/`.dll`) + static (`libopenqpep.a`) artifacts, `pkg-config` (`openqpep.pc.in`), and `extern "C"` C++11+ compatibility.
- **Complete Phase 1 Hardening Baseline (`v1.1.1`–`v1.1.9`):**
  - 9-threat active adversarial attack simulator (`openqpep audit`, `83/83` defended across FO malleability, universal multi-suite fault injection, stream truncation/reorder/flags, suite/legacy downgrade, Ed448 `E[4]` small-order & X448 low-order, RFC 4648 §3.5 canonical Base64 / armor / TLV DoS, duplicate JSON keys / 2,000-level JSON depth bombs / Unicode homograph & Bidi UIDs, and Ratchet/MLS/Sphinx replay + CMT-4 + KDF OOM-bomb + 1,000:1 zip-bomb defenses) verified under BOTH Native C99 and Pure-Python paths.
  - Strict parser resource ceilings (`strict_b64decode`, iterative O(N) `strict_json_loads`, dual `128 MiB` + `200:1` `safe_zlib_decompress`, armor line/blank-line/CRC ceilings, canonical ascending TLV v5.1 ordering, streaming & multi-recipient bounds).
  - Bit-exact RFC 9106 `QPKD-Argon2id` across `argon2-cffi`, OpenSSL 3.2+ (`cryptography`), and Pure-Python with cgroup-aware memory ceilings, calibrated per-device benchmarking, and hardened passphrase policy.
  - KyberSlash-immune division-free branchless lattice arithmetic (AST-guarded across Python/C99/Rust), FIPS 204-style hedged signatures & Verify-Before-Emit Fault-Guard across all 10 suites, CMT-4 `CC-512` + `CC-512-SIV`, OS `mlock`/`MADV_DONTDUMP` guard-page arenas, and permanent AST zero-broad-`except` enforcement.
- **10 Cryptographically Genuine Post-Quantum Suites:**
  - **5 Structured Module-LWE + HGC-448 Suites:** `QLX-768`, `QLX-1024`, `QLX-2048`, `QLX-4096` (default), `QLX-16384` paired with `QVS-65`..`QVS-1024`.
  - **5 Genuine Beyond-LWE Suites:** `CIF-SQI-512` (CSIDH-512 + SeaSign + `QHS-512`), `CRT-RSD512` (LRPC Rank-Metric + UOV `QMQ-512`), `CGM-8192` (Binary Goppa Patterson + `QHS-512`), `CULC-2048` (Zero-Ring Plain-LWE + Binary Goppa Patterson), and `CSP-Omega` (5-Family Beyond-LWE Citadel).
- **Hardened Stateful & Privacy Protocols:** `QPEP-Ratchet`, `QPEP-MLS`, `QPEP-AKE`, `QPEP-KT`, `QVS-Ring`, `DeniableVault`, `ThresholdKEM`, `Sphinx-PQ`, `LatticeZKProof`, `BlindSearchVault`, `LT-QR`, `TimeLockCapsule`, and `EncryptedLWWMapCRDT`.
- **5-Language Runtime Conformance:** Python Reference (`1.2.0`), C99/AVX2/NEON SDK (`libopenqpep` `1.2.0`, `include/openqpep.h`, `-Wall -Wextra -Werror -Wpedantic`), Rust (`openqpep-core` `1.2.0`, `#![forbid(unsafe_code)]`), WASM SIMD128 (`@calyxlabs/openqpep-wasm` `1.2.0` + `qpep_worker.js`), and Go (`go/openqpep` `1.2.0`).
