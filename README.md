# OpenQPEP by Calyx Labs Inc. — Official Release `v1.1.4` (`OpenQPEP/1.1.4`)

**Protocol Version:** `OpenQPEP/1.1.4` (`Official Release 1.1.4`, PEP 440 `1.1.4`, upgraded from **Official Release `1.1.3`**)  
**Creator & Lead Architect:** Tristen Martinez (Calyx Labs Inc., Cleveland, Ohio)  
**Repository:** https://github.com/CalyxLabsInc/OpenQPEP  
**Public Key Directory & QPEP-KT:** https://qpepkeys.calyxlabsinc.org  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

OpenQPEP is a modern, quantum-proof encryption, authentication, and messaging protocol engineered to replace legacy OpenPGP (RFC 4880 / RFC 9580) as a worldwide standard—with provable multi-assumption post-quantum security, constant-time native C99/Rust/WASM/Go performance, and 100% deterministic Known Answer Test (KAT) verification.

## Official Release `v1.1.4` Highlights

- **100% Official `v1.0.x`–`v1.1.x` Interoperability (`1.0.0`–`1.1.3` ↔ `1.1.4`):** Preserves complete Wire Format v5 (`\x89QPE\x05\x00`), Compact TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), and `kdf_version: 4` compatibility across all Official Public Stable Releases while continuing to hard-reject all retired pre-release formats (`-rc`, `-pc`, `-beta`, Wire v1–v4, `kdf_version < 4`) with `QPEPLegacyProtocolError`.
- **FIPS 204-Style Hedged Signatures & Universal Verify-Before-Emit Fault-Guard (All 10 Suites):** Upgraded `QVSEngine`, `QHS-512`, `QMQ-512` (UOV), and `CIF-SQI-512` (CSIDH-512 SeaSign) to hedged deterministic signing (`hedged=True` default, `hedged=False` pure-deterministic option) resistant to both weak/stuck RNGs and differential fault analysis, and expanded mandatory Verify-Before-Emit Fault-Guard (`QPEPFaultGuardError`) across **all 10 canonical suites** (`QVS`, `Ed448`, `QHS-512`, `QMQ-512`, `CIF-SQI-512`, `CSP-Omega`).
- **Constant-Time CMT-4 `CC-512` AEAD & Nonce-Misuse-Resistant `CC-512-SIV` Mode:** Strict `QPEPWireFormatError` key/nonce/length validation and `SecretBuffer` scrubbing across `CC-512`, plus deterministic & hedged Synthetic-IV `CC-512-SIV` (`cc512_siv_encrypt`, `cc512_siv_decrypt`, `cc512_siv_wrap_key`, `cc512_siv_unwrap_key`, `CC512SIV`) for nonce-misuse-resistant key wrapping and offline vaults while keeping Wire v5 `CC-512` 100% bit-exact.
- **OS Memory Locking & Guard-Page Secret Arenas (`mlock` / `MADV_DONTDUMP` / `PR_SET_DUMPABLE`):** Reference-counted `mlock()`/`munlock()` inside `SecretBuffer`, dedicated `PROT_NONE` guard-paged & `MADV_DONTDUMP`-excluded `LockedMemoryBuffer` arenas, C99 constant-time `openqpep_explicit_bzero` + `openqpep_is_zeroed`, opt-in process core-dump hardening (`disable_core_dumps`, `harden_process_memory`), and deterministic scrubbing across KDF/KEM/DSA/AEAD/protocol secret paths.
- **Shared Server Security Adapter (`calyx_qpep.compat_server`):** Canonical `SlidingWindowRateLimiter`, strict Wire v5 verification, pre-release token guards, and directory `.qpkrf` validator shared across ecosystem backends.
- **Mandatory `kdf_version: 4` (`RFC 9106 QPKD-Argon2id + qSponge-512`):** Hardcoded 64-byte structural passphrase witness, hardware auto-tuner, and optional `FIDO2-PRF` hardware passkey secret mixing.
- **10 Cryptographically Genuine Post-Quantum Suites:**
  - **5 Structured Module-LWE + HGC-448 Suites:** `QLX-768`, `QLX-1024`, `QLX-2048`, `QLX-4096` (default), `QLX-16384` paired with `QVS-65`..`QVS-1024` (with Verify-Before-Emit Fault-Guard).
  - **5 Genuine Beyond-LWE Suites:** **CSIDH-512** Supersingular Isogeny (`CIF-SQI-512`), **LRPC / ROLLO-I** Rank-Metric Syndrome Decoding (`CRT-RSD512`) + **UOV** Multivariate Quadratic (`QMQ-512`), **Classic McEliece / Niederreiter Binary Goppa Patterson** (`CGM-8192`), **Zero-Ring Plain-LWE + Goppa** (`CULC-2048`), and **5-Family Citadel** (`CSP-Omega`).
- **Complete Hardened Sub-Protocol Stack:** `QPEP-Ratchet`, `QPEP-MLS` (256-member TreeKEM), `QPEP-AKE`, `QPEP-KT` (Ed448 publicly verifiable STHs + RFC 9162 Merkle Consistency Proofs), `QVS-Ring`, `DeniableVault`, `ThresholdKEM`, `Sphinx-PQ`, `LT-QR`, `BlindSearchVault`, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.

## All 10 Canonical OpenQPEP Post-Quantum Suites (`v1.1.4`)

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
# 1. Build Native C99 / SIMD Accelerator (zero warnings with -Werror)
make -C calyx_qpep/native/csrc clean all

# 2. Install OpenQPEP Official Release 1.1.4
pip install -e .

# 3. Verify All 10 Deterministic Golden KAT Suites (Native C99 & Pure-Python)
python3 -m calyx_qpep.cli verify-vectors
OPENQPEP_DISABLE_NATIVE=1 python3 -m calyx_qpep.cli verify-vectors

# 4. Run Full Cryptographic, Adversarial, Fuzzing & 5-Language Interop Suite
python3 -m unittest discover -s tests -v

# 5. Launch Interactive Shell or Scriptable CLI
openqpep --version
openqpep
```

## Specifications & Documentation

- [WIRE_FORMAT_V5_SPEC.md](WIRE_FORMAT_V5_SPEC.md) — Official Binary Wire Format v5 / Compact TLV v5.1 / Stream v5 Specification
- [specs/OPENQPEP_v1.1.4_OFFICIAL_RELEASE_SPEC.md](specs/OPENQPEP_v1.1.4_OFFICIAL_RELEASE_SPEC.md) — Official Release `v1.1.4` Frozen Wire v5 Specification
- [CHANGELOG.md](CHANGELOG.md) — Official Release Changelog
- [docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Mathematical & Cryptographic Specification
- [docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — OpenQPEP vs. OpenPGP Security Comparison
- [docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — `.qpkrf` Key Ring & Wire Format Guide
- [docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — CLI, Client Ecosystem & Key Transparency Guide
