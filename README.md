# OpenQPEP by Calyx Labs Inc. — Official Release `v1.1.9` (`OpenQPEP/1.1.9`)

**Protocol Version:** `OpenQPEP/1.1.9` (`Official Release 1.1.9`, PEP 440 `1.1.9`, **Phase 1 Hardening Complete**, upgraded from **Official Release `1.1.8`**)  
**Creator & Lead Architect:** Tristen Martinez (Calyx Labs Inc., Cleveland, Ohio)  
**Repository:** https://github.com/CalyxLabsInc/OpenQPEP  
**Public Key Directory & QPEP-KT:** https://qpepkeys.calyxlabsinc.org  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

OpenQPEP is a modern, quantum-proof encryption, authentication, and messaging protocol engineered to replace legacy OpenPGP (RFC 4880 / RFC 9580) as a worldwide standard—with provable multi-assumption post-quantum security, constant-time native C99/Rust/WASM/Go performance, and 100% deterministic Known Answer Test (KAT) verification.

## Official Release `v1.1.9` Highlights (Phase 1 Hardening Consolidation Gate)

- **100% Official `v1.0.x`–`v1.1.x` Interoperability (`1.0.0`–`1.1.8` ↔ `1.1.9`):** Preserves complete Wire Format v5 (`\x89QPE\x05\x00`), Compact TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), and `kdf_version: 4` compatibility across all Official Public Stable Releases while continuing to hard-reject all retired pre-release formats (`-rc`, `-pc`, `-beta`, Wire v1–v4, `kdf_version < 4`) with `QPEPLegacyProtocolError`.
- **Phase 1 Security Regression Gate & Expanded 9-Threat Adversarial Simulator (`calyx_qpep/audit/attack_sim.py`):** Expanded active attack simulation from 4 to **9 adversarial threat families** covering FO IND-CCA2 malleability, universal multi-suite fault injection (`QVS`, `Ed448`, `QHS-512`, `QMQ-512`, `CIF-SQI-512`), stream truncation/reorder/reserved-flag/non-canonical-`is_final` attacks, suite & legacy-protocol downgrade, RFC 8032 Ed448 `E[4]` small-order `S=0` / `S >= L` & RFC 7748 X448 low-order points, RFC 4648 §3.5 non-canonical Base64 & armor/TLV DoS, duplicate JSON keys / 2,000-level JSON depth bombs / Unicode homograph & Bidi UIDs, and Ratchet/MLS/Sphinx replay + CMT-4 + KDF OOM-bomb + 1,000:1 zip-bomb defenses—verified end-to-end across BOTH Native C99 and Pure-Python paths and wired into `openqpep audit` and CI.
- **Parser Resource Ceilings, Depth Limits & Zip-Bomb / Algorithmic-Complexity Defenses (`v1.1.8`):** Strict RFC 4648 §3.5 canonical Base64 (`strict_b64decode`), iterative O(N) JSON nesting-depth (`MAX_JSON_DEPTH = 32`) & node-count (`MAX_JSON_NODES = 250,000`) ceilings (`strict_json_loads`), dual `128 MiB` + `200:1` zip-bomb defense (`safe_zlib_decompress`), armor line/blank-line/CRC ceilings, canonical ascending TLV tag ordering in Compact Wire v5.1, streaming chunk/byte/flag limits, and packet/multi-recipient slot bounds.
- **Hardened `QPKD-Argon2id` Pure-Python & C-Backend Parity + Auto-Calibration (`v1.1.7`):** 100% bit-exact RFC 9106 Argon2id parity across `argon2-cffi`, OpenSSL 3.2+ (`cryptography`), and Pure-Python (verified against RFC 9106 Section 5.3 and multi-lane/multi-pass matrices), zero silent pure-Python downgrades, container/cgroup-aware memory-ceiling bounds, calibrated per-device KDF benchmark reporting, and hardened passphrase policy.
- **RFC 7748 / RFC 8032 `HGC-448` Low-Order Hardening & `.qpkrf` Anti-Substitution (`v1.1.6`):** Full X448 contributory & canonical `u < p` validation, strict Ed448 verification rejecting all 4 small-order torsion points `E[4]` and non-canonical `S >= L` malleability, plus Unicode homograph / Bidi / zero-width UID defenses and armor-header anti-substitution validation.
- **Constant-Time Division-Free Lattice Arithmetic (`v1.1.5` — KyberSlash Immunity):** Eliminated all variable-time `//` and `%` integer divisions from `poly_ring.py`, `ntt_3329.py`, `ntt_8380417.py`, `consttime.py`, C99 `ntt_3329.c`, and Rust `ntt.rs`—aligned bit-for-bit across Python, C99, and Rust and permanently enforced by AST verification.
- **FIPS 204-Style Hedged Signatures & Universal Verify-Before-Emit Fault-Guard (`v1.1.4`):** Default hedged deterministic signing (`hedged=True`) resistant to weak/stuck RNGs and differential fault analysis, plus mandatory Verify-Before-Emit Fault-Guard (`QPEPFaultGuardError`) across **all 10 canonical suites**.
- **CMT-4 `CC-512` AEAD, `CC-512-SIV`, OS `mlock`/`MADV_DONTDUMP` & Zero Broad-`except` (`v1.1.1`–`v1.1.3`):** Reference-counted `SecretBuffer` `mlock()`/`munlock()`, `PROT_NONE` guard-paged `LockedMemoryBuffer`, C99 `openqpep_explicit_bzero`/`openqpep_is_zeroed`, nonce-misuse-resistant `CC-512-SIV` encrypt/decrypt/key-wrap, constant-time comparisons, and permanent AST zero-broad-`except` verification.
- **10 Cryptographically Genuine Post-Quantum Suites:**
  - **5 Structured Module-LWE + HGC-448 Suites:** `QLX-768`, `QLX-1024`, `QLX-2048`, `QLX-4096` (default), `QLX-16384` paired with `QVS-65`..`QVS-1024`.
  - **5 Genuine Beyond-LWE Suites:** **CSIDH-512** Supersingular Isogeny (`CIF-SQI-512`), **LRPC / ROLLO-I** Rank-Metric Syndrome Decoding (`CRT-RSD512`) + **UOV** Multivariate Quadratic (`QMQ-512`), **Classic McEliece / Niederreiter Binary Goppa Patterson** (`CGM-8192`), **Zero-Ring Plain-LWE + Goppa** (`CULC-2048`), and **5-Family Citadel** (`CSP-Omega`).
- **Complete Hardened Sub-Protocol Stack:** `QPEP-Ratchet`, `QPEP-MLS` (256-member TreeKEM), `QPEP-AKE`, `QPEP-KT` (Ed448 publicly verifiable STHs + RFC 9162 Merkle Consistency Proofs), `QVS-Ring`, `DeniableVault`, `ThresholdKEM`, `Sphinx-PQ`, `LT-QR`, `BlindSearchVault`, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.

## All 10 Canonical OpenQPEP Post-Quantum Suites (`v1.1.9`)

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

# 2. Install OpenQPEP Official Release 1.1.9
pip install -e .

# 3. Verify All 10 Deterministic Golden KAT Suites (Native C99 & Pure-Python)
python3 -m calyx_qpep.cli verify-vectors
OPENQPEP_DISABLE_NATIVE=1 python3 -m calyx_qpep.cli verify-vectors

# 4. Run Phase 1 Adversarial Attack Simulator & 5-Language Interop Audit
python3 -m calyx_qpep.cli audit

# 5. Run Full Cryptographic, Adversarial, Fuzzing & Phase 1 Consolidation Suite
python3 -m unittest discover -s tests -v

# 6. Launch Interactive Shell or Scriptable CLI
openqpep --version
openqpep
```

## Specifications & Documentation

- [WIRE_FORMAT_V5_SPEC.md](WIRE_FORMAT_V5_SPEC.md) — Official Binary Wire Format v5 / Compact TLV v5.1 / Stream v5 Specification
- [specs/OPENQPEP_v1.1.9_OFFICIAL_RELEASE_SPEC.md](specs/OPENQPEP_v1.1.9_OFFICIAL_RELEASE_SPEC.md) — Official Release `v1.1.9` Frozen Wire v5 & Phase 1 Complete Specification
- [CHANGELOG.md](CHANGELOG.md) — Official Release Changelog
- [docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Mathematical & Cryptographic Specification
- [docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — OpenQPEP vs. OpenPGP Security Comparison
- [docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — `.qpkrf` Key Ring & Wire Format Guide
- [docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — CLI, Client Ecosystem & Key Transparency Guide
