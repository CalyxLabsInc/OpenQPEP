# OpenQPEP Core Protocol Changelog — Official Release `v1.2.1`

## Official Release `v1.2.1` (2026-11-24) — Native C99 Keccak-f[1600] (`qSponge-512` / `SHA3-512` / `SHAKE-256`)

- **Zero-Dependency Native C99 Keccak-f[1600] Sponge Engine (`calyx_qpep/native/csrc/keccak_f1600.c`):**
  - Implemented a standalone, constant-time, endian-independent, register-unrolled (2 rounds per iteration, 24 full rounds) ISO C99 `openqpep_keccak_f1600` permutation with zero external dependencies and strict `-std=c99 -Wall -Wextra -Werror -Wpedantic -Wstrict-prototypes -Wmissing-prototypes` compilation.
  - Added incremental streaming sponge APIs (`openqpep_keccak_init`, `openqpep_sha3_512_init`, `openqpep_sha3_256_init`, `openqpep_shake256_init`, `openqpep_shake128_init`, `openqpep_keccak_absorb`, `openqpep_keccak_finalize`, `openqpep_keccak_squeeze`, and `openqpep_keccak_wipe` backed by `openqpep_explicit_bzero`) alongside one-shot FIPS 202 functions (`openqpep_qsponge_512`, `openqpep_sha3_256`, `openqpep_qsponge_var`, `openqpep_shake128`).
- **Public ABI & Transparent Python Dispatch (`include/openqpep.h`, `loader.py`, `qsponge.py`, `Makefile`, `CMakeLists.txt`):**
  - Bumped `OPENQPEP_ABI_VERSION` to `0x00010201U` (`1.2.1`), defined `openqpep_keccak_ctx_t` and FIPS 202 rate/domain constants in `include/openqpep.h`, and exported all 14 Keccak APIs with `OPENQPEP_API` across both Makefile and CMake builds.
  - Wired `native_qsponge_512`, `native_sha3_256`, `native_qsponge_var`, `native_shake128`, and the `NativeKeccakSponge` context manager into `calyx_qpep/native/loader.py` and `calyx_qpep/native/__init__.py`.
  - Upgraded `calyx_qpep/primitives/qsponge.py` (`qsponge_512` / `qsponge_var`) to transparently dispatch to native C99 Keccak-f[1600] when `libopenqpep` is active while retaining bit-exact `hashlib` Pure-Python fallback under `OPENQPEP_DISABLE_NATIVE=1`.
- **Verification:** Added 6-test FIPS 202 & C99 parity suite `tests/test_v121_c99_keccak_f1600.py` verifying official NIST FIPS 202 vectors, exhaustive rate-boundary absorb/squeeze parity against `hashlib`, incremental `NativeKeccakSponge` streaming & explicit wipe, Native↔Pure-Python `qsponge` toggle parity, external `-Wpedantic` C99 static & shared linking, 10/10 Native C99 + 10/10 Pure-Python Golden KATs, and 175/175 unit & AST tests.

---

## Official Release `v1.2.0` (2026-11-24) — Public C99 ABI Header (`include/openqpep.h`) & Build System Overhaul (Phase 2 Kickoff)

- **Public Versioned C99/C++ ABI Header (`calyx_qpep/native/csrc/include/openqpep.h`):**
  - Created canonical public header `openqpep.h` defining semantic & monotonic ABI version macros (`OPENQPEP_VERSION_MAJOR/MINOR/PATCH`, `OPENQPEP_VERSION_STRING`, `OPENQPEP_ABI_VERSION = 0x00010200U`), cross-platform `OPENQPEP_API` / `OPENQPEP_LOCAL` symbol visibility macros (DLL import/export on Windows, GCC/Clang default/hidden visibility on POSIX), `extern "C"` C++ guards, cryptographic/wire constants, and complete declarations for all 23 exported C99 symbols.
  - Added runtime ABI introspection (`openqpep_abi_version()`, `openqpep_version_string()`) in `cbd.c`, annotated all public C99 functions across `ntt_3329.c`, `ntt_8380417.c`, `cbd.c`, `pentad_accel.c`, and `openqpep_jni.c` with `OPENQPEP_API` and `#include "openqpep.h"`, and wired `native_abi_version()` / `native_version_string()` into `calyx_qpep/native/loader.py`, `calyx_qpep/native/__init__.py`, and `calyx_qpep/__init__.py`.
- **Overhauled Cross-Platform Build System (`Makefile`, `CMakeLists.txt`, `openqpep.pc.in`):**
  - Enforced strict ISO C99 compiler flags (`-std=c99 -Wall -Wextra -Werror -Wpedantic -Wstrict-prototypes -Wmissing-prototypes -fvisibility=hidden`, plus MSVC `/W4 /WX`) across both Makefile and CMake.
  - Added static library (`libopenqpep.a`), shared library (`libopenqpep.so` + `libopenqpep.so.1` SONAME / `.dylib` / `.dll`), `pkg-config` manifest generation (`openqpep.pc.in` -> `openqpep.pc`), `install` targets, and Android NDK JNI target selection (`OPENQPEP_BUILD_JNI` / `ANDROID`).
  - Updated `.gitignore` to ignore `*.a`, `*.so.*`, and generated `calyx_qpep/native/openqpep.pc`.
- **Verification:** Added 7-test C99 ABI & build verification suite `tests/test_v120_c99_abi_build.py` verifying dynamic symbol visibility (`nm -D`), external `-Wpedantic` C99 static & shared linking, C++17 `extern "C"` linkage, out-of-source CMake build/install, `openqpep.pc`, 10/10 Native C99 + 10/10 Pure-Python Golden KATs, and 169/169 unit & AST tests.

---

## Official Release `v1.1.9` (2026-11-24) — Phase 1 Security Regression Gate & `v1.1.x` Consolidation Audit

- **Expanded 9-Threat Active Cryptographic Attack Simulator (`calyx_qpep/audit/attack_sim.py`, `calyx_qpep/audit/__init__.py`):**
  - Expanded `run_all_attack_simulations()` from 4 to **9 adversarial simulations** covering the entire Phase 1 hardening surface:
    1. `FO_CCA2_Malleability` (QLX Fujisaki-Okamoto ciphertext malleability)
    2. `QVS_Fault_Injection` (QVS Rowhammer/glitch Verify-Before-Emit Fault-Guard)
    3. `Stream_Truncation_Reorder_Injection` (stream truncation, reorder, trailing bytes, reserved flags & non-canonical `is_final`)
    4. `Suite_And_Protocol_Downgrade` (`.qpkrf` suite downgrade + legacy `-rc`/`-pc`/`-beta` Wire v1–v4 & `kdf_version < 4` downgrade)
    5. `Ed448_SmallOrder_And_X448_LowOrder` (all 4 small-order `E[4]` Ed448 `S=0` torsion forgeries, `S >= L` malleability & RFC 7748 X448 `{0, 1, p-1}` / `u >= p`)
    6. `NonCanonical_Base64_Armor_And_TLV_DoS` (RFC 4648 §3.5 non-zero trailing-bit Base64, armor line/blank-line/duplicate-header/CRC DoS & TLV tag reordering)
    7. `JSON_DuplicateKey_DepthBomb_And_Homograph_UID` (duplicate JSON keys, `NaN`/`Infinity`, 2,000-level JSON depth bombs, node bombs & mixed-script/Bidi UID spoofing)
    8. `Replay_CMT4_KDFBomb_And_ZipBomb` (`QPEP-Ratchet`/`QPEP-MLS`/`Sphinx-PQ` replay, CMT-4 `CC-512`/`CC-512-SIV` cross-key forgery, 64 GiB KDF OOM-bombs & 1,000:1 zlib zip-bombs)
    9. `Universal_MultiSuite_Fault_Injection` (Verify-Before-Emit Fault-Guard across `Ed448`, `QHS-512`, `QMQ-512`, and `CIF-SQI-512`)
- **Phase 1 Consolidation Gate & Dual Native/Pure-Python CI (`.github/workflows/ci.yml`, `tests/test_v119_phase1_audit.py`):**
  - Added 8-test consolidation suite `tests/test_v119_phase1_audit.py` cross-verifying all Phase 1 (`v1.1.1`–`v1.1.9`) invariants under BOTH Native C99 (`libopenqpep`) and Pure-Python (`OPENQPEP_DISABLE_NATIVE=1`) execution paths, including zero leaked `mlock` pages, bit-exact Native↔Pure-Python lattice parity, 5-language interop matrix, wire fuzzer, and CLI `openqpep audit` end-to-end exit status.
  - Upgraded `.github/workflows/ci.yml` to run `python3 -m calyx_qpep.cli audit` and `OPENQPEP_DISABLE_NATIVE=1 python3 -m unittest tests/test_v119_phase1_audit.py -v` alongside 10/10 Native + 10/10 Pure-Python Golden KATs and the full 162-test suite—completing Phase 1 (`v1.1.1` → `v1.1.9`).

---

## Official Release `v1.1.8` (2026-11-24) — Parser Resource Ceilings, Depth Limits & Zip-Bomb / Algorithmic-Complexity Defenses

- **Strict Canonical Base64, Iterative JSON Depth/Complexity Limits & Zip-Bomb Defense (`calyx_qpep/wire/armor.py`, `protocol.py`, `beyond_lwe_bridge.py`, `wire/multi_recipient.py`):**
  - Added RFC 4648 Section 3.5 canonical Base64 decoder `strict_b64decode` enforcing standard `[A-Za-z0-9+/]` alphabet, multiple-of-4 length, zero internal whitespace, and zero non-canonical trailing padding bits (closing Base64 malleability left open by Python's `base64.b64decode(..., validate=True)`) across armor bodies, 8-char `={crc}` checksums, `protocol.py`, `multi_recipient.py`, and `beyond_lwe_bridge.py`.
  - Added iterative O(N) stack-free JSON pre-scanner inside `strict_json_loads` enforcing `MAX_JSON_DEPTH = 32`, `MAX_JSON_NODES = 250,000`, `MAX_JSON_BYTES = 64 MiB`, duplicate-key rejection, and `NaN`/`Infinity` rejection before invoking `json.loads` (preventing `RecursionError` crashes and algorithmic-complexity DoS), and eliminated remaining raw `json.loads` calls in `protocol.py`, `multi_recipient.py`, and `beyond_lwe_bridge.py`.
  - Upgraded `safe_zlib_decompress` with dual zip-bomb protection: hard `MAX_DECOMPRESSED_BYTES` (`128 MiB`) ceiling PLUS upfront `MAX_DECOMPRESSION_RATIO = 200` ratio cap above `1 MiB` (terminating high-ratio zip bombs early before large allocations) and strict rejection of trailing smuggled bytes (`dobj.unused_data`).
- **ASCII Armor, Wire v5, Compact TLV v5.1, Streaming & Packet Ceilings (`wire/armor.py`, `wire/framing.py`, `wire/compact_v51.py`, `wire/streaming.py`, `protocol.py`):**
  - Enforced `MAX_ARMOR_BODY_LINE_LEN = 128`, `MAX_ARMOR_BLANK_LINES = 64`, `MAX_ARMOR_LINES = 1,500,000` (checked before `splitlines()`), post-CRC body-line rejection, and strict 8-char canonical Base64 CRC validation across `armor_unwrap` and `_armor_unwrap`.
  - Enforced canonical ascending TLV tag ordering (`require_canonical_order=True`), `MAX_TLV_FIELDS = 256`, `MAX_TLV_PAYLOAD_BYTES`, and `bool`/label validation in `compact_v51.py`, plus `MAX_BUCKET_SIZE = 1 MiB` and printable ASCII label validation in `framing.py`.
  - Added `max_chunks` (`MAX_STREAM_CHUNKS`), `max_total_bytes`, reserved header-flag rejection, and canonical `is_final_byte in (0, 1)` enforcement in `streaming.py`, plus `MAX_PACKET_CHUNKS = 2048` in `protocol.py` and `MAX_MULTI_RECIPIENT_SLOTS = 256` in `multi_recipient.py`.
- **Verification:** Added 8-test security suite `tests/test_v118_parser_resource_ceilings.py` and verified 10/10 Native C99 + 10/10 Pure-Python Golden KATs + 154/154 tests.

---

## Official Release `v1.1.7` (2026-11-24) — Hardened `QPKD-Argon2id` Pure-Python & C-Backend Parity + Auto-Calibration

- **100% Bit-Exact RFC 9106 Argon2id Across All 3 Backends (`calyx_qpep/kdf/argon2id_cascade.py`):**
  - Rewrote `_argon2id_pure_python` with authentic RFC 9106 Section 3.4.1.2 Argon2id hybrid addressing (data-independent Argon2i address blocks in pass 0 slices 0–1 + data-dependent Argon2d in pass 0 slices 2–3 and subsequent passes) and exact Section 3.4.2 reference window & `start_pos` arithmetic—closing the prior pure-Python vs. C-backend mismatch (`associated_data` discrepancy and silent 64-KiB block truncation).
  - Added native OpenSSL 3.2+ C `Argon2id` (`argon2id-rfc9106-openssl` via `cryptography`) as a zero-extra-dependency C backend alongside `argon2-cffi` (`argon2id-rfc9106-cffi`) and Pure-Python (`argon2id-rfc9106-pure-python`), all verified bit-exact against RFC 9106 Section 5.3 (`0d640df58d78766c...`) and multi-parameter differential matrices via `verify_argon2id_backend_parity()`.
  - Enforced strict anti-DoS parameter bounds (`validate_kdf_params`: `m_kib <= 1 GiB`, `t_cost <= 64`, `p_lanes <= 16`, `m_kib >= 8 * p_lanes`, `bool` rejection) and refused silent memory downgrades above `MAX_PURE_PYTHON_ARGON2_KIB` (`8192 KiB`) unless explicitly overridden; hardened `OpenQPEPProtocol.unlock_private_keys` against malformed `kdf_params` / `kdf_version` payloads.
- **Memory-Ceiling Safety Bounds & Calibrated Auto-Tuner (`calyx_qpep/kdf/hardware_tuner.py`):**
  - Added container/cgroup RAM limit awareness (`detect_cgroup_ram_limit_mib`, `detect_available_ram_mib`), `compute_safe_memory_ceiling_kib` (25% RAM cap, 512 MiB auto-tuner ceiling), and `enforce_kdf_memory_ceiling` (1 GiB hard ceiling), with automatic clamping + `+1` iteration compensation in `select_kdf_profile`.
  - Upgraded `benchmark_kdf` with multi-sample latency stats (`min_ms`, `median_ms`, `max_ms`), memory-bandwidth throughput (`mib_per_sec`), and floor-preserving `recommended_t_cost`, plus `calibrate_kdf_for_device()` returning ready-to-use `calibrated_kdf_params` with `SecretBuffer` scrubbing.
- **Hardened Passphrase Policy & Entropy Telemetry (`calyx_qpep/kdf/passphrase_policy.py`):**
  - Enforced upper length ceilings (`MAX_LENGTH = 1024` chars / `4096` UTF-8 bytes), blocked NUL / C0–C1 control / surrogate / Unicode Bidi-override characters, actively scrubbed witness staging buffers via `SecretBuffer`, and added conservative `estimate_passphrase_entropy_bits` + `strength_tier` while preserving 100% bit-exact `CALYX-QPEP-HARDCODED-POLICY-WITNESS-v1.0.0|` compatibility.
- **Verification:** Added 8-test suite `tests/test_v117_kdf_parity_and_calibration.py` and verified 10/10 Native C99 + 10/10 Pure-Python Golden KATs + 146/146 tests.

---

## Official Release `v1.1.6` (2026-11-24) — Strict Key-Hash Binding, Anti-Substitution & `HGC-448` Low-Order Hardening

- **Full RFC 7748 X448 & RFC 8032 Ed448 Low-Order / Canonical Hardening (`calyx_qpep/primitives/hgc448.py`):**
  - Added `validate_x448_public_key` & `is_x448_low_order_point` rejecting all Curve448 & twist low-order points (`u mod p in {0, 1, p-1}`) and non-canonical `u >= p` encodings inside `x448_exchange` and keyring verification.
  - Added `strict_ed448_verify`, `validate_ed448_point`, and `is_ed448_small_order_point` enforcing canonical on-curve decoding (`y < p`, zero padding bits 448..454, no `-0`), rejecting all 4 small-order torsion points `E[4]` (closing OpenSSL's cofactored order-4 `S=0` forgery on `(1, 0)` and `(p-1, 0)`), and enforcing canonical scalar `0 <= S < L` (blocking `S + L` signature malleability); wired `ed448_verify` directly through `strict_ed448_verify`.
- **`.qpkrf` Parser & Anti-Substitution Hardening (`calyx_qpep/protocol.py`, `calyx_qpep/wire/armor.py`):**
  - Added `_strict_json_loads` rejecting duplicate JSON keys at any depth and non-standard `NaN`/`Infinity` constants across `import_qpkrf`, `unlock_private_keys`, `decrypt_packet`, and `verify_signature`.
  - Hardened `_validate_identity_field` against Unicode Bidi overrides (Trojan Source), zero-width/format characters, non-NFC strings, non-ASCII email spoofing, and mixed-script Latin/Cyrillic/Greek homograph UIDs while preserving legitimate single-script NFC Unicode names.
  - Enforced armor `Key-Hash:` header consistency, `envelope.suite_id` vs `public_bundle.suite_id` consistency, `PUBLIC_KEY_RING` private-bundle smuggling rejection, exact public-key sizes & tier cross-binding, and duplicate/oversized/Bidi ASCII armor header rejection.
- **Verification:** Added 8-test security regression suite `tests/test_v116_hgc448_and_qpkrf_hardening.py` and verified 10/10 Native C99 + 10/10 Pure-Python Golden KATs + 138/138 tests.

---

## Official Release `v1.1.5` (2026-11-24) — Constant-Time `poly_ring.py` Compression, Decompression & CBD Sampling (KyberSlash Closure)

- **KyberSlash-Immune Branchless `poly_ring.py` (`calyx_qpep/lattice/poly_ring.py`):** Replaced variable-time `// QLX_Q` compression division with exact fixed-point multiply-and-shift (`(((x << d) + 1664) * 20642679) >> 36`, proven bit-exact for all `x in 0..3328` and `d in 1..12`), eliminated `% QLX_Q` / `% QVS_Q` divisions from `decompress_poly`, `byte_encode_12`, `byte_decode_12`, `sample_cbd1_3329`, `sample_cbd2_3329`, `sample_eta_qvs`, `sample_mask_y_qvs`, `pack_poly24_qvs`, and `unpack_poly24_qvs`, added `sample_cbd_eta_3329` + strict input-length bounds, and wrapped secret sampling buffers in `SecretBuffer`.
- **Division-Free Branchless Barrett & QVS Decomposition (`consttime.py`, `ntt_3329.py`, `ntt_8380417.py`):** Upgraded `barrett_reduce_3329`, `montgomery_reduce_3329`, `barrett_reduce_qvs`, `center_qvs`, and `decompose_qvs` (exact `_QVS_ALPHA_M44 = 33587233` across all `8,380,417` residues) to zero-division branchless arithmetic, and aligned C99 `calyx_qpep/native/csrc/ntt_3329.c` and Rust `rust/openqpep-core/src/ntt.rs` on identical `ct_barrett_3329` reduction.
- **Hardened `QLXEngine` (`calyx_qpep/lattice/qlx_kem.py`):** Added strict bytes-like type validation on `ek`/`dk`/`ct` (`QPEPSuiteError`) and deterministic `try/finally` scrubbing of ephemeral encryption noise vectors (`r_vec`, `e1_vec`, `e2_list`) and decapsulation intermediates (`su_hat`, `w_poly`).
- **Verification:** Added 7-test regression suite `tests/test_v115_poly_ring_ct.py` including a permanent AST guard forbidding `//` and `%` inside secret lattice arithmetic, exhaustive `0..3328 x d=1..12` compression checks, Native C99 vs. Pure-Python parity tests, and 10/10 Golden KAT verification.

---

## Official Release `v1.1.4` (2026-11-24) — FIPS 204-Style Hedged Deterministic Signatures & Universal Fault-Guard Across All 10 Suites

- **FIPS 204-Style Hedged `QVSEngine.sign` (`calyx_qpep/lattice/qvs_dsa.py`):** Upgraded `QVSEngine.sign` to default hedged mode (`hedged=True`, mixing fresh 32-byte CSPRNG `rnd` with `k_sign` + `mu` via `CALYX-QVS-RNDS-HEDGED-v1.1.4|`) defeating both weak/stuck RNGs and differential fault analysis on repeated signing, while preserving optional pure deterministic mode (`hedged=False`) and 100% unchanged `QVSEngine.verify` wire compatibility.
- **Universal Verify-Before-Emit Fault-Guard (`QPEPFaultGuardError`) Across All 10 Suites:**
  - Added mandatory Verify-Before-Emit Fault-Guard to **`ed448_sign`** (`calyx_qpep/primitives/hgc448.py`).
  - Added hedged `opt_rand` derivation + mandatory Verify-Before-Emit Fault-Guard + full-scope `SecretBuffer` scrubbing to **`QHS512HypertreeEngine.sign`** (`calyx_qpep/hashsig/qhs_512_hypertree.py`).
  - Upgraded **`MultivariateQuadraticEngine.sign`** (`calyx_qpep/multivariate/qmq_512.py`) with hedged message-bound 16-byte UOV salt (closing weak-RNG vinegar-reuse attacks) + secret oil/vinegar matrix zeroization.
  - Upgraded **`SupersingularIsogenyEngine.sign`** (`calyx_qpep/isogeny/sqi_2d_512.py`) with hedged CSIDH-512 SeaSign nonce derivation + secret ideal scrubbing.
  - Added bundle-level Verify-Before-Emit Fault-Guard to **`CalyxSovereignPentad.sign`** (`calyx_qpep/pentad/sovereign_pentad.py`) and **`sign_beyond_lwe`** (`calyx_qpep/beyond_lwe_bridge.py`).
- **Verification:** Added 8-test suite `tests/test_v114_hedged_fault_guard.py` verifying hedged vs. deterministic signing, stuck all-zero RNG immunity, fault-injection rejection across every signature engine (`QVS`, `Ed448`, `QHS-512`, `QMQ-512`, `CIF-SQI-512`, `CSP-Omega`, and Beyond-LWE bridge), zero `mlock` leaks, and 10/10 Native + Pure-Python Golden KAT parity.

---

## Official Release `v1.1.3` (2026-11-24) — Constant-Time `CC-512` AEAD Hardening & Nonce-Misuse-Resistant `CC-512-SIV` Mode

- **Hardened Wire v5 `CC-512` AEAD (`calyx_qpep/primitives/cc512_aead.py`):** Added strict bytes-like type checks, 64-byte key / 24-byte nonce / NIST SP 800-38D payload-ceiling assertions (`QPEPWireFormatError`), `SecretBuffer` wrapping of master keys, derived subkeys, and intermediate `ct_inner` buffers on both encrypt and decrypt while keeping Wire v5 `CC-512` 100% bit-exact.
- **Nonce-Misuse-Resistant `CC-512-SIV` Mode (`cc512_siv_encrypt`, `cc512_siv_decrypt`, `CC512SIV`):** Implemented a provably CMT-4 key-committing Synthetic-IV mode (`96`-byte overhead = 32 B 256-bit `qSponge-512` SIV + 64 B `CC-512`) with injective `u64be` length-framed `(nonce, aad, plaintext)` binding, per-SIV fresh `(msg_key64, msg_nonce24)` derivation, deterministic & hedged nonce support, and constant-time SIV re-verification before releasing plaintext.
- **Domain-Separated Key Wrapping (`cc512_siv_wrap_key`, `cc512_siv_unwrap_key`):** Added nonce-misuse-resistant key wrapping with dedicated `CALYX-CC512-SIV-KEYWRAP-v1.1.3|` AAD domain separation and `SecretBuffer` scrubbing, exported from `calyx_qpep` and `calyx_qpep.primitives`.
- **Verification:** Added 9-test regression suite `tests/test_v113_cc512_siv.py` covering Wire v5 parity, strict bounds, nonce-misuse resistance, injective framing, bit-flip & SIV-recheck forgery defense, key-wrap domain separation, and zero `mlock` leaks.

---

## Official Release `v1.1.2` (2026-11-24) — OS Memory Locking (`mlock` / `MADV_DONTDUMP` / `PR_SET_DUMPABLE`) & Hardened `SecretBuffer`

- **Hardened `SecretBuffer` with Reference-Counted OS `mlock()` (`calyx_qpep/primitives/zeroize.py`):** Upgraded `SecretBuffer` to pin mutable secret `bytearray` storage against silent heap relocation, lock backing pages in physical RAM via thread-safe reference-counted `mlock()`/`munlock()`, expose `.view()` / `.copy_into()` / `.is_memory_locked` / `.is_wiped`, and gracefully degrade when `RLIMIT_MEMLOCK` is restricted.
- **Dedicated Guard-Page & Core-Dump-Excluded `LockedMemoryBuffer`:** Added POSIX `mmap()` secret arenas bracketed by `PROT_NONE` guard pages, locked with `mlock()` and excluded from Linux core dumps via `madvise(MADV_DONTDUMP)`, with scoped zero-copy views (`scoped_view()`) and mandatory post-wipe zeroization verification before `munlock()`/`munmap()`.
- **Native C99 `openqpep_is_zeroed` & Opt-In Process Hardening:** Added branchless constant-time `openqpep_is_zeroed` to `calyx_qpep/native/csrc/pentad_accel.c` (`native_is_zeroed` in `native/loader.py`), opt-in `disable_core_dumps()` / `harden_process_memory()` (`RLIMIT_CORE = 0` + Linux `prctl(PR_SET_DUMPABLE, 0)`), `memory_security_status()`, `zeroize_many()`, and `zeroize_secret_dict()`.
- **Expanded Secret Scrubbing Across KEM / DSA / KDF / AEAD / Protocol Paths:** Scrubbed pure-Python RFC 9106 Argon2id working lanes & `final_blk`, `QLXEngine` secret polynomials & FO intermediates, `QVSEngine` secret signing vectors & nonce seeds, `HGC-448` constant-time low-order checks, `CC-512` `memoryview` subkey slicing, and `protocol.py` private-key/masking/reassembly buffers.
- **Documentation Hygiene & Verification:** Updated `README.md` to remove the retired external roadmap link, added `tests/test_v112_memory_locking.py`, and verified 100% `v1.0.0`–`v1.1.1` Wire v5 / `kdf_version: 4` / 10-suite KAT parity.

---

## Official Release `v1.1.1` (2026-11-24) — Strict Input Bounds, Typed Exceptions & Constant-Time Audit Sweep

- **Zero Broad `except Exception:` in Production Protocol Modules:** Audited and replaced every broad `except Exception:` handler across all production modules (`protocol.py`, `beyond_lwe_bridge.py`, `primitives/cc512_aead.py`, `primitives/hgc448.py`, `wire/armor.py`, `wire/multi_recipient.py`, `directory_kt/merkle_log.py`, `hardware/fido2_prf.py`, `isogeny/isogeny_suite.py`, `lattice/citadel_suite.py`, `pentad/sovereign_pentad.py`, `ratchet/session_state.py`, `zkp/lattice_sigma.py`, `audit/attack_sim.py`) with explicit narrow exception tuples; guarded permanently by AST verification in `tests/test_v111_hardening.py`.
- **Constant-Time String & Integer Comparison Sweep:** Added `ct_eq_str` and `ct_eq_int` to `calyx_qpep/primitives/consttime.py` and eliminated non-constant-time hash/key/commitment/challenge equality checks across `protocol.py`, `directory_kt/merkle_log.py`, `pentad/sovereign_pentad.py`, `keyring/revocation.py`, `keyring/subkeys.py`, `recovery/qshare_codec.py`, `signatures/multisig.py`, `signatures/timestamp_proof.py`, and `zkp/lattice_sigma.py`.
- **Deterministic Typed Exceptions & Strict Input Bounds:** Enforced typed `OpenQPEPError` subclasses (`QPEPWireFormatError`, `QPEPKeyRingError`, `QPEPMacVerificationError`, `QPEPTruncationError`, `QPEPSuiteError`) and strict type/length/control-character bounds across `protocol.py`, `beyond_lwe_bridge.py` (blocking cross-suite material substitution), and `compat_server.py` (bounded-RAM flood eviction on `SlidingWindowRateLimiter`).
- **100% `v1.0.0`–`v1.1.0` Interoperability:** Preserves complete Wire Format v5/v5.1, Stream v5, `kdf_version: 4`, and 10/10 Golden KAT bit-exact compatibility.

---

## Official Release `v1.1.0` (2026-11-23) — Upgraded from Official Release `v1.0.2`

- **Synchronized `v1.1.0` Protocol Release (`OpenQPEP/1.1.0`, PEP 440 `1.1.0`, `v1.1.0-stable`, branch `main`):** Upgraded directly from **Official Release `v1.0.2`** across Python (`calyx-openqpep`), C99 (`libopenqpep`), Rust (`openqpep-core`), Go (`go/openqpep`), and WASM/JS bindings.
- **100% `v1.0.x` Wire Format v5 Interoperability:** Full interoperability with all Official Release `1.0.0`–`1.0.2` Wire Format v5 (`\x89QPE\x05\x00`), Compact Binary TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), and `kdf_version: 4` key rings and packets while continuing to strictly reject all retired pre-release wire frames and `kdf_version < 4` key rings with `QPEPLegacyProtocolError`.
- **Shared Server Security Adapter (`calyx_qpep.compat_server`):** Added thread-safe `SlidingWindowRateLimiter`, canonical Wire v5 frame validator, pre-release version-token guard, and directory `.qpkrf` validator, covered by `tests/test_v110_official_release_stabilization.py`.
- **Native C99 & Golden KAT Conformance:** Verified C99/AVX2 `libopenqpep.so` zero-warning `-Wall -Wextra -Werror` build, regenerated all 10 deterministic `v1.1.0` Golden KAT vectors (`10/10` bit-exact), and verified all 92 protocol unit & security regression tests passing.

---

## Official Release `v1.0.2` (2026-11-22) — Previous Public Stable Baseline
- Synchronized ecosystem stabilization release across protocol, apps, and server backends on Official Wire Format v5 / v5.1, CMT-4 `CC-512` AEAD, and mandatory `kdf_version: 4` (`RFC 9106 QPKD-Argon2id`).

## Official Release `v1.0.0` (2026-11-21) — Permanent Public Launch Baseline
- Clean-slate public launch of all 10 post-quantum suites (5 structured Module-LWE + 5 genuine Beyond-LWE), CMT-4 Key-Committing `CC-512` AEAD, mandatory `kdf_version: 4`, Official Wire Format v5 / v5.1 / Stream v5, hardened sub-protocol stack (`QPEP-Ratchet`, `QPEP-MLS`, `QPEP-AKE`, `QPEP-KT` Ed448 + RFC 9162 consistency proofs, `QVS-Ring`, `DeniableVault`, `ThresholdKEM`, `Sphinx-PQ`, `LatticeZKProof`), and `CPOSLS-1.0` licensing.
