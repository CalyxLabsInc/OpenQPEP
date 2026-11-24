# OpenQPEP Core Protocol Changelog — Official Release `v1.1.3`

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
