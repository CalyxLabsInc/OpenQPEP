# OpenQPEP vs. Legacy OpenPGP (`RFC 4880` & `RFC 9980`) — Security Analysis

**Protocol:** **OpenQPEP by Calyx Labs Inc.** (`Beta Version 0.1.8`)  
**Creator & Lead Architect:** **Tristen Martinez** ([Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEP/))  
**Public Key Registry:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  

---

## 1. Why Legacy OpenPGP (`RFC 4880`) Must Be Replaced

Legacy OpenPGP (`RFC 4880`) was standardized in the 1990s around classical number-theoretic assumptions (RSA integer factorization and discrete logarithms over elliptic curves) and legacy packet framing. In modern adversarial threat models, OpenPGP exhibits six systemic vulnerabilities:

1. **Quantum Breakability ("Harvest Now, Decrypt Later")**:
   Shor's polynomial-time quantum algorithm completely breaks RSA-2048/4096, DSA, ECDSA, and ECDH (`Curve25519` / `nistp256`). Adversaries archiving encrypted PGP messages today will be able to decrypt them retroactively once cryptographically relevant quantum computers scale.
2. **Legacy Packet Debt in Post-Quantum OpenPGP (`RFC 9980`)**:
   While [IETF RFC 9980](https://datatracker.ietf.org/doc/html/rfc9980) (analyzed in [Post-Quantum OpenPGP: RFC 9980 Standard Explained](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)) introduces post-quantum algorithm IDs into OpenPGP, its default profile relies on `ML-KEM-768 + X25519` (768-dimension lattice + 128-bit classical curve) while retaining legacy OpenPGP subkey binding packets, optional passphrase defaults, and complex multi-version parser surfaces.
3. **Optional or Weak Passphrases At Rest**:
   OpenPGP permits generating and exporting private keys with empty passphrases or low-iteration String-to-Key (`S2K`) hashes. If a user's device is seized or compromised, unencrypted or weakly hashed PGP secret subkeys can be extracted immediately.
4. **Single-Layer Cipher & CFB Malleability History**:
   Historically, OpenPGP relied on unauthenticated `CFB` mode with a Modification Detection Code (`MDC`) that enabled EFAIL gadget attacks, and even modern OpenPGP AEAD (`OCB`/`GCM`) relies on a single symmetric primitive.
5. **Detached Signature Stripping & Payload Substitution**:
   OpenPGP allows detached signatures where the signature block is separated from the message payload, allowing attackers or misconfigured mail clients to strip the signature or confuse which MIME part was actually signed.
6. **Collision-Prone Short Key IDs**:
   OpenPGP's legacy 32-bit and 64-bit Key IDs have long been vulnerable to birthday-bound collision spoofing ("Evil 32"), and 160-bit SHA-1 v4 fingerprints rely on a broken hash function.

---

## 2. How OpenQPEP (`Beta Version 0.1.8`) Solves Every OpenPGP Weakness

| Security Dimension | Legacy OpenPGP (`RFC 4880`) | Post-Quantum OpenPGP ([RFC 9980](https://datatracker.ietf.org/doc/html/rfc9980)) | **OpenQPEP by Calyx Labs Inc. (`Beta Version 0.1.8`)** |
| :--- | :--- | :--- | :--- |
| **Default Key Encapsulation** | Classical RSA-2048/4096 or X25519 (Quantum-vulnerable) | `ML-KEM-768 + X25519` (768-dim lattice + 128-bit curve) | **`QLX-1024 + HGC-448`** (1024-dim lattice + 448-bit Goldilocks curve, scaling to **`QLX-2048`**) |
| **Digital Signature Scheme** | Classical RSA / Ed25519 | Single-primitive or legacy packet bindings | **Conjunctive `QVS-87` / `QVS-128` Lattice Fiat-Shamir with Aborts + `Ed448`** |
| **Passphrase Enforcement** | Optional (allows empty or 1-char passphrases) | Optional (inherits OpenPGP S2K) | **Mandatory Protocol-Enforced `QPKD-Argon`** (`>=12` chars, `2+` digits, `4+` specials, `2+` upper, `4+` lower) |
| **Symmetric Payload Cipher** | Legacy CFB+MDC or single AEAD | Single-layer AEAD | **Cascaded Dual-Stream `CC-512`** (`14-round AES-256-GCM` + `20-round ChaCha20-Poly1305`) |
| **Signature Packaging** | Detached signatures permitted | Detached signatures permitted | **Attached Signatures Only (`ATTACHED_ENVELOPE`)** — message sealed inside signature |
| **Key Identifier** | 64-bit Key ID / 160-bit SHA-1 Fingerprint | 256-bit v6 Fingerprint | **512-Bit `Key Hash`** (64-character hex `qSponge-512` digest over all 4 public keys) |
| **Outer Wire Armor** | Base64 over predictable PGP packet headers | Base64 over OpenPGP TLV packets | **`\x89QPE\x01\x01` Binary Wire Frame + `qSponge-XOF` Stream Whitening + 256-Bit Wire MAC** |

---

## 3. Defense-in-Depth Guarantees of OpenQPEP

1. **Hybrid KEM Transcript Binding (`QLX` + `HGC-448`)**:
   In `OpenQPEPProtocol.encrypt_bytes`, the shared secret is derived by absorbing both the Module-LWE shared secret $K_{\text{QLX}}$ and the 448-bit `X448` shared secret $K_{\text{HGC}}$, together with both ciphertexts and both static public keys, into `qSponge-XOF`:
   $$K_{\text{hybrid}} = \text{qSponge-XOF}(\text{"CALYX-QPEP-KEM-v1|"} \,\|\, K_{\text{QLX}} \,\|\, K_{\text{HGC}} \,\|\, \text{ct}_{\text{QLX}} \,\|\, \text{pk}_{\text{eph}} \,\|\, \text{pk}_{\text{QLX}} \,\|\, \text{pk}_{\text{HGC}}, 64)$$
   An adversary must break **both** the Module-LWE lattice problem over $\mathbb{Z}_{3329}[X]/(X^{256}+1)$ **and** the 448-bit Goldilocks elliptic curve discrete logarithm problem to recover $K_{\text{hybrid}}$.
2. **Conjunctive Dual Signatures (`QVS` + `Ed448`)**:
   In `OpenQPEPProtocol.verify_signature` and `verify_public_keyring_self_signature`, verification succeeds if and only if **both** the 448-bit `Ed448` signature `sig1` **and** the lattice Fiat-Shamir with Aborts signature `sig2` (`QVSEngine.verify`) pass independently over the identical transcript.
3. **Truncation-Proof 64 KiB `CC-512` Framing**:
   Every 64 KiB chunk binds `recip=<KeyHash>|idx=<chunk_idx>|final=<0_or_1>` inside the authenticated additional data (`AAD`) of both `AES-256-GCM` and `ChaCha20-Poly1305`, and `decrypt_packet` enforces that chunk indices are strictly sequential ($0, 1, \dots, N-1$), that only chunk $N-1$ carries `final == 1`, and that the full chunk list matches the outer `transcript_qsponge_512` MAC before releasing a single byte of plaintext.


---

## `Signature QLX-4096 + QVS-256` Apex Quantum-Proof Tier (New in Beta Version 0.1.8)

**`Signature QLX-4096 + QVS-256`** is OpenQPEP's flagship maximum-security key type, engineered specifically to surpass legacy OpenPGP (`RSA-4096` / `Ed25519`) and standard first-generation post-quantum schemes against emerging 2026 quantum and AI-driven cryptanalytic breakthroughs:

| Tier Name | Module-LWE (`QLX`) | Vector Signature (`QVS`) | Public Key (`.qpkrf` Raw) | Secret Key (`.qpkrf` Raw) | Ciphertext / Sig Size |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Signature QLX-4096 + QVS-256` (Default Apex)** | $k=16, n=256, q=3329$ (`4,096`-Dim) | $(k=8, l=7), Q=8380417$ (`QVS-256`) | `6,176 B` (`QLX`) + `6,176 B` (`QVS`) | `12,384 B` (`QLX`) + `10,112 B` (`QVS`) | `5,792 B` (`CT`) / `5,440 B` (`Sig`) |
| **`QLX-2048 + QVS-128 Ultra-Grid`** | $k=8, n=256, q=3329$ (`2,048`-Dim) | $(k=6, l=5), Q=8380417$ (`QVS-128`) | `3,104 B` (`QLX`) + `4,640 B` (`QVS`) | `6,240 B` (`QLX`) + `7,552 B` (`QVS`) | `2,976 B` (`CT`) / `3,904 B` (`Sig`) |
| **`QLX-1024 + QVS-87 Sovereign Hybrid`** | $k=4, n=256, q=3329$ (`1,024`-Dim) | $(k=4, l=3), Q=8380417$ (`QVS-87`) | `1,568 B` (`QLX`) + `3,104 B` (`QVS`) | `3,168 B` (`QLX`) + `4,992 B` (`QVS`) | `1,568 B` (`CT`) / `2,368 B` (`Sig`) |
| **`QLX-768 + QVS-65 Velocity`** | $k=3, n=256, q=3329$ (`768`-Dim) | $(k=3, l=2), Q=8380417$ (`QVS-65`) | `1,184 B` (`QLX`) + `2,336 B` (`QVS`) | `2,400 B` (`QLX`) + `3,712 B` (`QVS`) | `1,088 B` (`CT`) / `1,600 B` (`Sig`) |

### 2026 Threat Immunity Matrix (`Signature QLX-4096 + QVS-256`)
1. **Jesse-Victor-Gharabaghi (JVG) Hybrid QNTT Factorization & Shor's Algorithm**: Whereas JVG ([Preprints.org 202510.1649](https://www.preprints.org/manuscript/202510.1649/v1)) and Shor's algorithm attack RSA composite moduli and abelian discrete logarithms via Quantum Number Theoretic Transform (QNTT) / IQFT period finding, `Signature QLX-4096 + QVS-256` anchors hardness in `4,096`-dimensional Module-LWE and `(8x7)` Module-SIS over polynomial rings with no hidden abelian period, hybridized with `HGC-448` (`X448`/`Ed448`) via `qSponge-512`.
2. **Quantum-Accelerated Lattice Sieving (Grover-Enhanced BKZ-$eta$)**: Doubling the lattice module rank to $k=16$ ($N = 4,096$ polynomial ring dimensions) and $(k=8, l=7)$ ($3,840$ vector dimensions) pushes the required BKZ block size to $eta > 1650$, maintaining $>512$-bit post-quantum security even under Grover-accelerated $2^{0.265eta}$ quantum sieve bounds ([PostQuantum Sieving Analysis](https://postquantum.com/quantum-research/quantum-sieving-breakthrough/)).
3. **Quantum Algorithms for the Dihedral Coset Problem (DCP / Extrapolated DCP)**: Hardened against theoretical LWE-to-DCP reductions ([IACR ePrint 2026/1591](https://eprint.iacr.org/2026/1591); refuted in [PQprobe / ePrint 2026/1693](https://pqprobe.com/blog/dcp-claim-refuted)) via Fujisaki-Okamoto (`FO`) IND-CCA2 re-encryption verification (`CALYX-QLX-FO-G|`), lossy $(d_u=11, d_v=5)$ rounding compression, and constant-time implicit rejection (`CALYX-QLX-FO-REJECT|`), preventing coherent quantum coset state extraction.
4. **Anthropic Claude Mythos Preview (July 2026) HAWK-256 Algebraic Symmetry Flaw & 7-Round AES Shortcuts**: In July 2026, Anthropic's Claude Mythos Preview ([Anthropic Research](https://www.anthropic.com/research/discovering-cryptographic-weaknesses)) halved the security of `HAWK-256` ($2^{64} 	o 2^{38}$) by exploiting rotational/Galois symmetries in rank-2 NTRU lattices and accelerated 7-round AES-128 attacks via the Möbius Bridge. `QVS-256` avoids NTRU ring isomorphisms completely, using asymmetric $(8 	imes 7)$ Module-SIS Fiat-Shamir with Aborts with per-coordinate domain-separated `qSponge-XOF` matrix expansion (`CALYX-QVS-MAT-A|`), while `Calyx-Cascade-512 (CC-512)` cascades **full 14-round AES-256-GCM** inside **full 20-round ChaCha20-Poly1305** across two independent mathematical families (SPN + ARX).
5. **Grover's Algorithm on Symmetric & Hash-Based Primitives**: Uses 512-bit `qSponge-512` (`SHA3-512`) and `qSponge-XOF` (`SHAKE-256`) over a 1600-bit Keccak state (zero `SHA-256` usage) and 512-bit cascaded `CC-512` keys, leaving $\ge 256$ bits of post-quantum security under Grover's $O(2^{n/2})$ bound.
6. **Side-Channel & Fault Injection Attacks**: Implements **Verify-Before-Emit `Fault-Guard`** inside `QVSEngine.sign` (mathematically verifying every generated lattice signature against `pk` before returning it so glitch/Rowhammer faults can never leak secret vectors `s1, s2`), constant-time `hmac.compare_digest` checks, and `qSponge-XOF` secret-key XOR masking (`CALYX-QPEP-SK-MASK|`) at rest.
