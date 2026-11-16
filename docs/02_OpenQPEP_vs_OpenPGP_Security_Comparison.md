# OpenQPEP vs. Legacy OpenPGP (`RFC 4880` & `RFC 9980`) — Security Analysis

**Protocol:** **OpenQPEP by Calyx Labs Inc.** (`Beta Version 0.1.6`)  
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

## 2. How OpenQPEP (`Beta Version 0.1.6`) Solves Every OpenPGP Weakness

| Security Dimension | Legacy OpenPGP (`RFC 4880`) | Post-Quantum OpenPGP ([RFC 9980](https://datatracker.ietf.org/doc/html/rfc9980)) | **OpenQPEP by Calyx Labs Inc. (`Beta Version 0.1.6`)** |
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
