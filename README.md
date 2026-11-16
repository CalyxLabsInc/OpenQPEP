# OpenQPEP by Calyx Labs Inc. (`Beta Version 0.1.6`)

**Official Repository:** [OpenQPEP Github Repository](https://github.com/CalyxLabsInc/OpenQPEP/)  
**Official Public Key Directory:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  
**Android Application:** [Calyx QPEP Client Direct Download](https://github.com/CalyxLabsInc/CalyxQPEP-Client/releases/download/v0.1.6-beta/CalyxQPEPClient-Beta-v0.1.6.apk)                                             
**Creator & Lead Architect:** **Tristen Martinez** at **Calyx Labs Inc.** (`support@calyxlabsinc.org`)  
**License:** **Calyx Public Open Source License 1.0 (`CPOSL-1.0` — OpenQPEP Beta Version 0.1.6 Edition)**  

---

## 1. What Is OpenQPEP?

**OpenQPEP by Calyx Labs Inc.** (Open Quantum-Proof Encryption Protocol) is a ground-up, hybrid post-quantum encryption and digital signature standard created by **Tristen Martinez** at **Calyx Labs Inc.** to replace legacy OpenPGP (`RFC 4880`) and improve upon early post-quantum OpenPGP extensions such as [IETF RFC 9980](https://datatracker.ietf.org/doc/html/rfc9980).

OpenQPEP eliminates classical RSA/ECC single-point quantum vulnerabilities, optional passphrase defaults, collision-prone 64-bit Key IDs, detached signature stripping, and readable Base64 packet headers by combining:
- **Higher-Dimensional Module-LWE Lattices (`QLX-768`, `QLX-1024`, `QLX-2048`)** over $R_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ via a 7-layer Cooley-Tukey / Gentleman-Sande Number Theoretic Transform (`NTT`, $\zeta = 17 \bmod 3329$) with a full Fujisaki-Okamoto (`FO`) IND-CCA2 re-encryption transform and **448-bit Goldilocks Diffie-Hellman (`HGC-448` / `X448`)**.
- **Lattice Fiat-Shamir with Aborts Signatures (`QVS-65`, `QVS-87`, `QVS-128`)** over $R_{8380417} = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$ via an 8-layer complete `NTT` ($\zeta_Q = 1753 \bmod 8380417$) and strict rejection sampling, paired conjunctively with **448-bit Edwards Signatures (`Ed448`)**.
- **24-Round 1600-Bit Sponge Primitives (`qSponge-512` & `qSponge-XOF`)** with domain-separated duplex framing and zero reliance on `SHA-1` or `SHA-256`.
- **Protocol-Enforced `QPKD-Argon` Passphrase Lock** requiring every passphrase to be **12+ characters with at least 2 numbers, 4 special characters, 2 uppercase letters, and 4 lowercase letters**, absorbing a 64-byte cryptographic policy witness directly into key generation and secret key wrapping.
- **Dual-Stream Authenticated Payload Cipher (`Calyx-Cascade-512` / `CC-512`)** encrypting every 64 KiB frame twice in cascade through **14-round NIST `AES-256-GCM`** ($\text{GF}(2^{128})$ GHASH) and **20-round RFC 8439 `ChaCha20-Poly1305`** ($\bmod\ 2^{130}-5$).
- **Binary Wire Framing (`\x89QPE\x01\x01` + `qSponge-XOF` Whitening + 256-Bit Wire MAC)** so `base64 -d` on any `.qpkrf`, `.qpep`, or `ATTACHED SIGNATURE` block yields high-entropy binary bytes rather than readable JSON or plaintext.

---

## 2. Official Documentation Suite (`docs/`)

Detailed technical specifications and architectural manuals are located in the [`docs/`](docs/) directory:

1. [**`docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md`**](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Complete mathematical specification of the 24-round `Keccak-f[1600]` sponge (`qSponge-512` / `qSponge-XOF`), 7-layer NTT Module-LWE (`QLX`) over $\mathbb{Z}_{3329}[X]/(X^{256}+1)$, Fujisaki-Okamoto IND-CCA2 decapsulation, and 8-layer NTT Lattice Fiat-Shamir with Aborts (`QVS`) over $\mathbb{Z}_{8380417}[X]/(X^{256}+1)$.
2. [**`docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md`**](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — Side-by-side security analysis comparing **OpenQPEP (`Beta Version 0.1.6`)** against legacy OpenPGP (`RFC 4880`) and Post-Quantum OpenPGP ([RFC 9980](https://datatracker.ietf.org/doc/html/rfc9980) / [Post-Quantum OpenPGP Overview](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)).
3. [**`docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md`**](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — Byte-level specification of the `.qpkrf` (Quantum Proof Key Ring File) envelope, `Key Hash` derivation, `integrity_mac` verification, and the `\x89QPE\x01\x01` whitened binary wire frame.
4. [**`docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md`**](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — User and developer manual for the **Interactive Blue-Text OpenQPEP CLI**, the **Calyx QPEP Client** Android app, and the [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org) Public Key Directory server.
5. [**`GUIDE.md`**](GUIDE.md) — Step-by-step Linux server + Cloudflare Zero Trust deployment and update guide for `qpepkeys.calyxlabsinc.org`.

---

## 3. OpenQPEP Cryptographic Tiers (`QLX` + `QVS` + `HGC-448` + `CC-512`)

| OpenQPEP Suite Name | `QLX` Lattice KEM ($R_{3329}$) | `QVS` Lattice Signature ($R_{8380417}$) | Classical Hybrid Curve | Payload Cipher Cascade | Target Security Profile |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`QLX-768 + QVS-65 Velocity`** | Rank $k=3$ ($768$-dim, $1,184\text{ B}$ PK) | $(k,\ell)=(3,2)$ ($1,600\text{ B}$ Sig) | `HGC-448` (`X448` + `Ed448`) | `CC-512` (`AES-256-GCM` + `ChaCha20-Poly1305`) | Low-latency mobile messaging |
| **`QLX-1024 + QVS-87 Sovereign Hybrid` (Default)** | Rank $k=4$ ($1,024$-dim, $1,568\text{ B}$ PK) | $(k,\ell)=(4,3)$ ($2,368\text{ B}$ Sig) | `HGC-448` (`X448` + `Ed448`) | `CC-512` (`AES-256-GCM` + `ChaCha20-Poly1305`) | Sovereign hybrid default ([ML-KEM-1024 class](https://quantumsequrity.com/blog/ml-kem-1024-deep-dive) + [FIPS 204 class](https://www.quantumsecuritydefence.com/insights/fips-204-ml-dsa/)) |
| **`QLX-2048 + QVS-128 Ultra-Grid`** | Rank $k=8$ ($2,048$-dim, $3,104\text{ B}$ PK) | $(k,\ell)=(6,5)$ ($3,904\text{ B}$ Sig) | `HGC-448` (`X448` + `Ed448`) | `CC-512` (`AES-256-GCM` + `ChaCha20-Poly1305`) | Multi-decade archival secrecy |

---

## 4. Quick Start & Interactive Blue-Text English CLI (`openqpep`)

```bash
git clone https://github.com/CalyxLabsInc/OpenQPEP.git
cd OpenQPEP
pip install -e .

# Run the automated unit & cryptographic test suite
python3 -m unittest discover -s tests -v

# Launch the Interactive Blue-Text English-Command CLI
openqpep
```

Inside the interactive `OpenQPEP>` shell, type plain-English commands:
- **`Create Key`** &rarr; Prompts `Specify Key Type:` (`1` for `QLX-1024 + QVS-87 Sovereign Hybrid`, `2` for `QLX-2048 + QVS-128 Ultra-Grid`, `3` for `QLX-768 + QVS-65 Velocity`), then `Set Key Name:`, `Set Key Email:`, `Set Key Comment:`, and `Set Key Passphrase:`, generates your `.qpkrf` key pair, and optionally publishes your public key to `https://qpepkeys.calyxlabsinc.org`.
- **`Export Public <KeyName>`** / **`Export Private <KeyName>`** &rarr; Exports your public or passphrase-unlocked private `.qpkrf` key ring file.
- **`Import Key <FilePath.qpkrf>`** &rarr; Imports a public or private `.qpkrf` key ring file.
- **`List Keys`** / **`Key Details <KeyName>`** &rarr; Lists keys or displays the full 64-character **Key Hash** and `.qpkrf` public block.
- **`Encrypt Text`** / **`Decrypt Text`** / **`Encrypt File`** / **`Decrypt File`** &rarr; Interactive encryption and decryption with automatic sender signature verification.
- **`Create Signature`** / **`Verify Signature`** &rarr; Generates and verifies self-contained Attached Signatures (`CALYX QPEP ATTACHED SIGNATURE`).

---

## 5. Beta Version Progression Changelog (`0.1.1` &rarr; `0.1.6`)

OpenQPEP follows an incremental beta versioning scheme (`+0.0.1` per major architectural update, security fix, or feature):
- **`Beta Version 0.1.1`**: Initial multi-tier `QLX`/`QVS` reference implementation, `.qpkrf` key rings, `Key Hash` addressing, attached-only signatures, `qpepkeys.calyxlabsinc.org` directory server, and **Calyx QPEP Client** Android app.
- **`Beta Version 0.1.2`**: Official renaming of the protocol and project to **OpenQPEP by Calyx Labs Inc.** while retaining **Calyx QPEP Client** for the Android application.
- **`Beta Version 0.1.3`**: Security Audit Fix #1 — Enforced constant-time recomputation and verification of the 512-bit `integrity_mac` and 64-character `Key Hash` public-key binding during `import_qpkrf`.
- **`Beta Version 0.1.4`**: Security Audit Fix #2 — Enforced terminal-frame truncation checks (`final == 1` on the last 64 KiB `CC-512` chunk and `final == 0` on all preceding chunks) and automatic embedded sender signature verification on packet decryption.
- **`Beta Version 0.1.5`**: Released the **Interactive Blue-Text English-Command OpenQPEP CLI** (`openqpep`) with guided `Create Key`, `Export Private/Public <KeyName>`, `Import Key`, encryption/decryption, attached signing/verification, and persistent `~/.openqpep/keyring.json` storage.
- **`Beta Version 0.1.6` (Current)**: Recreated and expanded the [`docs/`](docs/) specification suite (4 comprehensive technical manuals), expanded `README.md`, and updated the **Calyx Public Open Source License 1.0 (`CPOSL-1.0`)**.
