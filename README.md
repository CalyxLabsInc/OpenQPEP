# OpenQPEP — Calyx Quantum Proof Encryption Protocol (`Calyx QPEP`)

[![Official Repository](https://img.shields.io/badge/GitHub-CalyxLabsInc%2FOpenQPEP-00D4FF)](https://github.com/CalyxLabsInc/OpenQPEP/)
[![Protocol Version](https://img.shields.io/badge/Calyx%20QPEP-Beta Version 0.1.1-2563EB)](https://github.com/CalyxLabsInc/OpenQPEP/)
[![Key Ring Format](https://img.shields.io/badge/Key%20Ring-.qpkrf-00D4FF)](https://github.com/CalyxLabsInc/OpenQPEP/)
[![License](https://img.shields.io/badge/License-Calyx%20Public%20Open%20Source%20License%201.0-10B981)](LICENSE)

**OpenQPEP** (`https://github.com/CalyxLabsInc/OpenQPEP/`) is the official open-source reference implementation and specification of the **Calyx Quantum Proof Encryption Protocol (`Calyx QPEP`)**, created by **Tristen Martinez** at **Calyx Labs Inc.**

**Calyx QPEP** is a sovereign, zero-downgrade post-quantum encryption, digital signature, and key-management standard designed from the ground up to replace legacy PGP systems and power the **Calyx QPEP Client** Android ecosystem.

---

## 1. How Calyx QPEP Works (End-to-End Architecture)

Every cryptographic operation in **Calyx QPEP** is executed across five interlocking protocol layers:

1. **Mandatory `QPKD-Argon` Passphrase Gate**:
   - **Calyx QPEP cannot function without a compliant passphrase.** Before any key pair is generated, unlocked, imported, exported, decrypted, or used to sign data, the protocol enforces the **Calyx QPEP Passphrase Policy**:
     - **Minimum Length:** `12` characters or more (`len >= 12`)
     - **Numbers (`0–9`):** At least `2`
     - **Special Characters (`!@#$%^&*()-_=+...`):** At least `4`
     - **Uppercase Letters (`A–Z`):** At least `2`
     - **Lowercase Letters (`a–z`):** At least `4`
   - Once validated, **`QPKD-Argon`** (**Quantum-Proof Key Derivation — Memory-Hard Matrix Lock**) stretches the passphrase with a 256-bit random salt and derives independent 256-bit key-wrapping streams via **`qSponge-512`**.

2. **Hybrid Quantum Lattice Key Encapsulation (`QLX` + `HGC-448`)**:
   - When encrypting a message or file to a recipient's `.qpkrf` key ring, the sender encapsulates a shared session secret across both a high-dimensional **Quantum Lattice Exchange (`QLX`)** polynomial ring $R_q = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ and an ephemeral **448-bit Hyper-Goldilocks Curve (`HGC-448`)** birational trapdoor.
   - Both shared secrets, both ciphertexts, and both recipient public keys are absorbed into a 512-bit **`qSponge-512`** transcript combiner:
     $$SS_{\text{QPEP}} = \text{qSponge-512}(\text{"CALYX-QPEP-KEM-v1"} \parallel SS_{\text{QLX}} \parallel SS_{\text{HGC-448}} \parallel CT_{\text{QLX}} \parallel EPK_{\text{HGC-448}} \parallel PK_{\text{QLX}} \parallel PK_{\text{HGC-448}})$$

3. **Cascaded Dual-Stream Matrix Payload Encryption (`Calyx-Cascade-512` / `CC-512`)**:
   - Plaintext messages and arbitrary binary files are segmented into **64 KiB (`65,536-byte`) frames**.
   - Each frame is encrypted twice in cascade under **`Calyx-Cascade-512` (`CC-512`)**: first through an inner 256-bit authenticated matrix cipher stream, and then through an outer, mathematically independent 256-bit authenticated stream cipher with frame-index Additional Authenticated Data (`AAD`), followed by a full-packet **`qSponge-512`** transcript authentication tag.

4. **Quantum Vector Digital Signatures (`QVS` + `qSponge-512`)**:
   - Digital signatures bind the message's `qSponge-512` digest, signer `Key Hash`, and UTC timestamp into a conjunctive **`QVS` (Quantum Vector Signature)** lattice commitment paired with a 448-bit Edwards-curve signature. Verification succeeds **if and only if** both signatures verify independently.

5. **Quantum Proof Key Ring Files (`.qpkrf`)**:
   - Exported and imported public and private key rings use the **`.qpkrf`** extension (`-----BEGIN CALYX QPKRF PUBLIC KEY RING-----` and `-----BEGIN CALYX QPKRF PRIVATE KEY RING-----`). Every `.qpkrf` key ring carries an atomic self-certification signature over the owner identity and all public key vectors.

---

## 2. The Three Calyx QPEP `QLX` Key Types & How They Work

**Calyx QPEP** defines three selectable **`QLX` (Quantum Lattice Exchange)** + **`QVS` (Quantum Vector Signature)** security tiers so users can match key parameters to their operational environment:

| Calyx QPEP Key Type | Lattice Module Rank & Ring | Signature Vector Rank | Classical Curve Partner | Symmetric Payload Cipher | Target Use Case & Operational Profile |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`QLX-768 + QVS-65 Velocity`** | Rank $k=3$, 768-Dim Polynomial Ring ($n=256, q=3329$) | 65-Rank `QVS-65` Vector Commitment | `HGC-448` (224-Bit Security) | `Calyx-Cascade-512 (CC-512)` | High-frequency mobile messaging & low-latency packet streaming with full quantum immunity |
| **`QLX-1024 + QVS-87 Sovereign Hybrid` *(Default)*** | Rank $k=4$, 1024-Dim Polynomial Ring ($n=256, q=3329$) | 87-Rank `QVS-87` Vector Commitment | `HGC-448` (224-Bit Security) | `Calyx-Cascade-512 (CC-512)` | Default sovereign standard for **Calyx QPEP Client** personal & receiver `.qpkrf` key rings |
| **`QLX-2048 + QVS-128 Ultra-Grid`** | Rank $k=8$, 2048-Dim Hyper-Lattice ($n=256, q=3329$) | 128-Rank `QVS-128` Vector Commitment | `HGC-448` (224-Bit Security) | `Calyx-Cascade-512 (CC-512)` | Multi-decade archival secrets & maximum-paranoia sovereign key rings |

### Mathematical Operation of `QLX` Key Types
- **Key Generation (`QLX.KeyGen`)**: Samples a public matrix $\mathbf{A} \in R_q^{k \times k}$ from a `qSponge-512` seed $\rho$ and centered binomial secret/error vectors $\mathbf{s}, \mathbf{e} \in R_q^k$, publishing the lattice vector $\mathbf{t} = \mathbf{A}\mathbf{s} + \mathbf{e} \pmod q$ alongside the `HGC-448` public point.
- **Encapsulation (`QLX.Encaps`)**: Encodes a 256-bit entropy seed into lattice polynomial space $(\mathbf{u}, v)$, masks it with the recipient's `QLX` lattice vector $\mathbf{t}$, performs `HGC-448` key agreement, and hashes the complete transcript through `qSponge-512` (with implicit rejection on decapsulation to defeat active chosen-ciphertext oracles).

---

## 3. Why Calyx QPEP Is Stronger Than PGP

Legacy PGP (and its incremental extensions) carries decades of structural baggage. **Calyx QPEP** eliminates those vulnerabilities at the protocol level:

| Security Dimension | Legacy PGP (`.asc` / `.pgp` / `.gpg`) | Calyx QPEP (`.qpkrf` / `.qpep`) | Why Calyx QPEP Is Stronger |
| :--- | :--- | :--- | :--- |
| **Passphrase Enforcement** | Optional; permits empty (`""`) or weak 4-character passphrases | **Strictly Mandatory `QPKD-Argon` Gate** (`12+` chars: `>=2` digits, `>=4` specials, `>=2` upper, `>=4` lower) | Eliminates unencrypted at-rest private keys and weak user passphrases entirely |
| **Quantum Resistance & Downgrade Surface** | Relies on RSA/ECC or mixed v4/v6 key bundles where classical subkeys can be stripped/downgraded | **100% Atomic `QLX + HGC-448` & `QVS-87` `.qpkrf` Key Rings** | Zero classical-only subkeys and zero legacy v4 downgrade paths |
| **Symmetric Payload Encryption** | Single-cipher CFB or single-layer AEAD | **Cascaded Dual-Stream `Calyx-Cascade-512 (CC-512)`** | Survives a complete cryptanalytic break of either underlying stream cipher |
| **Packet Framing & Truncation Immunity** | Historically vulnerable to CFB malleability and prefix/truncation attacks | **64 KiB Authenticated `CC-512` Chunks + Full-Packet `qSponge-512` MAC** | Detects any bit flip, chunk reordering, or premature stream truncation before outputting plaintext |
| **Key Ring Integrity** | Unauthenticated packet concatenation in legacy key rings | **`.qpkrf` Self-Certified Envelope + `QPKD-Argon` Export Lock** | Every `.qpkrf` file is cryptographically self-signed and tamper-evident |

---

## 4. Quick Start & CLI Usage

### Installation

```bash
git clone https://github.com/CalyxLabsInc/OpenQPEP.git
cd OpenQPEP
pip install -e .
```

### Python SDK Example

```python
from calyx_qpep import CalyxQPEPProtocol

# 1. Generate a Calyx QPEP Key Pair (QPKD-Argon passphrase rule enforced automatically)
passphrase = "Calyx!@#$_26Qp"  # 14 chars: 2+ digits, 4+ specials, 2+ upper, 4+ lower
keyring = CalyxQPEPProtocol.generate_keypair(
    name="Tristen Martinez",
    email="tristen@calyxlabs.io",
    passphrase=passphrase,
)

# 2. Export Public & Private Quantum Proof Key Ring Files (.qpkrf)
CalyxQPEPProtocol.export_qpkrf(keyring, passphrase, include_private=False, output_path="public.qpkrf")
CalyxQPEPProtocol.export_qpkrf(keyring, passphrase, include_private=True, output_path="private.qpkrf")

# 3. Encrypt & Decrypt Text (QLX-1024 + HGC-448 | CC-512)
packet = CalyxQPEPProtocol.encrypt_text("Sovereign quantum-proof payload", keyring, passphrase, sender_keyring=keyring)
plaintext = CalyxQPEPProtocol.decrypt_text(packet, keyring, passphrase, sender_public_keyring=keyring)

# 4. Sign & Verify (QVS-87 + qSponge-512)
sig = CalyxQPEPProtocol.sign_text("Release manifest Beta Version 0.1.1", keyring, passphrase)
assert CalyxQPEPProtocol.verify_text_signature("Release manifest Beta Version 0.1.1", sig, keyring)
```

### Run the Automated Test Suite

```bash
python3 -m unittest discover -s tests -v
```

---

## 5. License

Licensed under the **Calyx Public Open Source License 1.0 (`CPOSL-1.0`)**. See [`LICENSE`](LICENSE) for full terms.  
Copyright &copy; 2026 **Calyx Labs Inc.** (Created by **Tristen Martinez**).
