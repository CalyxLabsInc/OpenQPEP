# CALYX-QPEP-0001: Calyx Quantum Proof Encryption Protocol (Calyx QPEP) Specification
**Organization:** Calyx Labs Inc.  
**Creator & Lead Architect:** Tristen Martinez  
**Protocol Name:** Calyx Quantum Proof Encryption Protocol (`Calyx QPEP` / `CALYX-QPEP/1.0`)  
**Official Client Application:** `Calyx QPEP Client`  
**Key Ring File Extension:** `.qpkrf` (Quantum Proof Key Ring File)  

---

## 1. Executive Summary

The **Calyx Quantum Proof Encryption Protocol (`Calyx QPEP`)** is a standalone, sovereign post-quantum encryption, digital signature, and key-management protocol created by **Calyx Labs Inc.**

Unlike legacy public-key standards, **Calyx QPEP** uses its own cohesive family of cryptographic primitives, a strict protocol-enforced passphrase gate, and the **`.qpkrf` (Quantum Proof Key Ring File)** format:

| Cryptographic Layer | Calyx QPEP Primitive Name | Technical Architecture |
| :--- | :--- | :--- |
| **Asymmetric Key Exchange** | **`QLX-1024 + HGC-448`** | **Quantum Lattice Exchange (1024-Dimension Module Ring)** fused with **Hyper-Goldilocks Curve 448 (224-Bit Birational Trapdoor)** |
| **Extended Key Exchange Tiers** | **`QLX-2048`** / **`QLX-768`** | 2048-Dimension Ultra-Grid Lattice & 768-Dimension Velocity Mobile Lattice modes |
| **Digital Signature Engine** | **`QVS-87 + qSponge-512`** | **Quantum Vector Signature (87-Rank Lattice Vector Commitment)** bound to **512-Bit Quantum Sponge Transcripts** |
| **Payload Stream Cipher** | **`Calyx-Cascade-512` (`CC-512`)** | **512-Bit Dual-Stream Authenticated Matrix Cipher** operating in 64 KiB tamper-evident frames |
| **Passphrase Key Ring Lock** | **`QPKD-Argon`** | **Quantum-Proof Key Derivation (Memory-Hard Matrix Lock)** protecting `.qpkrf` secret key rings |
| **Key Ring File Format** | **`.qpkrf`** | **Quantum Proof Key Ring File** (`PUBLIC KEY RING` & `PRIVATE KEY RING`) |

---

## 2. Mandatory Passphrase Policy (`QPKD-Argon` Enforcement)

Passphrases are **strictly mandatory** in the **Calyx QPEP** standard. No key pair can be generated, imported, exported, unlocked, used for decryption, or used for signing without a passphrase satisfying all five rules:

1. **Minimum Length**: `12` characters or more (`len >= 12`)
2. **Minimum Numbers**: At least `2` numeric digits (`0–9`)
3. **Minimum Special Characters**: At least `4` non-alphanumeric symbol characters (`!@#$%^&*()-_=+[]{}|;:'",.<>/?~`)
4. **Minimum Uppercase Letters**: At least `2` uppercase letters (`A–Z`)
5. **Minimum Lowercase Letters**: At least `4` lowercase letters (`a–z`)

---

## 3. Quantum Proof Key Ring File (`.qpkrf`) Armor Format

### Public Key Ring (`.qpkrf`)
```text
-----BEGIN CALYX QPKRF PUBLIC KEY RING-----
Version: CALYX-QPEP/1.0 (Calyx Labs Inc.)
Suite: QLX-1024+HGC-448 / QVS-87+qSponge-512 / CC-512
Key-ID: <32-Hex-Character Key Identifier>
Passphrase-Policy: QPKD-ARGON-MANDATORY-12CHAR-2NUM-4SPEC-2UPPER-4LOWER

<Base64-Encoded Authenticated .qpkrf Payload>
=<qSponge-Checksum>
-----END CALYX QPKRF PUBLIC KEY RING-----
```

### Private Key Ring (`.qpkrf`)
```text
-----BEGIN CALYX QPKRF PRIVATE KEY RING-----
Version: CALYX-QPEP/1.0 (Calyx Labs Inc.)
Suite: QLX-1024+HGC-448 / QVS-87+qSponge-512 / CC-512
Key-ID: <32-Hex-Character Key Identifier>
KDF: QPKD-Argon + qSponge-512
Passphrase-Policy: QPKD-ARGON-MANDATORY-12CHAR-2NUM-4SPEC-2UPPER-4LOWER

<Base64-Encoded Encrypted & Authenticated .qpkrf Payload>
=<qSponge-Checksum>
-----END CALYX QPKRF PRIVATE KEY RING-----
```
