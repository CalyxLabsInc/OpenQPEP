# OpenQPEP `.qpkrf` Key Ring & Binary Wire Format Specification (`Beta Version 0.1.6`)

**Protocol:** **OpenQPEP by Calyx Labs Inc.** (`Beta Version 0.1.6`)  
**Creator & Lead Architect:** **Tristen Martinez** ([Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEP/))  
**File Extensions:** `.qpkrf` (Quantum Proof Key Ring File) & `.qpep` (Encrypted Packet)  

---

## 1. Binary Wire Framing (`\x89QPE\x01\x01` + `qSponge-XOF` Whitening)

To prevent passive protocol fingerprinting and ensure that raw Base64 decoding (`base64 -d`) never exposes plaintext JSON keys or metadata in transit, every OpenQPEP armored block (`.qpkrf` Public Key Ring, `.qpkrf` Private Key Ring, `.qpep` Encrypted Packet, and `ATTACHED SIGNATURE`) encapsulates its serialized payload inside a **whitened binary wire frame** before Base64 encoding:

```text
+-----------------------------------------------------------------------+
| Byte Offset | Length | Field Name   | Description                     |
+-------------+--------+--------------+---------------------------------+
| 0..5        | 6 B    | WIRE_MAGIC   | \x89 Q P E \x01 \x01            |
| 6..21       | 16 B   | wire_nonce   | CSPRNG 128-bit per-packet nonce |
| 22..N-33    | Var    | whitened     | payload XOR qSponge-XOF stream  |
| N-32..N-1   | 32 B   | wire_mac     | qSponge-512 frame MAC (256-bit) |
+-----------------------------------------------------------------------+
```

### 1.1 Wire Whitening & Authentication Equations
Given `header_label` (e.g., `"CALYX QPEP ENCRYPTED PACKET"`) and `payload_bytes`:
1. Sample `wire_nonce = os.urandom(16)`.
2. Generate whitening stream:
   $$M = \text{qSponge-XOF}(\text{"CALYX-WIRE-WHITEN-v1|"} \,\|\, \text{wire\_nonce} \,\|\, \text{header\_label}, |\text{payload\_bytes}|)$$
3. Compute whitened body $W = \text{payload\_bytes} \oplus M$.
4. Compute 256-bit frame MAC:
   $$\text{wire\_mac} = \text{qSponge-512}(\text{"CALYX-WIRE-MAC-v1|"} \,\|\, \text{wire\_nonce} \,\|\, \text{header\_label} \,\|\, W)[0:32]$$
5. Concatenate `wire_frame = WIRE_MAGIC || wire_nonce || W || wire_mac`, Base64-encode at 64 characters per line, and append the 48-bit `qSponge-XOF` armor checksum line:
   $$\text{crc\_line} = \text{"="} \,\|\, \text{Base64}(\text{qSponge-XOF}(\text{"CALYX-ARMOR-CRC-v1|"} \,\|\, \text{wire\_frame}, 6))$$

---

## 2. `.qpkrf` (Quantum Proof Key Ring File) Structure

All public and private keys in **OpenQPEP** are exported and imported using the `.qpkrf` file extension:
- **Public Key Rings (`PUBLIC_KEY_RING`)**: Do **not** require a passphrase to export or import. Used for sharing with correspondents and publishing to [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org).
- **Private Key Rings (`PRIVATE_KEY_RING`)**: Strictly require the owner's mandatory `QPKD-Argon` passphrase (`>=12` chars, `2+` digits, `4+` specials, `2+` uppercase, `4+` lowercase) on both export and import.

### 2.1 Self-Certification & `integrity_mac` Verification (`0.1.3` Hardening)
Every `.qpkrf` file binds its identity metadata and all four public keys (`hgc_448_public_b64`, `qlx_public_b64`, `hgc_sig_public_b64`, `qvs_public_b64`) via two independent cryptographic proofs verified automatically during `OpenQPEPProtocol.import_qpkrf`:
1. **`Key Hash` Binding**:
   $$\text{key\_hash} = \text{HexUpper}(\text{qSponge-512}(\text{"CALYX-QPEP-KEY-HASH-v1|"} \,\|\, \text{pk}_{\text{HGC}} \,\|\, \text{pk}_{\text{QLX}} \,\|\, \text{pk}_{\text{Ed448}} \,\|\, \text{pk}_{\text{QVS}}))[0:64]$$
2. **Conjunctive Self-Certification Signature (`self_signature_b64`)**:
   A 114-byte `Ed448` signature concatenated with a `QVS` lattice Fiat-Shamir with Aborts signature (`1,600` / `2,368` / `3,904` bytes) over:
   $$\text{cert\_transcript} = \text{"CALYX-QPEP-SELFCERT|"} \,\|\, \text{key\_hash} \,\|\, \text{created\_at} \,\|\, \text{name} \,\|\, \text{email} \,\|\, \text{qlx\_tier} \,\|\, \text{qvs\_tier} \,\|\, \text{comment} \,\|\, \text{pk}_{\text{all}}$$
3. **Envelope `integrity_mac`**:
   A 512-bit `qSponge-512` digest over the canonical sorted JSON representation of `(key_hash, created_at, name, email, public_bundle)` verified in constant time via `hmac.compare_digest`.

### 2.2 Dual-Layer Secret Key Protection (`encrypted_private_bundle`)
When a private key ring is created, the secret keys are protected by two independent cryptographic layers derived from `(passphrase, kdf_salt)` via `_qpkd_argon_derive`:
1. **Inner Lattice Secret Key Masking**: `qlx_sk` is XOR-masked with $\text{qSponge-XOF}(\text{"CALYX-QPEP-SK-MASK|"} \,\|\, k_{\text{mac}} \,\|\, \text{key\_hash}, |\text{qlx\_sk}|)$.
2. **Outer `CC-512` AEAD Cascade**: The serialized secret bundle `{hgc_448_private_b64, qlx_masked_private_b64, hgc_sig_private_b64, qvs_private_b64}` is encrypted with `AES-256-GCM(k_s1, n1, aad)` followed by `ChaCha20-Poly1305(k_s2, n2, aad)` where `aad = "CALYX-QPEP-PRIVRING|" || key_hash`.
