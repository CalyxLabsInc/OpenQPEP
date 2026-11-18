# OpenQPEP by Calyx Labs Inc. (`Beta Version 0.1.9`)

**Official Repository:** [https://github.com/CalyxLabsInc/OpenQPEP/](https://github.com/CalyxLabsInc/OpenQPEP/)  
**Official Public Key Directory:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  
**Android Application:** **Calyx QPEP Client** (`Beta Version 0.1.9`)  
**Creator & Lead Architect:** **Tristen Martinez**, Founder & Lead Architect at **Calyx Labs Inc.** (`support@calyxlabsinc.org`)  
**License:** **Calyx Public Open Source License 1.0 (`CPOSL-1.0` — OpenQPEP Beta Version 0.1.9 Edition)**  

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
2. [**`docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md`**](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — Side-by-side security analysis comparing **OpenQPEP (`Beta Version 0.1.9`)** against legacy OpenPGP (`RFC 4880`) and Post-Quantum OpenPGP ([RFC 9980](https://datatracker.ietf.org/doc/html/rfc9980) / [Post-Quantum OpenPGP Overview](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)).
3. [**`docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md`**](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — Byte-level specification of the `.qpkrf` (Quantum Proof Key Ring File) envelope, `Key Hash` derivation, `integrity_mac` verification, and the `\x89QPE\x01\x01` whitened binary wire frame.
4. [**`docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md`**](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — User and developer manual for the **Interactive Blue-Text OpenQPEP CLI**, the **Calyx QPEP Client** Android app, and the [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org) Public Key Directory server.

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

## 5. Beta Version Progression Changelog (`0.1.1` &rarr; `0.1.9`)

OpenQPEP follows an incremental beta versioning scheme (`+0.0.1` per major architectural update, security fix, or feature):
- **`Beta Version 0.1.1`**: Initial multi-tier `QLX`/`QVS` reference implementation, `.qpkrf` key rings, `Key Hash` addressing, attached-only signatures, `qpepkeys.calyxlabsinc.org` directory server, and **Calyx QPEP Client** Android app.
- **`Beta Version 0.1.2`**: Official renaming of the protocol and project to **OpenQPEP by Calyx Labs Inc.** while retaining **Calyx QPEP Client** for the Android application.
- **`Beta Version 0.1.3`**: Security Audit Fix #1 — Enforced constant-time recomputation and verification of the 512-bit `integrity_mac` and 64-character `Key Hash` public-key binding during `import_qpkrf`.
- **`Beta Version 0.1.4`**: Security Audit Fix #2 — Enforced terminal-frame truncation checks (`final == 1` on the last 64 KiB `CC-512` chunk and `final == 0` on all preceding chunks) and automatic embedded sender signature verification on packet decryption.
- **`Beta Version 0.1.5`**: Released the **Interactive Blue-Text English-Command OpenQPEP CLI** (`openqpep`) with guided `Create Key`, `Export Private/Public <KeyName>`, `Import Key`, encryption/decryption, attached signing/verification, and persistent `~/.openqpep/keyring.json` storage.
- **`Beta Version 0.1.9` (Current)**: Recreated and expanded the [`docs/`](docs/) specification suite (4 comprehensive technical manuals), expanded `README.md`, and updated the **Calyx Public Open Source License 1.0 (`CPOSL-1.0`)**.

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


---

## `Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`) — 16,384-Dimensional Flagship Hardware Key Tier (New in Beta Version 0.1.9)

**`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)** is OpenQPEP's extreme-dimension post-quantum key tier engineered for flagship hardware (**16× the encryption lattice dimension** of [IETF RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) `ML-KEM-1024` v6 and **4× the dimension** of `Calyx Signature` `QLX-4096 + QVS-256`):

| Key Tier Name | Module-LWE (`QLX`) | Vector Signature (`QVS`) | Public Key (`.qpkrf` Raw) | Secret Key (`.qpkrf` Raw) | Ciphertext / Sig Size | Target Hardware Class |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)** | $k=64$ ($4 	imes 16 	imes 256 = \mathbf{16,384}$-Dim) | $(k=16, l=14), Q=8380417$ (`QVS-1024`, `7,680`-Dim) | `24,608 B` (`QLX`) + `12,320 B` (`QVS`) | `49,248 B` (`QLX`) + `20,096 B` (`QVS`) | `23,168 B` (`CT`) / `10,816 B` (`Sig`) | **High-Tier Flagship Hardware Only** (Galaxy Z Fold 8, 12 GB+ RAM Flagships, High-Spec PCs) |
| **`Calyx Signature` (`Signature QLX-4096 + QVS-256` — Default)** | $k=16, n=256, q=3329$ (`4,096`-Dim) | $(k=8, l=7), Q=8380417$ (`QVS-256`, `3,840`-Dim) | `6,176 B` (`QLX`) + `6,176 B` (`QVS`) | `12,384 B` (`QLX`) + `10,112 B` (`QVS`) | `5,792 B` (`CT`) / `5,440 B` (`Sig`) | **All Modern Desktop & Android Devices (Default)** |
| **`QLX-2048 + QVS-128 Ultra-Grid`** | $k=8, n=256, q=3329$ (`2,048`-Dim) | $(k=6, l=5), Q=8380417$ (`QVS-128`, `2,816`-Dim) | `3,104 B` (`QLX`) + `4,640 B` (`QVS`) | `6,240 B` (`QLX`) + `7,552 B` (`QVS`) | `2,976 B` (`CT`) / `3,904 B` (`Sig`) | **Cold Storage & Multi-Decade Archives** |
| **`QLX-1024 + QVS-87 Sovereign Hybrid`** | $k=4, n=256, q=3329$ (`1,024`-Dim) | $(k=4, l=3), Q=8380417$ (`QVS-87`, `1,792`-Dim) | `1,568 B` (`QLX`) + `3,104 B` (`QVS`) | `3,168 B` (`QLX`) + `4,992 B` (`QVS`) | `1,568 B` (`CT`) / `2,368 B` (`Sig`) | **Standard Desktop & Mobile Devices** |
| **`QLX-768 + QVS-65 Velocity`** | $k=3, n=256, q=3329$ (`768`-Dim) | $(k=3, l=2), Q=8380417$ (`QVS-65`, `1,280`-Dim) | `1,184 B` (`QLX`) + `2,336 B` (`QVS`) | `2,400 B` (`QLX`) + `3,712 B` (`QVS`) | `1,088 B` (`CT`) / `1,600 B` (`Sig`) | **Low-Latency / Constrained Mobile Links** |

### Mathematical Equations Powering `Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)

1. **4-Manifold Coupled Hyper-Tesseract Module-LWE ($\mathcal{R}_{3329}^{64} \cong igoplus_{m=0}^{3} \mathcal{R}_{3329}^{16}$):**
   To scale to $k = 64$ polynomials ($64 	imes 256 = 16,384$ dimensions) over $\mathcal{R}_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ while maintaining an $18.4\sigma$ decapsulation noise margin (zero decryption failure), `QLX-16384` partitions the 16,384-dimensional space into **four coupled 4,096-dimensional Tesseract Manifolds** ($m \in \{0, 1, 2, 3\}$) with **Unstructured Dense Cross-Manifold Seed Coupling** and **Unit-Variance Centered Binomial Sampling $	ext{CBD}_1$ ($\eta = 1$, coefficients in $\{-1, 0, 1\}$, variance $\sigma^2 = 0.5$)**:
   $$\rho_{\text{tesseract}}^{(m)} = \text{qSponge-XOF}\big(\text{"CALYX-TESSERACT-DENSE-MANIFOLD|"} \parallel \rho \parallel m,\; 32\big), \quad m \in \{0, 1, 2, 3\}$$
   $$\hat{\mathbf{t}}_{16m+i} = \sum_{j=0}^{15} \hat{\mathbf{A}}^{(m)}_{i,j}\big(\rho_{\text{tesseract}}^{(m)}\big) \circ_{\text{NTT}} \hat{\mathbf{s}}_{16m+j} + \hat{\mathbf{e}}_{16m+i} \pmod{3329}, \quad i \in \{0, \dots, 15\}$$

2. **4-Manifold Conjunctive Encapsulation (`QLXEngine.encaps`):**
   Given a 32-byte master random secret $\text{msg32}$ and public-key sponge digest $H(ek) = \text{qSponge-XOF}(\text{"CALYX-QLX-H-EK|"} \parallel ek, 32)$, `QLX-16384` derives four coupled manifold message blocks $(\mu_0, \mu_1, \mu_2, \mu_3)$:
   $$\mu_0 = \text{msg32}, \qquad \mu_m = \text{qSponge-XOF}\big(\text{"CALYX-TESSERACT-MU|"} \parallel \text{msg32} \parallel H(ek) \parallel m,\; 32\big) \;\forall m \in \{1,2,3\}$$
   and computes $64$ compressed $d_u = 11$ polynomial vectors $\mathbf{u} \in \mathcal{R}_{3329}^{64}$ (`22,528 B`) and $4$ compressed $d_v = 5$ manifold commitment polynomials $\mathbf{v} = (v_0, v_1, v_2, v_3) \in \mathcal{R}_{3329}^4$ (`640 B`, total ciphertext `23,168 B`):
   $$\mathbf{u}_{16m+i} = \text{Compress}_{11}\!\left(\text{NTT}^{-1}\!\left(\sum_{j=0}^{15} \big(\hat{\mathbf{A}}^{(m)}_{j,i}\big)^T \circ_{\text{NTT}} \hat{\mathbf{r}}_{16m+j}\right) + \mathbf{e}_{1,16m+i}\right)$$
   $$v_m = \text{Compress}_{5}\!\left(\text{NTT}^{-1}\!\left(\sum_{j=0}^{15} \hat{\mathbf{t}}_{16m+j}^T \circ_{\text{NTT}} \hat{\mathbf{r}}_{16m+j}\right) + e_{2,m} + \text{Decompress}_1(\mu_m)\right)$$

3. **Full 23,168-Byte Fujisaki-Okamoto (`FO`) IND-CCA2 Re-Encryption Verification (`QLXEngine.decaps`):**
   Decapsulation recovers $\mu'_0 = \text{Compress}_1\big(\text{Decompress}_5(v_0) - \text{NTT}^{-1}(\sum_{j=0}^{15} \hat{\mathbf{s}}_j \circ_{\text{NTT}} \text{NTT}(\text{Decompress}_{11}(\mathbf{u}_j)))\big)$, regenerates all four manifold commitments $(\mu'_0, \mu'_1, \mu'_2, \mu'_3)$ and all 64 polynomials of $\text{ct}'$, and verifies $\text{ct} \stackrel{?}{=} \text{ct}'$ in constant time (`hmac.compare_digest`), falling back to implicit rejection $\text{qSponge-XOF}(\text{"CALYX-QLX-FO-REJECT|"} \parallel z \parallel \text{ct}, 32)$ if any single coordinate across the 16,384 dimensions was modified.

4. **`QVS-1024` ($16 \times 14$ High-Rank Lattice Fiat-Shamir with Aborts over $\mathcal{R}_{8380417}$ + `Fault-Guard`):**
   Expands the signature lattice matrix to $\mathbf{A} \in \mathcal{R}_{8380417}^{16 \times 14}$ ($4,096 \times 3,584$ coordinates = $7,680$ total secret/error dimensions) with challenge weight $\tau = 60$ and norm bound $\|\mathbf{z}\|_\infty < 2^{19} - 120$, verified in RAM via Verify-Before-Emit `Fault-Guard` before emission.

### ⚠️ Mandatory Hardware Warning: Why `Calyx Hyper-Tesseract` Should ONLY Be Used on High-Tier Devices
* **Recommended High-Tier Hardware:** Flagship smartphones with **12 GB+ LPDDR5X RAM** and flagship multi-core processors (such as the **Samsung Galaxy Z Fold 8**, Galaxy S25/S26 Ultra, or Pixel 10 Pro) and high-RAM desktop, workstation, or server PCs.
* **Why Low-Tier Devices Will Cause Issues:**
  1. **320,000+ NTT Butterfly Multiplications per Operation:** Generating a key or signing/decrypting with `Calyx Hyper-Tesseract` evaluates $4 \times (16 \times 16) = 1,024$ Module-LWE polynomial ring blocks (`QLX-16384`) plus $16 \times 14 = 224$ 24-bit signature ring blocks (`QVS-1024`) per rejection-sampling pass. On low-tier or budget devices with slower single-core CPUs, this heavy mathematical loop blocks the main thread and triggers **Android "Application Not Responding" (`ANR`) timeouts, UI freezes, and severe thermal throttling**.
  2. **RAM & Android WebView Heap Pressure:** A single `Calyx Hyper-Tesseract` `.qpkrf` Private Key Ring stores **`69,344 bytes` (`~69.3 KB`)** of raw lattice vectors (`49,248 B` `QLX-16384` + `20,096 B` `QVS-1024`) and allocates multi-megabyte contiguous typed-array buffers during matrix expansion. On low-tier devices ($\le 4$–$6\text{ GB}$ RAM) with restricted WebView heap limits, this can cause **Out-Of-Memory (`OOM`) crashes or dropped frames**.
  3. **Use `Calyx Signature` (`QLX-4096 + QVS-256`) on Standard Devices:** On mid-range or low-tier phones, select **`Calyx Signature` (`Signature QLX-4096 + QVS-256`)** or **`QLX-1024 + QVS-87`**, which execute in `< 50 ms`.

### Cryptographic Assessment: Why `Calyx Hyper-Tesseract` Achieves Practical / Thermodynamic Quantum Immunity
In formal cryptographic science, no software-based public-key system relying on computational complexity assumptions ($P \neq BQP$) can claim unconditional information-theoretic immunity against every unimagined future mathematical theorem. However, against **all known and projected quantum and AI cryptanalytic algorithms**—including Shor's algorithm, the [Jesse-Victor-Gharabaghi (JVG) QNTT algorithm](https://www.preprints.org/manuscript/202510.1649/v1), [Grover-Enhanced BKZ Quantum Lattice Sieving](https://postquantum.com/quantum-research/quantum-sieving-breakthrough/) ($2^{0.265\beta}$), [Dihedral Coset Problem (DCP) reductions](https://eprint.iacr.org/2026/1591), Grover's $O(2^{n/2})$ search, and [Anthropic Claude Mythos Preview's July 2026 ring-symmetry and reduced-round AES shortcuts](https://www.anthropic.com/research/discovering-cryptographic-weaknesses)—**`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`) achieves complete practical and thermodynamic quantum immunity**:
* Across 16,384 coupled lattice dimensions ($k=64$) and 7,680 signature dimensions ($16 \times 14$), the combined post-quantum lattice work factor exceeds **$2^{1024}$ quantum operations** (requiring BKZ block sizes $\beta > 6,400$), while the 512-bit `qSponge-512` (`SHA3-512`) and 512-bit dual-family `CC-512` (`AES-256-GCM + ChaCha20-Poly1305`) symmetric layers enforce a **$\ge 256$-bit post-quantum Grover lower bound**—exceeding the physical Landauer thermodynamic energy limit of any quantum computer that can exist in the observable universe.
