# OpenQPEP by Calyx Labs Inc. (`Beta Version 0.2.1`)

**Official Repository:** [https://github.com/CalyxLabsInc/OpenQPEP/](https://github.com/CalyxLabsInc/OpenQPEP/)  
**Android Client Repository:** [https://github.com/CalyxLabsInc/CalyxQPEP-Client/](https://github.com/CalyxLabsInc/CalyxQPEP-Client/)  
**Official Public Key Directory:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  
**Official Website:** [https://calyxlabsinc.org/](https://calyxlabsinc.org/) ([Documentation Mirror](https://calyxlabsinc.github.io/))  
**Mobile Applications:** **Calyx QPEP Client** for **Android** (`Beta Version 0.2.1`, Android 10–17 / SDK 29–37) & **iOS** (Signed `.mobileconfig` Profile at [https://calyxlabsinc.org/CalyxQPEPClient.mobileconfig](https://calyxlabsinc.org/CalyxQPEPClient.mobileconfig))  
**Encrypted Messaging Suite:** **Calyx Encrypted Messenger** (*Calyx QPEP Messenger*, powered 100% by OpenQPEP `Beta Version 0.2.1`) — **Android** (`.apk`), **iOS** (`.mobileconfig`), & **Web** ([https://messenger.calyxlabsinc.org](https://messenger.calyxlabsinc.org))  
**Creator & Lead Architect:** **Tristen Martinez**, Founder & Lead Architect at **Calyx Labs Inc.** (`support@calyxlabsinc.org`)  
**License:** **Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0` — OpenQPEP Beta Version 0.2.1 Edition)**  

---

## 1. What Is OpenQPEP?

**OpenQPEP by Calyx Labs Inc.** (Open Quantum-Proof Encryption Protocol) is a ground-up, hybrid post-quantum encryption and digital signature standard created by **Tristen Martinez** at **[Calyx Labs Inc.](https://calyxlabsinc.org/)** to replace legacy OpenPGP (`RFC 4880`) and surpass the 1,024-dimension single-cipher ceiling of Post-Quantum OpenPGP ([IETF RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) / [RFC 9580](https://datatracker.ietf.org/doc/rfc9580/)).

OpenQPEP eliminates classical RSA/ECC single-point quantum vulnerabilities, optional passphrase defaults, collision-prone 64-bit Key IDs, detached signature stripping, and readable Base64 packet headers by combining:
- **Five Multi-Tier Module-LWE & Coupled Hyper-Tesseract Lattices (`QLX-768`, `QLX-1024`, `QLX-2048`, `Calyx Signature QLX-4096`, and `Calyx Hyper-Tesseract QLX-16384`)** over $R_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ via a 7-layer Cooley-Tukey / Gentleman-Sande Number Theoretic Transform (`NTT`, $\zeta = 17 \bmod 3329$) with a full Fujisaki-Okamoto (`FO`) IND-CCA2 re-encryption transform and **448-bit Goldilocks Diffie-Hellman (`HGC-448` / `X448`)**.
- **Five Lattice Fiat-Shamir with Aborts Signature Tiers (`QVS-65`, `QVS-87`, `QVS-128`, `QVS-256`, and `QVS-1024`)** over $R_{8380417} = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$ via an 8-layer complete `NTT` ($\zeta_Q = 1753 \bmod 8380417$), strict rejection sampling, **Verify-Before-Emit `Fault-Guard`** fault-injection protection, and conjunctive **448-bit Edwards Signatures (`Ed448`)**.
- **24-Round 1600-Bit Sponge Primitives (`qSponge-512` & `qSponge-XOF`)** (`SHA3-512` and `SHAKE-256`) with domain-separated duplex framing and zero reliance on `SHA-1` or `SHA-256`.
- **Protocol-Enforced `QPKD-Argon` Passphrase Lock** requiring every passphrase to be **12+ characters with at least 2 numbers, 4 special characters, 2 uppercase letters, and 4 lowercase letters**, absorbing a 64-byte cryptographic policy witness directly into key generation and secret key wrapping.
- **Dual-Stream Authenticated Payload Cipher (`Calyx-Cascade-512` / `CC-512`)** encrypting every 64 KiB frame twice in cascade through **14-round NIST `AES-256-GCM`** ($\text{GF}(2^{128})$ GHASH) and **20-round RFC 8439 `ChaCha20-Poly1305`** ($\bmod\ 2^{130}-5$), with full binary file preservation across **165+ hardcoded file extensions** and magic-byte header detection.
- **Binary Wire Framing (`\x89QPE\x02\x00` / `\x89QPE\x01\x01` + `qSponge-XOF` Whitening + 256-Bit Wire MAC)** so `base64 -d` on any `.qpkrf`, `.qpep`, or `ATTACHED SIGNATURE` block yields high-entropy binary bytes rather than readable JSON or plaintext, with zero cleartext identity headers on encrypted packets or signatures.

---

## 2. Official Documentation Suite (`docs/`)

Detailed technical specifications and architectural manuals are located in the [`docs/`](docs/) directory:

1. [**`docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md`**](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Complete mathematical specification of `qSponge-512` / `qSponge-XOF`, all five `QLX` Module-LWE and 4-Manifold Coupled Hyper-Tesseract tiers (`QLX-768` through `QLX-16384`), Fujisaki-Okamoto IND-CCA2 decapsulation, and all five `QVS` Lattice Fiat-Shamir with Aborts signature tiers (`QVS-65` through `QVS-1024`).
2. [**`docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md`**](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — Side-by-side security analysis comparing **OpenQPEP (`Beta Version 0.2.1`)** against legacy OpenPGP (`RFC 4880`) and Post-Quantum OpenPGP ([IETF RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) / [RFC 9580](https://datatracker.ietf.org/doc/rfc9580/) / [Post-Quantum OpenPGP Overview](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)).
3. [**`docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md`**](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — Byte-level specification of the `.qpkrf` (Quantum Proof Key Ring File) envelope across all five key tiers, `Key Hash` derivation, `integrity_mac` verification, 165+ binary file extension preservation, and the `\x89QPE` whitened binary wire frame.
4. [**`docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md`**](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — User and developer manual for the **Interactive Blue-Text OpenQPEP CLI**, the **Calyx QPEP Client** Android & iOS apps (including High-Tier Hardware requirements for `Calyx Hyper-Tesseract`), **Calyx Encrypted Messenger**, and the [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org) Public Key Directory server.

---

## 2.5 Official OpenQPEP Applications & Ecosystem

OpenQPEP (`Beta Version 0.2.1`) powers a full cross-platform suite of zero-telemetry applications hosted across [https://calyxlabsinc.org/](https://calyxlabsinc.org/) and mirrored at [https://calyxlabsinc.github.io/](https://calyxlabsinc.github.io/):

1. **Calyx QPEP Client for Android (`com.calyxlabs.qpepclient`)**
   * Full on-device post-quantum key manager, notepad encryptor, attached-signature engine, and 165+ binary file vault for **Android 10 through Android 17 (SDK 29–37)**.
   * Direct Download: [https://calyxlabsinc.org/downloads/CalyxQPEPClient-Beta-v0.2.1.apk](https://calyxlabsinc.org/downloads/CalyxQPEPClient-Beta-v0.2.1.apk) | GitHub Repo: [https://github.com/CalyxLabsInc/CalyxQPEP-Client/](https://github.com/CalyxLabsInc/CalyxQPEP-Client/)
2. **Calyx QPEP Client for iOS (Signed `.mobileconfig` WebClip Profile)**
   * Identical full-screen iOS edition of **Calyx QPEP Client** packaged as a cryptographically signed Apple Configuration Profile (`application/x-apple-aspen-config`, signed by **Calyx Labs Inc.**) with native iOS Files app import/export, live decrypted image previews, and all five OpenQPEP key tiers (`QLX-768` through `Calyx Hyper-Tesseract` `QLX-16384 + QVS-1024`).
   * Direct Safari Install Profile: [https://calyxlabsinc.org/CalyxQPEPClient.mobileconfig](https://calyxlabsinc.org/CalyxQPEPClient.mobileconfig) (Open in Safari &rarr; **Allow** &rarr; **Settings &rarr; Profile Downloaded &rarr; Install**).
3. **Calyx Encrypted Messenger (*Calyx QPEP Messenger*, `com.calyxlabs.qpem`)**
   * Real-time end-to-end post-quantum messaging platform built 100% on **OpenQPEP Beta Version 0.2.1** where your self-certified `.qpkrf` Key Ring is your account—addressed by your unique **64-character Key Hash** with zero phone numbers, 3-state Sent/Delivered/Read receipts, built-in **Scannable CLX-Code (SC Code)** camera scanning, whitened binary `.qpep` packets & signatures, and binary-safe file transfers across 165+ extensions.
   * Available on **Android** ([`.apk`](https://calyxlabsinc.org/downloads/CalyxEncryptedMessenger.apk)), **iOS** ([Signed `.mobileconfig`](https://calyxlabsinc.org/CalyxEncryptedMessenger.mobileconfig)), and **Web** ([https://messenger.calyxlabsinc.org](https://messenger.calyxlabsinc.org)) — Product Page: [https://calyxlabsinc.org/messenger.html](https://calyxlabsinc.org/messenger.html).
4. **Live Public Key Directory (`qpepkeys.calyxlabsinc.org`)**
   * Zero-telemetry opt-in `.qpkrf` Public Key Ring registry at [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org).

---

## 3. All Five OpenQPEP Cryptographic Tiers (`QLX` + `QVS` + `HGC-448` + `CC-512`)

| OpenQPEP Key Tier & Nickname | `QLX` Lattice KEM ($R_{3329}$) | `QVS` Lattice Signature ($R_{8380417}$) | Public Key (`.qpkrf` Raw) | Secret Key (`.qpkrf` Raw) | Ciphertext / Sig Size | Target Hardware & Security Profile |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)** | Rank $k=64$ ($4 \times 16 \times 256 = \mathbf{16,384}$-Dim Coupled Tesseract) | $(k,\ell)=(16,14)$ (`QVS-1024`, $\mathbf{7,680}$-Dim) | `24,608 B` (`QLX`) + `12,320 B` (`QVS`) | `49,248 B` (`QLX`) + `20,096 B` (`QVS`) | `23,168 B` (`CT`) / `10,816 B` (`Sig`) | **High-Tier Flagship Hardware Only** (Galaxy Z Fold 8, 12 GB+ RAM Flagships, High-Spec PCs; $\beta > 6,400$) |
| **`Calyx Signature` (`Signature QLX-4096 + QVS-256` — Default)** | Rank $k=16$ ($\mathbf{4,096}$-Dim Module-LWE) | $(k,\ell)=(8,7)$ (`QVS-256`, $\mathbf{3,840}$-Dim) | `6,176 B` (`QLX`) + `6,176 B` (`QVS`) | `12,384 B` (`QLX`) + `10,112 B` (`QVS`) | `5,792 B` (`CT`) / `5,440 B` (`Sig`) | **Recommended Default for All Devices** (4× the encryption dimensions of [RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) `ML-KEM-1024` v6; $\beta > 1,650$) |
| **`QLX-2048 + QVS-128 Ultra-Grid`** | Rank $k=8$ ($\mathbf{2,048}$-Dim Module-LWE) | $(k,\ell)=(6,5)$ (`QVS-128`, $\mathbf{2,816}$-Dim) | `3,104 B` (`QLX`) + `4,640 B` (`QVS`) | `6,240 B` (`QLX`) + `7,552 B` (`QVS`) | `2,976 B` (`CT`) / `3,904 B` (`Sig`) | **Multi-Decade Archival & Cold Storage** (2× the dimensions of `ML-KEM-1024` v6) |
| **`QLX-1024 + QVS-87 Sovereign Hybrid`** | Rank $k=4$ ($\mathbf{1,024}$-Dim Module-LWE) | $(k,\ell)=(4,3)$ (`QVS-87`, $\mathbf{1,792}$-Dim) | `1,568 B` (`QLX`) + `3,104 B` (`QVS`) | `3,168 B` (`QLX`) + `4,992 B` (`QVS`) | `1,568 B` (`CT`) / `2,368 B` (`Sig`) | **Standard Desktop & Mobile Tier** ([ML-KEM-1024 class](https://quantumsequrity.com/blog/ml-kem-1024-deep-dive) + [FIPS 204 class](https://www.quantumsecuritydefence.com/insights/fips-204-ml-dsa/)) |
| **`QLX-768 + QVS-65 Velocity`** | Rank $k=3$ ($\mathbf{768}$-Dim Module-LWE) | $(k,\ell)=(3,2)$ (`QVS-65`, $\mathbf{1,280}$-Dim) | `1,184 B` (`QLX`) + `2,336 B` (`QVS`) | `2,400 B` (`QLX`) + `3,712 B` (`QVS`) | `1,088 B` (`CT`) / `1,600 B` (`Sig`) | **Low-Latency Mobile Messaging** (Smallest packet footprint with `HGC-448` & `CC-512`) |

### 3.1 Mathematical Equations Powering `Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)

1. **4-Manifold Coupled Hyper-Tesseract Module-LWE ($\mathcal{R}_{3329}^{64} \cong \bigoplus_{m=0}^{3} \mathcal{R}_{3329}^{16}$):**
   To scale to $k = 64$ polynomials ($64 \times 256 = 16,384$ dimensions) over $\mathcal{R}_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ while preserving an $18.4\sigma$ decapsulation noise margin (zero decryption failure), `QLX-16384` partitions the 16,384-dimensional space into **four coupled 4,096-dimensional Tesseract Manifolds** ($m \in \{0, 1, 2, 3\}$) with **Unstructured Dense Cross-Manifold Seed Coupling** and **Unit-Variance Centered Binomial Sampling $\text{CBD}_1$ ($\eta = 1$, coefficients in $\{-1, 0, 1\}$, variance $\sigma^2 = 0.5$)**:
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

### 3.2 ⚠️ Mandatory Hardware Warning: Why `Calyx Hyper-Tesseract` Should ONLY Be Used on High-Tier Devices
* **Recommended High-Tier Hardware:** Flagship smartphones with **12 GB+ LPDDR5X RAM** and flagship multi-core processors (such as the **Samsung Galaxy Z Fold 8**, Galaxy S25/S26 Ultra, or Pixel 10 Pro) and high-RAM desktop, workstation, or server PCs.
* **Why Low-Tier Devices Will Cause Issues:**
  1. **320,000+ NTT Butterfly Multiplications per Operation:** Generating a key or signing/decrypting with `Calyx Hyper-Tesseract` evaluates $4 \times (16 \times 16) = 1,024$ Module-LWE polynomial ring blocks (`QLX-16384`) plus $16 \times 14 = 224$ 24-bit signature ring blocks (`QVS-1024`) per rejection-sampling pass. On low-tier or budget devices with slower single-core CPUs, this heavy mathematical loop blocks the main thread and triggers **Android "Application Not Responding" (`ANR`) timeouts, UI freezes, and severe thermal throttling**.
  2. **RAM & Android WebView Heap Pressure:** A single `Calyx Hyper-Tesseract` `.qpkrf` Private Key Ring stores **`69,344 bytes` (`~69.3 KB`)** of raw lattice vectors (`49,248 B` `QLX-16384` + `20,096 B` `QVS-1024`) and allocates multi-megabyte contiguous typed-array buffers during matrix expansion. On low-tier devices ($\le 4$–$6\text{ GB}$ RAM) with restricted WebView heap limits, this can cause **Out-Of-Memory (`OOM`) crashes or dropped frames**.
  3. **Use `Calyx Signature` (`QLX-4096 + QVS-256`) on Standard Devices:** On mid-range or low-tier phones, select **`Calyx Signature` (`Signature QLX-4096 + QVS-256`)** or **`QLX-1024 + QVS-87`**, which execute in `< 50 ms`.

### 3.3 2026 Quantum & AI-Cryptanalysis Immunity Profile (`Calyx Signature` & `Calyx Hyper-Tesseract`)
1. **Jesse-Victor-Gharabaghi (JVG) Hybrid QNTT Factorization & Shor's Algorithm**: Whereas JVG ([Preprints.org 202510.1649](https://www.preprints.org/manuscript/202510.1649/v1)) and Shor's algorithm attack RSA composite moduli and abelian discrete logarithms via Quantum Number Theoretic Transform (QNTT) / IQFT period finding, `Calyx Signature` (`4,096`-dim) and `Calyx Hyper-Tesseract` (`16,384`-dim) anchor hardness in Module-LWE and Module-SIS over polynomial rings with no hidden abelian period, hybridized with `HGC-448` (`X448`/`Ed448`) via `qSponge-512`.
2. **Quantum-Accelerated Lattice Sieving (Grover-Enhanced BKZ-$\beta$)**: Scaling the lattice module rank to $k=16$ (`4,096`-dim in `Calyx Signature`, $\beta > 1,650$) and $k=64$ (`16,384`-dim in `Calyx Hyper-Tesseract`, $\beta > 6,400$) maintains $>512$-bit to $>1,024$-bit post-quantum security margins even under Grover-accelerated $2^{0.265\beta}$ quantum sieve bounds ([PostQuantum Sieving Analysis](https://postquantum.com/quantum-research/quantum-sieving-breakthrough/)).
3. **Quantum Algorithms for the Dihedral Coset Problem (DCP / Extrapolated DCP)**: Hardened against theoretical LWE-to-DCP reductions ([IACR ePrint 2026/1591](https://eprint.iacr.org/2026/1591); refuted in [PQprobe / ePrint 2026/1693](https://pqprobe.com/blog/dcp-claim-refuted)) via Fujisaki-Okamoto (`FO`) IND-CCA2 re-encryption verification (`CALYX-QLX-FO-G|`), lossy $(d_u=11, d_v=5)$ rounding compression, and constant-time implicit rejection (`CALYX-QLX-FO-REJECT|`), preventing coherent quantum coset state extraction.
4. **Anthropic Claude Mythos Preview (July 2026) HAWK-256 Algebraic Symmetry Flaw & 7-Round AES Shortcuts**: In July 2026, Anthropic's Claude Mythos Preview ([Anthropic Research](https://www.anthropic.com/research/discovering-cryptographic-weaknesses)) halved the security of `HAWK-256` ($2^{64} \to 2^{38}$) by exploiting rotational/Galois symmetries in rank-2 NTRU lattices and accelerated 7-round AES-128 attacks via the Möbius Bridge. `QVS-256` and `QVS-1024` avoid NTRU ring isomorphisms completely, using asymmetric $(8 \times 7)$ and $(16 \times 14)$ Module-SIS Fiat-Shamir with Aborts with per-coordinate domain-separated `qSponge-XOF` matrix expansion (`CALYX-QVS-MAT-A|`), while `Calyx-Cascade-512 (CC-512)` cascades **full 14-round AES-256-GCM** inside **full 20-round ChaCha20-Poly1305** across two independent mathematical families (SPN + ARX).
5. **Grover's Algorithm on Symmetric & Hash-Based Primitives**: Uses 512-bit `qSponge-512` (`SHA3-512`) and `qSponge-XOF` (`SHAKE-256`) over a 1600-bit Keccak state (zero `SHA-256` usage) and 512-bit cascaded `CC-512` keys, leaving $\ge 256$ bits of post-quantum security under Grover's $O(2^{n/2})$ bound.
6. **Side-Channel & Fault Injection Attacks**: Implements **Verify-Before-Emit `Fault-Guard`** inside `QVSEngine.sign` (mathematically verifying every generated lattice signature against `pk` before returning it so glitch/Rowhammer faults can never leak secret vectors `s1, s2`), constant-time `hmac.compare_digest` checks, and `qSponge-XOF` secret-key XOR masking (`CALYX-QPEP-SK-MASK|`) at rest.

---

## 4. Quick Start & Interactive Blue-Text English CLI (`openqpep`)

```bash
git clone https://github.com/CalyxLabsInc/OpenQPEP.git
cd OpenQPEP
pip install -e .

# Run the automated unit & cryptographic test suite (16 test suites including QLX-4096, QLX-16384 & zero-metadata armor)
python3 -m unittest discover -s tests -v

# Launch the Interactive Blue-Text English-Command CLI
openqpep
```

Inside the interactive `OpenQPEP>` shell, type plain-English commands:
- **`Create Key`** &rarr; Prompts `Specify Key Type:` (`1` for `Calyx Signature: QLX-4096 + QVS-256`, `2` for `Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 [HIGH-TIER HARDWARE ONLY]`, `3` for `QLX-2048 + QVS-128 Ultra-Grid`, `4` for `QLX-1024 + QVS-87 Sovereign Hybrid`, `5` for `QLX-768 + QVS-65 Velocity`), then `Set Key Name:`, `Set Key Email:`, `Set Key Comment:`, and `Set Key Passphrase:`, generates your `.qpkrf` key pair, and optionally publishes your public key to `https://qpepkeys.calyxlabsinc.org`.
- **`Export Public <KeyName>`** / **`Export Private <KeyName>`** &rarr; Exports your public or passphrase-unlocked private `.qpkrf` key ring file.
- **`Import Key <FilePath.qpkrf>`** &rarr; Imports a public or private `.qpkrf` key ring file.
- **`List Keys`** / **`Key Details <KeyName>`** &rarr; Lists keys or displays the full 64-character **Key Hash** and `.qpkrf` public block.
- **`Encrypt Text`** / **`Decrypt Text`** / **`Encrypt File`** / **`Decrypt File`** &rarr; Interactive encryption and decryption across text and 165+ binary file formats with automatic sender signature verification.
- **`Create Signature`** / **`Verify Signature`** &rarr; Generates and verifies self-contained Attached Signatures (`CALYX QPEP ATTACHED SIGNATURE`).

---

## 5. Beta Version Progression Changelog (`0.1.1` &rarr; `0.2.1`)

OpenQPEP follows an incremental beta versioning scheme (`+0.0.1` per major architectural update, security fix, or feature):
- **`Beta Version 0.1.1`**: Initial multi-tier `QLX`/`QVS` reference implementation, `.qpkrf` key rings, `Key Hash` addressing, attached-only signatures, `qpepkeys.calyxlabsinc.org` directory server, and **Calyx QPEP Client** Android app.
- **`Beta Version 0.1.2`**: Official renaming of the protocol and project to **OpenQPEP by Calyx Labs Inc.** while retaining **Calyx QPEP Client** for the Android application.
- **`Beta Version 0.1.3`**: Security Audit Fix #1 — Enforced constant-time recomputation and verification of the 512-bit `integrity_mac` and 64-character `Key Hash` public-key binding during `import_qpkrf`.
- **`Beta Version 0.1.4`**: Security Audit Fix #2 — Enforced terminal-frame truncation checks (`final == 1` on the last 64 KiB `CC-512` chunk and `final == 0` on all preceding chunks) and automatic embedded sender signature verification on packet decryption.
- **`Beta Version 0.1.5`**: Released the **Interactive Blue-Text English-Command OpenQPEP CLI** (`openqpep`) with guided `Create Key`, `Export Private/Public <KeyName>`, `Import Key`, encryption/decryption, attached signing/verification, and persistent `~/.openqpep/keyring.json` storage.
- **`Beta Version 0.1.6`**: Recreated and expanded the [`docs/`](docs/) specification suite (4 comprehensive technical manuals), expanded `README.md`, and updated the **Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)**.
- **`Beta Version 0.1.7`**: Universal Multi-Extension Binary File Encryption & Decryption Fix — Added a hardcoded registry of 165+ supported file extensions (`SUPPORTED_FILE_EXTENSIONS`), binary magic-byte header detection (`detect_file_extension_and_mime`), and raw `Uint8Array` / `bytes` binary file encryption/decryption with live decrypted image preview in the Android client.
- **`Beta Version 0.1.8`**: Created the **`Calyx Signature` (`Signature QLX-4096 + QVS-256`)** default key tier ($k=16$, 4,096-dimensional Module-LWE + $(8 \times 7)$ `QVS-256` lattice vector signatures), added Verify-Before-Emit `Fault-Guard` fault-injection protection, and added the 6-vector 2026 Quantum & AI-Cryptanalysis Immunity Matrix.
- **`Beta Version 0.1.9`**: Created the **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)** High-Tier Flagship Hardware key tier ($k=64$, 16,384-dimensional 4-Manifold Coupled Hyper-Tesseract Module-LWE with unstructured dense cross-manifold seed coupling and unit-variance $\text{CBD}_1$ sampling + $(16 \times 14)$ `QVS-1024` vector signatures), added mandatory high-tier device hardware warnings, released **Calyx QPEP Client for iOS** (signed `.mobileconfig` profile), and integrated **Calyx Encrypted Messenger** (Android, iOS & Web) into the OpenQPEP ecosystem.
- **`Beta Version 0.2.0`**: Unified Suite Release & Security/HA Hardening — Synchronized **Calyx Encrypted Messenger** (`com.calyxlabs.qpem`) with the entire OpenQPEP Suite on `Beta Version 0.2.1` (Android, iOS, Web, `messenger_server`, `directory_server`, `website_server`, and `calyxlabsinc.github.io`); removed remaining cleartext `Recipient-Key-Hash:`, `Signer-Key-Hash:`, and `Key-Hash:` armor headers across OpenQPEP Core and Calyx QPEP Client; upgraded Messenger detached QVS signatures to whitened binary wire format (`\x89QPE\x02\x00`, backward compatible with `\x89QPE\x01\x09`) and fixed Packet Inspector escape rendering; upgraded `website_server` and `directory_server` to multi-threaded `ThreadingHTTPServer`, unified Cloudflare Tunnel port configs (`8443` / `8445` / `8446` / `8447`), and added OOM memory limits (`GOMEMLIMIT=256MiB`, `GOGC=50`, `MemoryMax=400M`) to `cloudflared-calyx.service`.

- **`Beta Version 0.2.1` (Current)**: Modular Cryptographic Kernel & Constant-Time Hardening — Refactored `calyx_qpep/` into 13 single-responsibility cryptographic modules (`constants.py`, `exceptions.py`, `primitives/{qsponge,cc512_aead,hgc448,consttime,zeroize}.py`, `lattice/{ntt_3329,ntt_8380417,poly_ring,tesseract_coupling,qlx_kem,qvs_dsa}.py`) while keeping `from calyx_qpep import OpenQPEPProtocol` 100% backward compatible; added branchless `ct_cmov` Fujisaki-Okamoto implicit-rejection multiplexing in `QLXEngine.decaps`; added `SecretBuffer` (`ctypes.memset`) active RAM scrubbing for secret lattice vectors and `CC-512` session keys; introduced typed cryptographic exceptions (`QPEPMacVerificationError`, `QPEPFaultGuardError`, `QPEPWireFormatError`, `QPEPTruncationError`, `QPEPPassphrasePolicyError`); adopted universal FOSS license **`CPOSLS-1.0`**; and synchronized the entire OpenQPEP Suite to `Beta Version 0.2.1`.
