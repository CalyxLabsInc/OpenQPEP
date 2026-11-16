# OpenQPEP Mathematical & Cryptographic Specification (`Beta Version 0.1.6`)

**Protocol:** **OpenQPEP by Calyx Labs Inc.** (Open Quantum-Proof Encryption Protocol)  
**Android Application:** **Calyx QPEP Client** (`Beta Version 0.1.6`)  
**Creator & Lead Architect:** **Tristen Martinez** ([Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEP/))  
**Public Key Registry:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  
**Universal Version:** `Beta Version 0.1.6` (`0.1.6`)  

---

## 1. Executive Architecture Overview

**OpenQPEP by Calyx Labs Inc.** (`Beta Version 0.1.6`) is a clean-slate, hybrid post-quantum encryption and digital signature standard engineered by **Tristen Martinez** at **Calyx Labs Inc.** to replace legacy OpenPGP (`RFC 4880`) and improve upon early post-quantum OpenPGP drafts such as [IETF RFC 9980](https://datatracker.ietf.org/doc/html/rfc9980).

Every cryptographic operation in **OpenQPEP** is built around five core pillars:
1. **1600-Bit 24-Round Sponge Primitives (`qSponge-512` & `qSponge-XOF`)**: Built directly on the 24-round `Keccak-f[1600]` state permutation with explicit domain separation (`CALYX-QSPONGE-512-v1|` and `CALYX-QSPONGE-XOF-v1|`) and zero reliance on legacy `SHA-1` or `SHA-256`.
2. **Module-LWE Key Encapsulation (`QLX-768`, `QLX-1024`, `QLX-2048`) + 448-Bit Classical Hybrid (`HGC-448`)**: Performs polynomial ring arithmetic over $R_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ via a 7-layer Cooley-Tukey / Gentleman-Sande Number Theoretic Transform (`NTT`) with primitive 256th root of unity $\zeta = 17 \bmod 3329$ and a full Fujisaki-Okamoto (`FO`) IND-CCA2 re-encryption transform, combined with 448-bit Goldilocks Diffie-Hellman (`X448`).
3. **Lattice Fiat-Shamir with Aborts Signatures (`QVS-65`, `QVS-87`, `QVS-128`) + 448-Bit Edwards Conjunctive Signatures (`Ed448`)**: Performs polynomial ring arithmetic over $R_{8380417} = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$ via an 8-layer complete `NTT` with primitive 512th root of unity $\zeta_Q = 1753 \bmod 8380417$ and strict rejection sampling over masking vectors $\mathbf{y} \in [-\gamma_1+1, \gamma_1]^\ell$.
4. **Protocol-Enforced `QPKD-Argon` Passphrase Lock**: Hardcodes a mandatory character-class policy (`>=12` characters, `>=2` digits, `>=4` special characters, `>=2` uppercase letters, `>=4` lowercase letters) into a 64-byte cryptographic policy witness absorbed into both key generation and secret key wrapping.
5. **Dual-Stream Authenticated Payload Cipher (`Calyx-Cascade-512` / `CC-512`) & `\x89QPE\x01\x01` Binary Wire Framing**: Encrypts all payloads and secret key rings twice in cascade through 14-round NIST `AES-256-GCM` ($\text{GF}(2^{128})$ GHASH) and 20-round RFC 8439 `ChaCha20-Poly1305` ($\bmod\ 2^{130}-5$), then whitens the outer wire frame with a 128-bit random salt and `qSponge-XOF` keystream before Base64 armoring.

---

## 2. `qSponge-512` and `qSponge-XOF` (24-Round `Keccak-f[1600]`)

OpenQPEP completely eliminates `SHA-256` across both the Python reference library (`calyx_qpep/qlx_lattice.py`) and the **Calyx QPEP Client** Android engine. All hashing, transcript binding, matrix expansion, and keystream whitening use the 1600-bit `Keccak-f[1600]` state array $A \in (\mathbb{Z}_2^{64})^{5 \times 5}$ across 24 rounds of $(\iota \circ \chi \circ \pi \circ \rho \circ \theta)$:

- **`qSponge-512` (`qsponge_512`)**:
  - Rate $r = 576$ bits ($72$ bytes), capacity $c = 1024$ bits ($128$ bytes), output length $512$ bits ($64$ bytes).
  - Domain separator prefix: `"CALYX-QSPONGE-512-v1|"`.
  - Delimited suffix byte: `0x06`, final rate bit `0x80`.
- **`qSponge-XOF` (`qsponge_var`)**:
  - Rate $r = 1088$ bits ($136$ bytes), capacity $c = 512$ bits ($64$ bytes), arbitrary output length $L$ bytes.
  - Domain separator prefix: `"CALYX-QSPONGE-XOF-v1|"`.
  - Delimited suffix byte: `0x1F`, final rate bit `0x80`.

---

## 3. `QLX` Module-LWE Key Encapsulation Over $R_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$

### 3.1 Ring Parameters & Tiers
Consistent with high-security lattice parameterizations analyzed in [ML-KEM-1024 Deep Dive](https://quantumsequrity.com/blog/ml-kem-1024-deep-dive), OpenQPEP defines three Module-LWE tiers over the cyclotomic ring $R_q = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ ($q = 3329 = 2^8 \cdot 13 + 1$, $n = 256$, primitive 256th root of unity $\zeta = 17 \bmod 3329$ satisfying $\zeta^{128} \equiv -1 \pmod{3329}$):

| OpenQPEP Tier | Module Rank $k$ | Polynomial Dimension | Compression $(d_u, d_v)$ | Public Key (`ek`) | Secret Key (`dk`) | Ciphertext (`ct`) | Paired Signature Tier |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`QLX-768`** | $k = 3$ | $768$ | $(10, 4)$ | $1,184\text{ B}$ | $2,400\text{ B}$ | $1,088\text{ B}$ | `QVS-65` |
| **`QLX-1024` (Default)** | $k = 4$ | $1,024$ | $(11, 5)$ | $1,568\text{ B}$ | $3,168\text{ B}$ | $1,568\text{ B}$ | `QVS-87` |
| **`QLX-2048`** | $k = 8$ | $2,048$ | $(11, 5)$ | $3,104\text{ B}$ | $6,240\text{ B}$ | $2,976\text{ B}$ | `QVS-128` |

### 3.2 7-Layer Number Theoretic Transform (`ntt_3329` & `inv_ntt_3329`)
Because $X^{256} + 1 \equiv \prod_{i=0}^{127} (X^2 - \zeta^{2\text{br}_7(i)+1}) \pmod{3329}$ where $\text{br}_7(i)$ is the 7-bit reversal of $i$:
1. **Forward NTT (`ntt_3329`)**: Executes 7 butterfly layers (`len = 128, 64, 32, 16, 8, 4, 2`) transforming $f \in R_{3329}$ into $\hat{f} = (f_0 + f_1 X, \dots, f_{254} + f_{255} X) \in \bigoplus_{i=0}^{127} \mathbb{Z}_{3329}[X]/(X^2 - \zeta^{2\text{br}_7(i)+1})$.
2. **Base Multiplication (`ntt_base_mul_3329`)**: Multiplies each degree-1 pair $(\hat{a}_{2i}, \hat{a}_{2i+1})$ and $(\hat{b}_{2i}, \hat{b}_{2i+1})$ modulo $X^2 - \gamma_i$ where $\gamma_i = \zeta^{2\text{br}_7(i)+1} \bmod 3329$:
   $$\hat{c}_{2i} = (\hat{a}_{2i}\hat{b}_{2i} + \hat{a}_{2i+1}\hat{b}_{2i+1}\gamma_i) \bmod 3329, \qquad \hat{c}_{2i+1} = (\hat{a}_{2i}\hat{b}_{2i+1} + \hat{a}_{2i+1}\hat{b}_{2i}) \bmod 3329$$
3. **Inverse NTT (`inv_ntt_3329`)**: Executes 7 Gentleman-Sande inverse butterfly layers and scales each coefficient by $128^{-1} \equiv 3303 \pmod{3329}$.

### 3.3 Key Generation, Encapsulation & Fujisaki-Okamoto IND-CCA2 Decapsulation
- **Key Generation (`QLXEngine.keygen`)**:
  1. Absorbs 32-byte random seed $d$ and the 64-byte `QPKD-Argon` passphrase policy witness $W_{\text{policy}}$ into `qSponge-512` to derive $(\rho, \sigma) \in \{0,1\}^{256} \times \{0,1\}^{256}$.
  2. Rejection-samples the $k \times k$ matrix $\hat{\mathbf{A}} \in R_{3329}^{k \times k}$ uniformly from $\rho$.
  3. Samples secret vector $\mathbf{s} \in R_{3329}^k$ and error vector $\mathbf{e} \in R_{3329}^k$ from the Centered Binomial Distribution $\text{CBD}_2(\sigma)$ with coefficients in $\{-2, -1, 0, 1, 2\} \pmod{3329}$.
  4. Computes the Module-LWE public key in NTT domain:
     $$\hat{\mathbf{t}} = \hat{\mathbf{A}} \circ \text{NTT}(\mathbf{s}) + \text{NTT}(\mathbf{e}) \pmod{3329}$$
  5. Packs $\hat{\mathbf{t}}$ at 12 bits/coefficient ($384k$ bytes) + $\rho$ ($32$ bytes) into `ek`, and packs $\hat{\mathbf{s}}$ ($384k$ bytes) + `ek` + $H(\text{ek})$ + implicit rejection seed $z$ into `dk`.
- **Encapsulation (`QLXEngine.encaps`)**:
  1. Samples $m \leftarrow \{0,1\}^{256}$ and computes $(K, r) = \text{qSponge-512}(\text{"CALYX-QLX-FO-G|"} \,\|\, m \,\|\, H(\text{ek}))$.
  2. Samples $\mathbf{r}_v, \mathbf{e}_1 \in R_{3329}^k$ and $e_2 \in R_{3329}$ from $\text{CBD}_2(r)$ and computes:
     $$\mathbf{u} = \text{NTT}^{-1}(\hat{\mathbf{A}}^T \circ \text{NTT}(\mathbf{r}_v)) + \mathbf{e}_1 \pmod{3329}$$
     $$v = \text{NTT}^{-1}(\hat{\mathbf{t}}^T \circ \text{NTT}(\mathbf{r}_v)) + e_2 + \text{Decompress}_1(m) \pmod{3329}$$
  3. Compresses $(\mathbf{u}, v)$ to $(d_u, d_v)$ bits per coefficient to form ciphertext `ct`.
- **Decapsulation (`QLXEngine.decaps`)**:
  1. Decompresses $(\mathbf{u}, v)$ and computes the noisy difference polynomial:
     $$w = v - \text{NTT}^{-1}(\hat{\mathbf{s}}^T \circ \text{NTT}(\mathbf{u})) \pmod{3329}$$
  2. Because $\mathbf{v} - \mathbf{s}^T\mathbf{u} = \text{Decompress}_1(m) + \mathbf{e}^T\mathbf{r}_v + e_2 - \mathbf{s}^T\mathbf{e}_1 \pmod{3329}$ and the small noise polynomial has infinity norm strictly bounded below $q/4 \approx 832$, 1-bit compression $m' = \text{Compress}_1(w)$ recovers $m$ exactly.
  3. Re-derives $(K', r') = \text{qSponge-512}(\text{"CALYX-QLX-FO-G|"} \,\|\, m' \,\|\, H(\text{ek}))$, re-encrypts $\text{ct}' = \text{Enc}(\text{ek}, m', r')$, and checks $\text{ct} \stackrel{?}{=} \text{ct}'$ in constant time (`hmac.compare_digest`). If equal, returns $K'$; otherwise returns the implicit-rejection key $\text{qSponge-XOF}(\text{"CALYX-QLX-FO-REJECT|"} \,\|\, z \,\|\, \text{ct}, 32)$.

---

## 4. `QVS` Lattice Fiat-Shamir with Aborts Over $R_{8380417} = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$

### 4.1 Ring Parameters & Complete 8-Layer NTT
Aligned with the prime modulus structure of [FIPS 204 (ML-DSA)](https://www.quantumsecuritydefence.com/insights/fips-204-ml-dsa/), OpenQPEP's `QVSEngine` operates over $R_Q = \mathbb{Z}_Q[X]/(X^{256}+1)$ with prime modulus $Q = 8380417 = 2^{23} - 2^{13} + 1$ and primitive 512th root of unity $\zeta_Q = 1753 \bmod Q$ ($\zeta_Q^{256} \equiv -1 \pmod{Q}$):

| Signature Tier | Matrix Dimensions $(k, \ell)$ | Secret Bound $\eta$ | Challenge Weight $\tau$ | Norm Margin $\beta = \tau\eta$ | Mask Bound $\gamma_1$ | Rounding Bound $\gamma_2$ | Public Key | Signature Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`QVS-65`** | $(3, 2)$ | $2$ | $39$ | $78$ | $2^{19}$ | $261,888$ | $2,336\text{ B}$ | $1,600\text{ B}$ |
| **`QVS-87` (Default)** | $(4, 3)$ | $2$ | $49$ | $98$ | $2^{19}$ | $261,888$ | $3,104\text{ B}$ | $2,368\text{ B}$ |
| **`QVS-128`** | $(6, 5)$ | $2$ | $60$ | $120$ | $2^{19}$ | $261,888$ | $4,640\text{ B}$ | $3,904\text{ B}$ |

### 4.2 KeyGen, Rejection-Sampled Signing, and Verification
- **Key Generation (`QVSEngine.keygen`)**:
  Samples short secret vectors $\mathbf{s}_1 \in [-\eta, \eta]^\ell$ and $\mathbf{s}_2 \in [-\eta, \eta]^k$, expands $\hat{\mathbf{A}} \in R_Q^{k \times \ell}$ from $\rho$, and computes:
  $$\mathbf{t} = \text{NTT}^{-1}(\hat{\mathbf{A}} \circ \text{NTT}(\mathbf{s}_1)) + \mathbf{s}_2 \pmod{Q}$$
- **Signing (`QVSEngine.sign`)**:
  Repeats rejection sampling over masking vectors $\mathbf{y} \in [-\gamma_1+1, \gamma_1]^\ell$:
  1. Computes $\mathbf{w} = \text{NTT}^{-1}(\hat{\mathbf{A}} \circ \text{NTT}(\mathbf{y})) \pmod{Q}$ and decomposes each coefficient $w \equiv w_1 \cdot (2\gamma_2) + w_0 \pmod{Q}$ with $w_0 \in (-\gamma_2, \gamma_2]$.
  2. Hashes $\tilde{c} = \text{qSponge-XOF}(\text{"CALYX-QVS-CHALLENGE|"} \,\|\, \mu \,\|\, \mathbf{w}_1, 64)$ and samples sparse challenge polynomial $c = \text{SampleInBall}(\tilde{c}, \tau) \in R_Q$ with $\tau$ entries in $\{-1, +1\}$.
  3. Computes response vector $\mathbf{z} = \mathbf{y} + c\mathbf{s}_1 \pmod{Q}$.
  4. **Rejection Condition**: Rejects and resamples if $\|\mathbf{z}\|_\infty \ge \gamma_1 - \beta$, or $\|\text{LowBits}(\mathbf{w} - c\mathbf{s}_2, 2\gamma_2)\|_\infty \ge \gamma_2 - \beta$, or $\text{HighBits}(\mathbf{w} - c\mathbf{s}_2, 2\gamma_2) \ne \mathbf{w}_1$.
- **Verification (`QVSEngine.verify`)**:
  Checks $\|\mathbf{z}\|_\infty < \gamma_1 - \beta$, reconstructs $\mathbf{w}' = \text{NTT}^{-1}(\hat{\mathbf{A}} \circ \text{NTT}(\mathbf{z}) - \hat{c} \circ \text{NTT}(\mathbf{t})) \pmod{Q}$, extracts $\mathbf{w}_1' = \text{HighBits}(\mathbf{w}', 2\gamma_2)$ (which equals $\text{HighBits}(\mathbf{w} - c\mathbf{s}_2, 2\gamma_2) = \mathbf{w}_1$ by the algebraic identity $\mathbf{A}\mathbf{z} - c\mathbf{t} = \mathbf{A}(\mathbf{y}+c\mathbf{s}_1) - c(\mathbf{A}\mathbf{s}_1+\mathbf{s}_2) = \mathbf{w} - c\mathbf{s}_2$), and verifies $\tilde{c} \stackrel{?}{=} \text{qSponge-XOF}(\text{"CALYX-QVS-CHALLENGE|"} \,\|\, \mu \,\|\, \mathbf{w}_1', 64)$.
