# Calyx Open Source License
**Version 1.0.0**

**Copyright (c) 2026 Tristen Martinez, Calyx Labs Inc. All Rights Reserved.**

---

## 1. Definitions

* **"Licensor"** refers to Tristen Martinez (Sole Architect) and Calyx Labs Inc.
* **"Original Work"** refers to the Calyx Quantum Proof Encryption Protocol (`Calyx QPEP`), the `Calyx QPEP Client` (`com.calyxlabs.qpepclient`), the `.qpkrf` (Quantum Proof Key Ring File) schema, and all associated cryptographic suites, specifications, test vectors, and source code—specifically including `QLX-768`, `QLX-1024`, `QLX-2048`, `HGC-448`, `QVS-65`, `QVS-87`, `QVS-128`, `qSponge-512`, `Calyx-Cascade-512` (`CC-512`), and `QPKD-Argon`.
* **"Derivative Work"** refers to any work, software, fork, translation, or adaptation that is based upon or incorporates all or part of the Original Work.
* **"You"** (or **"Licensee"**) refers to any individual or legal entity exercising permissions granted by this License.
* **"Trademarks"** refers to the names, marks, and identifiers owned by the Licensor, including but not limited to: `"Calyx QPEP"`, `"Calyx Quantum Proof Encryption Protocol"`, `"Calyx Labs"`, `"Calyx Labs Inc."`, `"QPX"`, `"QLX"`, `"HGC-448"`, `"QVS"`, `"qSponge-512"`, `"Calyx-Cascade-512"`, `"QPKD-Argon"`, and `".qpkrf"`.

---

## 2. Grant of Copyright License

Subject to the terms and conditions of this License, the Licensor hereby grants You a worldwide, royalty-free, non-exclusive, perpetual license to reproduce, prepare Derivative Works of, publicly display, publicly perform, and distribute the Original Work and such Derivative Works in Source or Object form, provided that You strictly comply with Sections 3, 4, and 5 of this License.

---

## 3. Mandatory Attribution & Credit Preservation

You may distribute copies of the Original Work or Derivative Works in any medium, with or without modifications, provided that You meet all of the following conditions:

1. **Retention of Legal Notices:** You must retain, unmodified, a copy of this `LICENSE.md` file and all copyright, authorship, patent, trademark, and attribution notices in every source file and specification document of the Original Work.
2. **Visible Credit in Distributions:** Any distribution of the Original Work or a Derivative Work (whether in source code, compiled binary, mobile application, CLI tool, or web application) must prominently display the following attribution notice in its documentation, `README`, and user-facing "About" or legal notices screen:
   > *"Powered by the Calyx Quantum Proof Encryption Protocol (Calyx QPEP), originally architected and developed by Tristen Martinez (Calyx Labs Inc.)."*
3. **Modification Tracking:** If You modify any file from the Original Work, You must cause the modified files to carry prominent notices stating that You changed the files and the date of any change, while preserving the original copyright header crediting Tristen Martinez and Calyx Labs Inc.
4. **Checksum & Manifest Integrity:** You may not misrepresent modified files as unmodified Original Work or falsify `qSponge-512` manifest checksums associated with official Calyx Labs Inc. releases.

---

## 4. Protocol Integrity & Sovereign Security Requirements

To protect users from weakened or compromised cryptographic implementations claiming compatibility with the Original Work:

1. **Standard Compliance:** No software or Derivative Work may claim to be *"Calyx QPEP Compliant"* or *"QPX Compatible"* unless it passes 100% of the official `CALYX-QPEP_Test_Vectors.json` verification suite and enforces the mandatory `QPKD-Argon` passphrase policy (`12+` characters: `>=2` numbers, `>=4` special characters, `>=2` uppercase letters, `>=4` lowercase letters) when wrapping `.qpkrf` secret key rings.
2. **Prohibition on Telemetry:** Any Derivative Work that introduces network telemetry, remote key exfiltration, or third-party data collection must clearly disclose such modifications to end users and is strictly prohibited from using any Calyx Labs Inc. Trademarks.

---

## 5. Trademark & Naming Restrictions

This License does **not** grant permission to use the Trademarks of the Licensor, except as required for reasonable and customary use in describing the origin of the Original Work and fulfilling the attribution requirements in Section 3.

1. **Fork Rebranding:** If You distribute a modified version or Derivative Work of the Original Work, You must distribute it under a distinct project name and package identifier (it may not use `com.calyxlabs.*` or be titled `"Calyx QPEP"` or `"Calyx QPEP Client"`).
2. **Permitted Fork Statement:** Modified forks may state: *"Forked from Calyx QPEP by Tristen Martinez (Calyx Labs Inc.)"* to satisfy attribution, provided it is made clear that the fork is not an official release of Calyx Labs Inc.

---

## 6. Termination

If You fail to comply with any term of this License (including but not limited to stripping copyright notices, failing to credit Tristen Martinez / Calyx Labs Inc., or violating the Trademark restrictions), your rights under this License shall terminate automatically and immediately without notice.

---

## 7. Disclaimer of Warranty & Limitation of Liability

THE ORIGINAL WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL TRISTEN MARTINEZ OR CALYX LABS INC. BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE ORIGINAL WORK OR THE USE OR OTHER DEALINGS IN THE ORIGINAL WORK.