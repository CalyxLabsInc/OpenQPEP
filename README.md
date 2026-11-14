# Calyx QPEP: Calyx Quantum Proof Encryption Protocol

**Calyx QPEP** (`CALYX-QPEP/1.0`) is an open-source post-quantum encryption, digital signature, and `.qpkrf` key-ring protocol created by **Calyx Labs Inc.**

## Proprietary Cryptographic Suite

- **`QLX-1024 + HGC-448`**: 1024-Dimensional Quantum Lattice Exchange fused with Hyper-Goldilocks Curve 448.
- **`QVS-87 + qSponge-512`**: 87-Rank Quantum Vector Signatures over 512-bit Quantum Sponge transcripts.
- **`Calyx-Cascade-512` (`CC-512`)**: 512-Bit Dual-Stream Authenticated Matrix Cipher with 64 KiB streaming frames.
- **`QPKD-Argon`**: Mandatory 12+ character passphrase key-ring protection (`>=2` numbers, `>=4` specials, `>=2` uppercase, `>=4` lowercase).
- **`.qpkrf` (Quantum Proof Key Ring File)**: Self-certifying public and private key ring format.
