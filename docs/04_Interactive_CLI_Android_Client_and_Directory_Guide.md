# OpenQPEP Interactive CLI, Android Client & Public Key Directory Guide (`Beta Version 0.1.8`)

**Protocol:** **OpenQPEP by Calyx Labs Inc.** (`Beta Version 0.1.8`)  
**Android Application:** **Calyx QPEP Client** (`Beta Version 0.1.8`)  
**Creator & Lead Architect:** **Tristen Martinez** ([Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEP/))  
**Public Key Registry:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  

---

## 1. Using the Interactive Blue-Text OpenQPEP CLI (`openqpep`)

Starting in `Beta Version 0.1.5` / `0.1.8`, **OpenQPEP** includes an interactive, blue-themed terminal shell that lets users and developers execute every cryptographic workflow using plain English commands—without writing boilerplate Python scripts or memorizing long flag strings.

### 1.1 Launching the Interactive CLI
```bash
pip install -e .
openqpep
# Or run directly via Python module:
python3 -m calyx_qpep.cli
```

### 1.2 Plain-English Interactive Commands

| English Command | Interactive Workflow & Behavior |
| :--- | :--- |
| **`Create Key`** | Replies with `Specify Key Type:` (`1. QLX-1024 + QVS-87 Sovereign Hybrid`, `2. QLX-2048 + QVS-128 Ultra-Grid`, `3. QLX-768 + QVS-65 Velocity`), then prompts `Set Key Name:`, `Set Key Email:`, `Set Key Comment:`, and `Set Key Passphrase:` (with live character-class validation), generates the lattice + `HGC-448` keypair, saves it to `~/.openqpep/keyring.json`, and offers one-step publishing to `https://qpepkeys.calyxlabsinc.org`. |
| **`List Keys`** | Displays all Personal Key Pairs and Receiver Public Keys stored in your local keyring along with their `QLX`/`QVS` suite and 64-character **Key Hash**. |
| **`Key Details <KeyName>`** | Displays full key health status, identity metadata, 4-character grouped **Key Hash**, and the `.qpkrf` Public Key Block. |
| **`Export Public <KeyName>`** | Exports `<KeyName>_public.qpkrf` without requiring a passphrase. |
| **`Export Private <KeyName>`** | Prompts for the key's mandatory `QPKD-Argon` passphrase, verifies and unlocks the secret key bundle, and writes `<KeyName>_private.qpkrf`. |
| **`Import Key <FilePath.qpkrf>`** | Imports a `.qpkrf` file (automatically prompting for a passphrase only if the file is a `PRIVATE_KEY_RING`), verifies its conjunctive self-signature and `integrity_mac`, and saves it to the keyring. |
| **`Delete Key <KeyName>`** | Confirms and removes the specified key from your local keyring. |
| **`Encrypt Text`** | Prompts you to select your **Encrypting Key**, enter its passphrase, select the **Recipient Key**, and type your plaintext message; outputs an armored `.qpep` packet and optionally saves it to disk. |
| **`Decrypt Text`** | Prompts you to select your **Decrypting Key**, enter its passphrase, and provide a `.qpep` file or armored block; verifies the `qSponge-512` transcript MAC, decrypts the `CC-512` frames, and verifies the sender's embedded signature. |
| **`Encrypt File` / `Decrypt File`** | Encrypts any binary or text file into a streaming `.qpep` packet or decrypts a `.qpep` packet back to the original file. |
| **`Create Signature`** | Prompts for your **Signing Key**, passphrase, and message, and produces a self-contained `CALYX QPEP ATTACHED SIGNATURE` with the message sealed inside. |
| **`Verify Signature`** | Verifies an Attached Signature automatically across all keys in your keyring and extracts the verified message. |
| **`Publish Key <KeyName>`** | Publishes a key's public `.qpkrf` block directly to [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org). |
| **`Search Directory <Query>`** | Searches [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org) by **Key Hash**, owner name, or email. |

---

## 2. Calyx QPEP Client Android Application (`Beta Version 0.1.8`)

The **Calyx QPEP Client** Android application (`com.calyxlabs.qpepclient`) supports Android 10 (`API 29`) through Android 17 (`API 37`, aligned with modern [Android Target SDK Requirements](https://targetsdk.com/) and [Android 17 Compatibility Guidelines](https://medium.com/@zobaer53/bringing-a-3-year-old-android-app-to-android-17-0da7e2a7c457)):

- **Auto-Launch Setup Wizard**: Automatically opens the **Setup Wizard** whenever the hardware keyring has `0` keys.
- **Interactive Key Details View**: Tapping any key in **Manage My Keys** or **Manage Receiver Keys** opens the full Key Details view with a live scannable QR code, one-tap 64-character **Key Hash** copy with toast notification, key deletion, directory sync, quick **Encrypt File** / **Encrypt Text** shortcuts, and a passphrase-gated **QPKRF Private Key Vault**.
- **Native Android Files Integration (`ACTION_OPEN_DOCUMENT` & `ACTION_CREATE_DOCUMENT`)**: Tapping **Choose File** or **Save .qpkrf** dispatches native Android storage intents via `QpepWebClient` and `MainActivity.onActivityResult` so users can pick and save `.qpkrf` and `.qpep` files directly in the Android **Files** app.
- **Full On-Device Post-Quantum Engine**: Runs the complete 24-round `Keccak-f[1600]` sponge, 7-layer NTT `QLX` Module-LWE engine, 8-layer NTT `QVS` Lattice Fiat-Shamir with Aborts signature engine, and `CC-512` (`AES-256-GCM` + `ChaCha20-Poly1305`) cascade locally on the device.

---

## 3. Public Key Directory Server (`https://qpepkeys.calyxlabsinc.org`)

The zero-dependency Python 3 + SQLite3 directory server (`directory_server/app.py`) runs behind a Cloudflare Zero Trust Tunnel (`cloudflared`) on `127.0.0.1:8443` and exposes four REST endpoints:
- `GET /api/v1/health`: Returns live server and protocol status (`OpenQPEP/Beta-0.1.8`).
- `POST /api/v1/keys/publish`: Validates that the uploaded `.qpkrf` block is a `PUBLIC KEY RING` (rejecting any private key ring) and indexes it by 64-character `key_hash`, `name`, and `email`.
- `GET /api/v1/keys/search?q=<query>`: Searches registered public keys by **Key Hash**, name, or email.
- `GET /api/v1/keys/<KEY_HASH>?download=1`: Downloads the raw `.qpkrf` public key file.
