# SecureVault Password Manager

SecureVault is a secure, local password manager built in Python using PyQt5 for the user interface. It allows users to store, manage, and import passwords securely on their own devices. All data is encrypted locally using AES-256-GCM with key derivation via Argon2id (preferred) or PBKDF2, and never transmitted over the network. The application is designed for personal use only and requires explicit user consent for sensitive operations like browser password imports.

**Important Legal Notice:** This tool must only be used on devices you own or administer, with explicit consent. It is not intended for extracting or exfiltrating passwords from unauthorized devices. The app displays a consent dialog before fetching browser passwords.

## Features

- **Secure Storage:** Passwords are stored in an encrypted vault file (`.enc`) using strong cryptography.
- **Password Management:** Add, edit, delete, search, and view passwords with features like password generation and strength checking.
- **Import Support:**
  - Browser imports: Chrome and Edge on Windows (with decryption using Windows DPAPI). Firefox and other platforms require manual export.
  - CSV imports: Supports common formats from other password managers (e.g., site, username, password, URL, notes).
- **Biometric Authentication:** Supports Windows Hello (fingerprint/PIN) for quick unlocking, with fallback to master password.
- **Auto-Lock:** Configurable timeout to automatically lock the vault.
- **Password Generator:** Creates strong, customizable passwords.
- **Export/Backup:** Export to CSV and create encrypted backups.
- **Cross-Platform:** Primarily tested on Windows, with partial support for macOS and Linux (browser imports limited on non-Windows).
- **User Interface:** Modern PyQt5-based GUI with tabs for entries, settings, and imports.

## Application Structure

The application is structured as a Python package under the `app/` folder. Here's an overview of the key files and their roles:

- **`__init__.py`**: Package initializer with version and author info.
- **`biometric.py`**: Handles biometric authentication (e.g., Windows Hello fingerprint/PIN fallback). Checks for availability and stores/retrieves secrets securely.
- **`browser_import.py`**: Manages password imports from browsers (Chrome, Edge on Windows) and CSV files. Includes header mapping for flexible CSV parsing.
- **`crypto.py`**: Core cryptographic operations, including key derivation (Argon2 or PBKDF2), AES-256-GCM encryption/decryption, and secure comparisons.
- **`main.py`**: Entry point for the application. Sets up the Qt app, handles vault selection, login, and cleanup.
- **`storage.py`**: Manages the encrypted vault file, including loading/saving entries, unlocking/locking, and master password changes.
- **`ui.py`**: Defines the GUI components, including the main window, dialogs for login/vault selection/entry editing, and settings.

The vault is stored by default in `~/.securevault/vault.enc` (on Unix-like systems) or equivalent on Windows. Entries are serialized as JSON inside the encrypted file.

## Requirements

- Python 3.10+ (tested on 3.12).
- Dependencies (listed in `requirements.txt`): PyQt5, cryptography, argon2-cffi (optional but recommended for stronger key derivation), pywin32 (for Windows biometric and browser imports).
- For building executables: PyInstaller.

No internet access is required; all operations are local.

## Installation  (Manual)

1. Clone the repository:
   ```
   git clone https://github.com/dipta-roy/SecureVault.git
   cd SecureVault
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Unix-like
   # Or on Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Running from Source

```
python -m app.main
```

### Building an Executable (Windows)

The `build.bat` script creates a standalone executable using PyInstaller. It handles the following steps:

- Checks for Python 3.10+.
- Creates/activates a virtual environment.
- Upgrades pip and installs dependencies from `requirements.txt`.
- Installs PyInstaller.
- Cleans previous builds.
- Builds the executable using a spec file (`password_manager.spec` – assumed to exist in the repo root).
- Outputs to `dist/SecureVault.exe`.
- Creates a launch batch file (`dist/Run SecureVault.bat`).

Run the script:
```
build.bat
```

The resulting `dist/` folder contains a self-contained executable (no Python install needed on the target machine). Test it thoroughly, as PyInstaller bundles can sometimes trigger antivirus false positives.

## Usage

1. **First Launch**: Set a strong master password (at least 12 characters, including uppercase, lowercase, numbers, and symbols).
2. **Add Entries**: Use the GUI to add sites, usernames, and passwords. Generated passwords are copied to clipboard securely.
3. **Import Passwords**: Go to the Import tab, select your browser or CSV file, and grant consent.
4. **Lock/Unlock**: Use the lock button or timeout to secure the vault. Biometrics (Windows Hello) can be enabled for quick access.
5. **Export/Backup**: Export encrypted backups or unencrypted CSV (with warning).

The vault file is created at `~/.securevault/vault.enc` by default (cross-platform user directory).

## Security

- **Encryption**: AES-256-GCM for authenticated encryption.
- **Key Derivation**: Argon2id (with PBKDF2 fallback) for password-to-key conversion.
- **No Network**: Fully local; no telemetry or external calls.
- **Best Practices**: Constant-time comparisons, memory zeroing for secrets, and consent for sensitive operations.

## How Encryption and Decryption Work

This section explains the core security process in easy-to-understand terms. SecureVault keeps your passwords safe by turning them into unreadable "scrambled" data (encryption) and unscrambling them only when you unlock it (decryption). Everything relies on your master password—it's the only "key" to your vault.

### 1. **Generating the Encryption Key**

   - **What It Is**: The encryption key is a special 256-bit (32-byte) code used to scramble/unscramble your data. It's not stored anywhere—it's created fresh every time you unlock the vault.
   - **How It's Made** (Step-by-Step):
     1. You enter your **master password** (e.g., "MyStrongPass123!").
     2. The app reads a **salt** from the vault file. The salt is like a unique "spice" that makes your key one-of-a-kind.
     3. The app mixes your master password with the salt using a slow, secure math process called **Argon2id** (the main method) or **PBKDF2** (backup if Argon2 isn't available).
        - **Why Slow?** Argon2id takes time and computer memory on purpose (e.g., 64 MiB of RAM, 3-4 iterations). This makes it super hard for hackers to guess your password with fast computers or GPUs—it could take years!
     4. The result? A strong 256-bit key ready for encryption.
   - **Simple Analogy**: Think of your master password as flour and the salt as sugar. Argon2id is like baking a cake: It combines them slowly to make something new and unique. The same ingredients always make the same cake, but it's hard to reverse-engineer the recipe quickly.
   - **Where the Salt Comes From**: See the "Vault Storage" section below.

   **Pro Tip**: Use a long, random master password. The app checks for strength and suggests improvements.

### 2. **How the Vault Stores Data (Including Keys and Salt)**

   - **The Vault File (`vault.enc`)**: This is your locked "digital safe" stored in `~/.securevault/vault.enc`. It's a binary file (not readable text) containing:
     - **Your Passwords**: Stored as JSON (a simple list like `{"site": "google.com", "username": "user", "password": "secret"}`), but **encrypted** (scrambled).
     - **Salt**: A random 16-byte value generated once when you create the vault. It's stored **unencrypted** at the start of the file (safe because salt isn't secret—it's just random flavor for key-making).
     - **Nonce**: A 12-byte random number for each encryption (also unencrypted; ensures no two encryptions are identical).
     - **Authentication Tag**: A 16-byte "checksum" to detect tampering (unencrypted).
     - **File Structure** (Simplified):
       ```
       [Magic Bytes (4 bytes: "SVLT" ID)] + [Version (4 bytes: e.g., 1)] + [Salt Size (4 bytes)] + [Salt (16 bytes)] + [Nonce Size (4 bytes)] + [Nonce (12 bytes)] + [Tag Size (4 bytes)] + [Tag (16 bytes)] + [Encrypted Data (variable: your JSON passwords)]
       ```
     - Only the **encrypted data** part is protected; the rest is metadata to help unlock it.
   - **No Keys Stored**: The encryption key isn't saved—it's recreated from your master password + salt every time. Biometrics (e.g., fingerprint) just help enter the password securely via Windows.
   - **Simple Analogy**: The vault is like a locked diary. The salt is the diary's cover label (visible but harmless). Your passwords are the pages inside, scrambled with invisible ink that only your master password reveals.
   - **Safety**: Even if someone steals `vault.enc`, they need your master password to unscramble it. The salt prevents "dictionary attacks" where hackers pre-guess common passwords.

### 3. **How Decryption Works**

   - **What It Is**: Decryption is the reverse of encryption—turning scrambled data back into readable passwords.
   - **Step-by-Step Process**:
     1. You enter your **master password** (or use biometrics).
     2. The app opens `vault.enc` and reads the **unencrypted parts**: Salt, nonce, tag, and file ID/version (quick checks to ensure it's a valid vault).
     3. Using the salt + master password, it generates the **encryption key** (same as above).
     4. The app uses the key + nonce to **unscramble the encrypted data** with **AES-256-GCM**:
        - AES-256 is the "scrambler" algorithm (super strong, like a bank vault lock).
        - GCM mode adds a check: It verifies the authentication tag. If it doesn't match (wrong password or tampered file), it fails safely—no access granted.
     5. Success? The app gets plain JSON data, loads it into memory for the GUI, and shows your passwords.
     6. When done (lock or close), it clears the key and data from memory to prevent leaks.
   - **What If Wrong Password?** The tag check fails, and decryption "breaks" harmlessly—you get an error like "Invalid password."
   - **Simple Analogy**: Encryption is like writing in invisible ink; decryption is shining a UV light (your key) to reveal the words. The tag is like a seal—if broken, you know something's wrong.
   - **Re-Encryption on Save**: Any changes (new passwords) update the JSON, re-encrypt it with a fresh nonce, and save back to `vault.enc`.

This process ensures your data is always protected, even if your device is stolen. For technical details, see `app/crypto.py` and `app/storage.py`.

## False Positive Antivirus Warnings

Some antivirus software may flag SecureVault (especially the built executable or during browser imports) as malware. This is a **false positive** for the following reasons:

- **Behavior Similarity to Malware:** The app accesses browser password databases (e.g., Chrome's `Login Data` SQLite file on Windows) and decrypts them using system APIs (like Windows DPAPI via `win32crypt`). This mimics credential-stealing malware, which often targets the same files. However, SecureVault:
  - Requires explicit user consent via a dialog before any import.
  - Only operates on the local device.
  - Does not exfiltrate data (no network code).
  - Cleans up temporary files after use.

- **PyInstaller Bundles:** Executables built with PyInstaller often get flagged because they bundle Python interpreters and libraries, which can resemble packed malware. The script also uses temporary files for compilation (e.g., C# snippets for Windows Hello), which might raise suspicions.

- **Why It's Safe:**
  - Open-source: Review the code yourself.
  - Local-only: All encryption/decryption happens on-device.
  - No hidden features: Legal notices in every file emphasize ethical use.
  - If flagged, add an exception in your antivirus or build from source.

## License

This is free and unencumbered software released into the public domain. See the [UNLICENSE](UNLICENSE) file for details.