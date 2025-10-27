# SecureVault Password Manager

SecureVault is a secure, local-only password manager built in Python with a PyQt5-based GUI. It enables users to store, manage, and import passwords on their devices, with all data encrypted using AES-256-GCM and key derivation via Argon2id (preferred) or PBKDF2. No data is transmitted over the network, ensuring privacy. The application is designed for personal use and requires explicit user consent for sensitive operations like browser imports and biometric authentication.

**Legal Notice**: Use SecureVault only on devices you own or administer, with explicit consent. It is not intended for extracting passwords from unauthorized devices. Consent dialogs are shown before browser imports or biometric setup.

- **Purpose**: Local password management with strong encryption and optional biometric authentication, no network access.
- **Version**: 1.0.0.
- **Author**: Dipta Roy.

## Table of Contents
- [Features](#features)
- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Usage](#usage)
- [How Encryption Works](#how-encryption-works)
- [Security](#security)
  - [False Positive Antivirus Warnings](#false-positive-antivirus-warnings)
  - [Biometric Authentication Risks](#biometric-authentication-risks)
  - [Backup and Export Safety](#backup-and-export-safety)
- [Troubleshooting](#troubleshooting)
- [Technical Details](#technical-details)
  - [Application Structure](#application-structure)
  - [Build Process](#build-process)
- [Contributing](#contributing)
- [License](#license)

## Features
- **Secure Storage**: Passwords are stored in an encrypted vault file (`~/.securevault/vault.enc`) using AES-256-GCM.
- **Password Management**: Add, edit, delete, search, and generate strong passwords with strength validation.
- **Imports**:
  - Browser: Chrome/Edge on Windows (via DPAPI decryption); Firefox and non-Windows require manual export.
  - CSV: Supports common formats (site, username, password, URL, notes).
- **Biometric Authentication**: Windows Hello (fingerprint/PIN), Touch ID (macOS), or fingerprint (Linux) for quick unlocking, with master password fallback.
- **Auto-Lock**: Configurable timeout (default 5 minutes) to secure the vault.
- **Password Generator**: Customizable passwords (8–128 characters, configurable types).
- **Export/Backup**: Encrypted backups (`.enc`) or unencrypted CSV (with warning).
- **Cross-Platform**: Full support on Windows; partial on macOS/Linux (limited browser imports).
- **User Interface**: Modern PyQt5 GUI with tabs for entries, settings, and imports.

## Getting Started

### Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/dipta-roy/SecureVault.git
   cd SecureVault
   ```
2. **Create and Activate a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Unix-like
   # Or: venv\Scripts\activate (Windows)
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   - Requires Python 3.10+ (tested on 3.12).
   - Dependencies: `PyQt5`, `cryptography`, `argon2-cffi` (optional, recommended), `pywin32` (Windows, **essential for Windows security features**).
   - No internet required post-installation.

4. **Run from Source**:
   ```bash
   python -m app.main
   ```

5. **Build Executable (Windows)**:
   - Use `build.bat` to create a standalone executable:
     ```bash
     build.bat
     ```
   - Outputs `dist\SecureVault.exe` (no Python install needed on target machine).
   - See [Build Process](#build-process) for details.

### Usage
1. **First Launch**:
   - Set a strong master password (12+ characters, mixed case, numbers, symbols).
   - Optionally enable biometric authentication (e.g., Windows Hello fingerprint/PIN) via Settings.
2. **Managing Passwords**:
   - **Add**: Click "Add Entry" to input site, username, password, URL, and notes.
   - **Edit/Delete**: Select an entry and use the respective buttons.
   - **Generate**: Use the password generator (customizable length/types); copies to clipboard.
3. **Imports**:
   - Go to Import tab, select browser (Chrome/Edge on Windows) or CSV file, and confirm consent.
4. **Biometric Setup**:
   - In Settings, enable biometrics (if available). Set a PIN as fallback or use fingerprint/Touch ID.
   - Biometrics store the master password securely in `~/.securevault/biometric.json`.
5. **Backup/Export**:
   - **Backup**: In Settings > Backup, save an encrypted `.enc` file.
   - **Export**: Export to CSV (unencrypted; warning shown).
6. **Locking**: Click the lock button or wait for the auto-lock timer (default 5 minutes).

The vault is stored at `~/.securevault/vault.enc` (e.g., `C:\Users\<YourName>\.securevault` on Windows) by default.

## How Encryption Works
SecureVault protects your passwords by scrambling them (encryption) and only unscrambling them with your master password or biometrics (decryption). Here’s a simple explanation:

1. **Creating the Encryption Key**:
   - Your **master password** (e.g., "MyStrongPass123!") is combined with a **salt** (a unique 32-byte random value) using **Argon2id** (or **PBKDF2** if Argon2 is unavailable).
   - Argon2id is slow and memory-intensive (64 MiB, 2 iterations), making it hard for hackers to guess your password.
   - The result is a 256-bit (32-byte) key used for encryption, never stored.

2. **Storing Passwords**:
   - Passwords are saved as JSON (e.g., `{"site": "testsite.com", "username": "user", "password": "secret"}`) and encrypted with **AES-256-GCM**, a strong encryption standard.
   - The vault file (`~/.securevault/vault.enc`) contains:
     - **Magic Bytes**: `SVPM` (4 bytes, identifies the file).
     - **Version**: 4 bytes (current: 1).
     - **Salt**: 32 bytes (unencrypted, safe to expose).
     - **Nonce**: 12 bytes (unencrypted, random per encryption; a *nonce* is a one-time number ensuring unique encryption).
     - **Tag**: 16 bytes (unencrypted, verifies data integrity; a *tag* detects tampering).
     - **Encrypted Data**: Your passwords (JSON, scrambled).
   - **Analogy**: The vault is a locked safe. The salt is a visible label, and your password is the key. The nonce and tag ensure only you can open it correctly.

3. **Unlocking the Vault**:
   - Enter your master password or use biometrics to retrieve it.
   - The app regenerates the key using the salt and password, then uses it with the nonce to unscramble the data.
   - If the password is wrong or the file is tampered with, the tag check fails, and access is denied.
   - After unlocking, data is held in memory; it’s cleared on lock/close.

4. **Saving Changes**:
   - Updates are re-encrypted with a new nonce and saved atomically to prevent corruption.

**Pro Tip**: Use a strong, unique master password. If lost, data is unrecoverable.

## Security
- **Local-Only**: No network calls or telemetry (verifiable via packet sniffing).
- **Encryption**: AES-256-GCM (NIST SP 800-38D) with Argon2id key derivation.
- **Best Practices**: Constant-time comparisons, memory zeroing (limited by Python’s garbage collector), and consent dialogs.
- **File Security**: Vault and biometric files (`auth.json`, `biometric.json`) use restrictive permissions (owner-only read/write) on all supported platforms (Windows, macOS, Linux).

### False Positive Antivirus Warnings
Antivirus software may flag SecureVault due to:
- **Behavior**: Accessing browser password databases (e.g., Chrome’s `Login Data`) or compiling C# scripts for Windows Hello mimics malware.
- **PyInstaller**: Bundled executables resemble packed malware.
- **Why It’s Safe**:
  - Requires user consent for imports and biometrics.
  - No network activity; all operations are local.
  - Temporary files (e.g., C# scripts) are deleted.
  - Open-source: Review code at `app/`.
- **Mitigation**: Add an antivirus exception or build from source.

### Biometric Authentication Risks
- **Dependency**: Relies on OS credential stores (e.g., Windows Hello, Touch ID), which could be compromised if the OS is.
- **PIN Storage**: PINs are hashed (PBKDF2-HMAC-SHA256) in `~/.securevault/auth.json`, but a weak PIN reduces security.
- **Mitigation**: Use strong device security (e.g., BitLocker, secure boot); choose a strong PIN; disable biometrics if concerned.

### Backup and Export Safety
- **Encrypted Backups**: Safe (`vault.enc` copies); use the same master password.
- **CSV Exports**: Unencrypted; store securely or delete after use.
- **Mitigation**: Consider encrypting CSV exports externally; avoid storing on shared drives.

## Troubleshooting
- **Antivirus Flags**: Add `dist\SecureVault.exe` to your antivirus allowlist or build from source.
- **Build Failures**:
  - Ensure Python 3.10+ and `requirements.txt` dependencies are installed.
  - Check for `password_manager.spec` in the repository root.
  - Disable antivirus during build if PyInstaller is blocked.
- **Biometric Issues**:
  - Verify biometric hardware (e.g., fingerprint reader) is configured in OS settings.
  - Reset PIN via Settings if authentication fails.
- **Vault Access Errors**:
  - Check `~/.securevault/vault.enc` exists and is not corrupted.
  - Ensure correct master password; no recovery if lost.
- **Logs**: Check `~/.securevault/logs/audit.log` for errors (e.g., failed logins).

## Technical Details
### Application Structure
- **`app/__init__.py`**: Defines version (1.0.0) and author.
- **`app/biometric.py`**: Implements Windows Hello (fingerprint/PIN), Touch ID (macOS), or fingerprint (Linux).
- **`app/browser_import.py`**: Imports from Chrome/Edge (Windows) or CSV files.
- **`app/crypto.py`**: Handles AES-256-GCM encryption, Argon2id/PBKDF2 key derivation.
- **`app/main.py`**: Application entry point; initializes Qt and storage.
- **`app/storage.py`**: Manages `vault.enc` (load/save, lock/unlock).
- **`app/ui.py`**: Defines GUI (login, main window, settings).
- **`app/utils.py`**: Provides utility functions, including Windows-specific file permission handling.

### Build Process
- **File**: `build.bat` (Windows).
- **Steps**:
  - Verifies Python 3.10+.
  - Creates/activates virtual environment (`venv`).
  - Installs `requirements.txt` and PyInstaller.
  - Cleans `build`/`dist` folders.
  - Builds `dist\SecureVault.exe` using `password_manager.spec`.
  - Creates `Run SecureVault.bat` for easy launch.
- **Notes**:
  - Requires `password_manager.spec` (PyInstaller configuration).
  - Executable is self-contained; no Python needed on target machines.
  - May trigger antivirus warnings.

## License
Free and unencumbered software released into the public domain. See [UNLICENSE](UNLICENSE).