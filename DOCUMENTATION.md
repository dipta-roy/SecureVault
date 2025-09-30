# SecureVault Password Manager: Technical Documentation

## Table of Contents
- [1. Overview](#1-overview)
- [2. Architecture](#2-architecture)
  - [Biometric Authentication](#biometric-authentication)
- [3. Encryption Details](#3-encryption-details)
  - [Key Derivation](#key-derivation)
  - [Encryption Algorithm](#encryption-algorithm)
  - [Data Encrypted](#data-encrypted)
- [4. Vault Storage](#4-vault-storage)
  - [File Format and Location](#file-format-and-location)
  - [Salt Details](#salt-details)
  - [Exporting and Backups](#exporting-and-backups)
  - [Encryption Key Management](#encryption-key-management)
- [5. Import/Export Processes](#5-importexport-processes)
  - [Browser Imports](#browser-imports)
  - [CSV Imports and Exports](#csv-imports-and-exports)
- [6. User Interface and Flow](#6-user-interface-and-flow)
- [7. File-by-File Breakdown](#7-file-by-file-breakdown)
  - [init.py](#initpy)
  - [main.py](#mainpy)
  - [crypto.py](#cryptopy)
  - [browser_import.py](#browser_importpy)
  - [storage.py](#storagepy)
  - [ui.py](#uipy)
  - [biometric.py](#biometricpy)
- [8. Build Process](#8-build-process)
- [9. Security Considerations](#9-security-considerations)
  - [False Positive Antivirus Warnings](#false-positive-antivirus-warnings)
  - [Potential Vulnerabilities and Mitigations](#potential-vulnerabilities-and-mitigations)
- [10. Auditing SecureVault](#10-auditing-securevault)
  - [Audit Checklist](#audit-checklist)
  - [Recommended Tools](#recommended-tools)

## 1. Overview
This document provides a comprehensive audit-style analysis of the SecureVault Password Manager, a Python-based application using PyQt5 for its GUI. It covers architecture, encryption, storage, imports/exports, biometric authentication, build process, and file-by-file details, aimed at security auditors reviewing the codebase (`init.py`, `main.py`, `crypto.py`, `browser_import.py`, `storage.py`, `ui.py`, `biometric.py`, `build.bat`).

- **Purpose**: Local password management with strong encryption and optional biometric authentication, no network access.
- **Version**: 1.0.0 (defined in `init.py`).
- **Author**: Dipta Roy.

## 2. Architecture
- **Language and Framework**: Python with PyQt5 for the GUI, following a modular design.
- **Entry Point**: `main.py` initializes the Qt application, sets up storage, and launches the login or main window.
- **Core Components**:
  - **Encryption/Decryption**: `crypto.py` uses the `cryptography` library for AES-256-GCM encryption.
  - **Storage**: `storage.py` manages serialized, encrypted data in `~/.securevault/vault.enc`.
  - **UI**: `ui.py` defines dialogs for login, password management, generation, and settings.
  - **Imports**: `browser_import.py` handles browser and CSV imports.
  - **Biometric Authentication**: `biometric.py` supports fingerprint and PIN authentication.
  - **Initialization**: `init.py` sets metadata (version, author).
- **Security Model**:
  - Local-only: No network access or cloud integration.
  - Threat Model: Protects against unauthorized vault file access; assumes a secure device (no protection against keyloggers or memory dumps).
  - Consent: Browser imports and biometric authentication require explicit user consent via UI dialogs.
  - Logging: Security actions (e.g., login attempts, changes) logged to `~/.securevault/logs/audit.log`.
- **Platform Support**: Windows, macOS, Linux. Browser imports fully supported on Windows for Chrome/Edge; manual on other platforms. Biometric support is Windows Hello (Windows), Touch ID (macOS), or fingerprint (Linux).
- **Dependencies**:
  - Core: `cryptography`, `PyQt5`, `argon2`.
  - Platform: `win32crypt` (Windows), `keyring` (macOS, partially used), `sqlite3`, `shutil`, `ctypes` (biometric support).
- **Error Handling**: Uses try-except blocks; raises exceptions for unsupported operations (e.g., non-Windows browser imports). Edge cases like corrupted vault files or invalid biometric hashes trigger descriptive errors.

### Biometric Authentication
- **Module**: `biometric.py` provides fingerprint and PIN authentication via `BiometricManager` and `WindowsHelloHelper` (Windows-specific).
- **Supported Platforms**:
  - **Windows**: Uses Windows Hello for fingerprint authentication with PIN fallback. Checks biometric availability via WMI (`Win32_Biometric`).
  - **macOS**: Supports Touch ID with password fallback.
  - **Linux**: Supports fingerprint authentication with password fallback.
- **Process**:
  - Attempts fingerprint authentication first; falls back to PIN if unavailable or failed.
  - PIN is hashed using PBKDF2-HMAC-SHA256 (100,000 iterations, fixed salt) and stored in `~/.securevault/auth.json`.
  - Secrets (e.g., master password) can be stored in `~/.securevault/biometric.json` with base64 encoding.
- **Security Features**:
  - Consent required via UI dialogs (e.g., `QMessageBox` for fingerprint, `QInputDialog` for PIN).
  - File permissions set to 600 on non-Windows for `auth.json` and `biometric.json`.
  - Temporary C# files (Windows) are deleted post-authentication.
- **Limitations**: Relies on OS-provided biometric APIs; no protection against compromised OS credential stores.

## 3. Encryption Details
Encryption is managed by `CryptoManager` in `crypto.py` using symmetric encryption with a master password-derived key, following NIST SP 800-38D for AES-GCM.

### Key Derivation
- **Method**:
  - Preferred: Argon2id (via `argon2` library if available). Parameters: `time_cost=2`, `memory_cost=65536` (64 MB), `parallelism=4`, `hash_len=32` bytes. Argon2id is memory-hard, resisting GPU/ASIC attacks (OWASP recommendation).
  - Fallback: PBKDF2-HMAC-SHA256 (via `cryptography`) with 100,000 iterations.
- **Salt**: 32-byte (256-bit) random value generated via `os.urandom()`. Stored unencrypted in the vault file header (safe per cryptographic standards).
- **Key Size**: 32 bytes (256 bits) for AES-256.
- **Process**: `derive_key(password: str, salt: bytes) -> bytes`
  - Encodes password to UTF-8.
  - Uses Argon2’s `hash_secret_raw` or PBKDF2 to derive the key.
- **Security Notes**: Argon2id aligns with modern standards; PBKDF2 is a weaker fallback. No pepper (device-specific secret) is used, limiting resistance to device compromise.

### Encryption Algorithm
- **Cipher**: AES-256-GCM (Galois/Counter Mode) via `cryptography.hazmat.primitives.ciphers`.
- **Nonce**: 12 bytes (96 bits) random via `os.urandom()`, stored in the vault file.
- **Tag**: 16 bytes (128 bits) authentication tag, stored in the vault file.
- **Process**: `encrypt(plaintext: bytes, key: bytes) -> (ciphertext, nonce, tag)`
  - Initializes AES(key) with GCM(nonce).
  - Encrypts plaintext; finalizes with authentication tag.
- **Decryption**: `decrypt(ciphertext, key, nonce, tag) -> plaintext`
  - Uses GCM(nonce, tag); raises `InvalidTag` on tampering.
- **Additional Security**:
  - Constant-time comparison: `secure_compare(a, b)` uses `hmac.compare_digest` to prevent timing attacks (available but not used in core flow).
  - Memory clearing: `clear_bytes(data: bytes)` zeros bytearrays, though Python’s garbage collector limits effectiveness.

### Data Encrypted
- Password entries (site, username, password, URL, notes, dates) are serialized to JSON and encrypted as a single blob.
- Metadata (version, last_modified) is included in the JSON and encrypted.

## 4. Vault Storage
### File Format and Location
- **Location**: `~/.securevault/vault.enc` (`~` is the user’s home directory via `os.path.expanduser("~")`).
  - Directory created via `os.makedirs(app_dir, exist_ok=True)`.
  - Atomic saves: Writes to `.tmp` file, then renames/replaces to prevent corruption.
- **File Permissions**: On non-Windows, set to 600 (owner read/write only) via `os.chmod(stat.S_IRUSR | stat.S_IWUSR)`.
- **File Format**:
  - Magic Bytes: `b'SVPM'` (4 bytes).
  - Version: 4-byte unsigned int (little-endian), current=1.
  - Salt Size: 4-byte unsigned int, followed by 32-byte salt.
  - Nonce Size: 4-byte unsigned int, followed by 12-byte nonce.
  - Tag Size: 4-byte unsigned int, followed by 16-byte tag.
  - Ciphertext: Remainder (encrypted JSON).
- **Additional Files**:
  - `auth.json`: Stores PBKDF2-HMAC-SHA256 hash of PIN for biometric authentication (base64-encoded).
  - `biometric.json`: Stores base64-encoded secrets (e.g., master password) protected by biometric/PIN authentication.
  - Both files are in `~/.securevault/` with 600 permissions on non-Windows.
- **Data Structure**: List of `PasswordEntry` dataclasses (`id`: UUID str, `site`, `username`, `password`, `url`, `notes`, `date_added`, `date_modified` – all strings).
- **Locking**: Vault is "unlocked" in memory post-decryption; locked by clearing `_key` and `_entries`.

### Salt Details
The salt is a 32-byte random value ensuring unique key derivation per vault, protecting against precomputed attacks (e.g., rainbow tables).
- **Generation**: Created once during vault setup using `os.urandom(32)`.
  ```python
  import os
  salt = os.urandom(32)  # 32 bytes of cryptographically secure random data
  ```
- **Storage**: Saved unencrypted in `vault.enc` header (standard practice; salts are not secret).
- **Usage**: Combined with the master password via Argon2id (or PBKDF2) to derive the 256-bit AES key.
- **Security**: Stored only in `vault.enc`, not in memory post-lock or elsewhere (e.g., OS credential manager).

### Exporting and Backups
- **Manual Export**:
  - Copy `~/.securevault/vault.enc` to a new location (e.g., via file explorer or `cp`/`copy`).
  - To use in a new installation, modify `_get_storage_path()` in `main.py` (hardcoded, no UI configuration).
- **Backup Export (UI)**: In Settings > Backup tab:
  - Prompts for save location and filename (default: `securevault_backup_YYYYMMDD_HHMMSS.enc`).
  - Uses `shutil.copy2()` to preserve metadata.
  - Backup is identical to `vault.enc` (same encryption key).
- **Restore**: In Settings > Restore tab:
  - Selects `.enc` file; warns about overwriting; requires restart.
  - Unlocks with the backup’s master password.
- **CSV Export (Unencrypted)**:
  - From main window "Export" button; prompts for CSV location.
  - Headers: `Site,Username,Password,URL,Notes`.
  - Exports passwords in plaintext (security risk; user warned via dialog).

### Encryption Key Management
- **Key Storage**: Never stored; derived on-the-fly from master password and salt during unlock.
  - In memory: Held as `_key: bytes` in `StorageManager` while unlocked.
  - Cleared on lock/close via `crypto.clear_bytes(bytearray(self._key))` and set to None.
- **Master Password**: Entered via UI or retrieved via biometric authentication; never stored or logged.
- **No Key Escrow**: Forgotten passwords render data irrecoverable.

## 5. Import/Export Processes
### Browser Imports (`browser_import.py`)
- **Consent**: Requires UI acknowledgment dialog.
- **Supported Browsers**:
  - **Chrome (Windows)**: Copies `Login Data` SQLite DB from `%LOCALAPPDATA%\Google\Chrome\User Data\Default`; decrypts via `win32crypt.CryptUnprotectData` (DPAPI).
  - **Edge (Windows)**: Similar, from `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`.
  - **Firefox**: Not automated; raises exception directing manual export via `about:logins`.
  - **Chrome (macOS/Linux)**: Not automated; raises exception for manual export via `chrome://settings/passwords`.
- **Process**: Extracts URL, username, password; generates UUID ID; adds to vault via `add_entry()`.

### CSV Imports and Exports
- **CSV Import**:
  - Sniffs delimiter; heuristically maps headers (e.g., `site` to `name`, `site`, etc.).
  - Skips incomplete rows (no site/username/password); generates UUID ID.
- **CSV Export**: Unencrypted, as described in "Exporting and Backups."

## 6. User Interface and Flow (`ui.py`)
- **LoginDialog**: Checks for vault; creates new if absent (enforces strong password: 12+ chars, upper/lower/digit/special). Limits to 5 attempts. Supports biometric authentication via `biometric.py`.
- **MainWindow**: Displays entry table (columns: Site, Username, Password [hidden], Actions). Includes buttons for add/edit/delete/import/export/generate/settings.
  - **Timers**: Auto-lock (default 5 min, configurable); clipboard clear (30 sec).
  - **Copy**: Copies to clipboard; starts clear timer.
  - **Import Dialog**: Consent checkbox; supports browser/CSV; shows progress for large imports.
  - **Generator**: Customizable (length 8-128, char types); copies generated password.
- **SettingsDialog**: Tabs for Security (change password, timeouts), Backup (create/restore), About.
- **ChangeMasterPasswordDialog**: Verifies old password; enforces strong new password.
- **Note**: The provided `ui.py` is truncated, but visible code covers all critical UI logic.

## 7. File-by-File Breakdown
### init.py
- Defines metadata: `__version__ = "1.0.0"`, `__author__ = "SecureVault Team"`.
- Includes legal notice (repeated across files).

### main.py
- **Role**: Application entry point.
- **Key Class**: `PasswordManagerApp`
  - Sets app name, style (‘Fusion’), storage path (`_get_storage_path()`), and SIGINT handler.
- **Methods**:
  - `run()`: Shows LoginDialog; if successful, launches MainWindow and Qt loop.
  - `cleanup()`: Locks storage.
  - `main()`: Enables high DPI, runs app, cleans up.

### crypto.py
- Implements `CryptoManager` for encryption/decryption (see Section 3).
- Includes Argon2id/PBKDF2 fallback, constant-time comparison, memory clearing.

### browser_import.py
- **Classes**:
  - `BrowserImporter`: Handles platform-specific browser imports (see Section 5).
  - `CSVImporter`: Parses CSV files with header mapping and row validation.

### storage.py
- **Classes**:
  - `PasswordEntry`: Dataclass for entries (UUID, site, username, etc.).
  - `StorageManager`: Manages file I/O and encryption (see Section 4).
- **Methods**: `create_new_vault`, `unlock`, `lock`, `add/update/delete/get entries`, `change_master_password`, `_save` (atomic, sets permissions).

### ui.py
- **Classes**:
  - `PasswordStrengthValidator`: Enforces password strength (length>=12, char types).
  - Dialogs: Login, Generator, Import, Edit, Settings, ChangeMasterPassword.
  - `MainWindow`: Core UI with table, buttons, menus, timers, and logging (`_log_action` for login, changes).
- **Security Features**: Clipboard clearing, auto-lock, strong password enforcement, biometric integration.

### biometric.py
- **Role**: Implements biometric and/or PIN authentication.
- **Classes**:
  - **WindowsHelloHelper**: Windows-specific biometric support.
    - Checks biometric availability via WMI (`Win32_Biometric`).
    - Authenticates using Windows Hello via C# script (`credui.dll`) or `ShellExecuteW` with `runas`.
    - Deletes temporary files post-authentication.
  - **BiometricManager**: Manages authentication flow.
    - Attempts fingerprint authentication; falls back to PIN.
    - Stores PIN hash in `auth.json` using PBKDF2-HMAC-SHA256.
    - Manages secrets in `biometric.json` (e.g., master password).
- **Methods**:
  - `authenticate(reason)`: Tries fingerprint, then PIN.
  - `store_secret(key, secret)`: Saves base64-encoded secret.
  - `retrieve_secret(key)`: Retrieves secret if authenticated.
  - `delete_secret(key)`: Deletes secret.
- **Security Features**: Consent dialogs, file permissions (600 on non-Windows), temporary file cleanup.

## 8. Build Process
- **File**: `build.bat` (Windows-specific build script).
- **Purpose**: Creates a standalone executable using PyInstaller.
- **Steps**:
  - Checks for Python 3.10+; exits if not found.
  - Creates/activates a virtual environment (`venv`).
  - Upgrades `pip` and installs dependencies from `requirements.txt`.
  - Installs PyInstaller.
  - Cleans previous build artifacts (`build`, `dist`).
  - Builds executable using `password_manager.spec`, producing `dist\SecureVault.exe`.
  - Creates `Run SecureVault.bat` for easy launching.
- **Output**:
  - Executable: `dist\SecureVault.exe` (includes all dependencies).
  - Success: Displays file size and run instructions.
  - Failure: Lists common issues (e.g., missing dependencies, antivirus interference).
- **Security Notes**:
  - PyInstaller bundles Python interpreter and libraries, increasing executable size.
  - No Python installation required on target machines.
  - Users must keep master password secure and back up `vault.enc`.
 
## 9. Security Considerations
### False Positive Antivirus Warnings
Antivirus software may flag SecureVault executables or browser imports due to:
- **Behavior**: Accesses browser password databases (e.g., Chrome’s `Login Data` SQLite) and decrypts via system APIs (e.g., `win32crypt`), resembling credential-stealing malware. Biometric authentication may also trigger flags.
- **PyInstaller**: Bundled executables resemble packed malware; temporary files (e.g., for Windows Hello) raise suspicions.
- **Why It’s Safe**:
  - Requires explicit user consent for imports and biometric authentication.
  - Local-only; no network code (verifiable via packet sniffing).
  - Cleans up temporary files.
  - Open-source: Code is auditable.
  - **Mitigation**: Add antivirus exception or build from source.

### Potential Vulnerabilities and Mitigations
- **Predictable Storage Locations**: `~/.securevault/` files (`vault.enc`, `auth.json`, `biometric.json`) could be targeted by malware.
  - **Mitigation**: File permissions (600 on non-Windows) restrict access; consider user-configurable paths in future versions.
- **Plaintext CSV Exports**: Unencrypted exports pose a risk if mishandled.
  - **Mitigation**: Strengthen warning dialogs; consider optional encryption for exports.
- **No Pepper in Key Derivation**: Limits resistance to device compromise.
  - **Mitigation**: Future versions could add device-specific secrets (e.g., via TPM).
- **Memory Clearing Limitations**: Python’s garbage collector may retain sensitive data (e.g., PIN, master password).
  - **Mitigation**: Explicitly zero bytearrays; warn users about memory dump risks.
- **Biometric Risks**: Relies on OS credential stores (e.g., Windows Hello); compromised OS could expose secrets.
  - **Mitigation**: Use strong device security (e.g., BitLocker, secure boot); warn users in UI.
- **Side-Channel Risks**: No explicit protection against power analysis or cache attacks.
  - **Mitigation**: Limited by Python; auditors should verify deployment on secure hardware.

## 10. Auditing SecureVault
### Audit Checklist
- [ ] **Code Review**:
  - Verify `crypto.py` uses Argon2id (or PBKDF2 fallback) with specified parameters.
  - Check `storage.py` for atomic saves and correct file permissions (600 on non-Windows).
  - Confirm absence of network calls in all files (e.g., no `socket`, `requests`).
  - Review `biometric.py` for secure PIN hashing and temporary file cleanup.
- [ ] **Cryptography**:
  - Validate AES-256-GCM usage per NIST SP 800-38D (12-byte nonce, 16-byte tag).
  - Ensure salt/nonce generation uses `os.urandom()` for cryptographic security.
  - Verify PBKDF2 parameters in `biometric.py` (100,000 iterations, fixed salt).
- [ ] **Security Features**:
  - Test consent dialogs for browser imports (`browser_import.py`) and biometric authentication (`biometric.py`).
  - Verify clipboard clearing and auto-lock timers (`ui.py`).
  - Check file permissions for `auth.json` and `biometric.json`.
- [ ] **Edge Cases**:
  - Test handling of corrupted `vault.enc`, `auth.json`, or `biometric.json` files.
  - Simulate failed login attempts (5-attempt limit) and biometric failures.
- [ ] **Build Process**:
  - Verify `build.bat` and `password_manager.spec` for correct configuration.
  - Check for unnecessary dependencies or hidden imports in PyInstaller build.
- [ ] **Dependencies**:
  - Audit `cryptography`, `PyQt5`, `argon2` for known vulnerabilities (e.g., via `pip-audit`).