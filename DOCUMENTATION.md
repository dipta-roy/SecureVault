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
- **Version**: 1.2.1 (defined in `app/config.py`).
- **Author**: Dipta Roy.

## 2. Architecture
- **Language and Framework**: Python with PyQt5 for the GUI, following a modular design pattern to separate concerns (UI, crypto, storage, imports).
- **Entry Point**: `main.py` initializes the Qt application, sets up the `StorageManager`, and orchestrates the display of the `LoginDialog` or `MainWindow` based on vault status.
- **Core Components**:
  - **Encryption/Decryption**: `crypto.py` leverages the `cryptography` library for robust AES-256-GCM encryption and Argon2id/PBKDF2 key derivation.
  - **Storage**: `storage.py` manages the lifecycle of the encrypted vault file (`~/.securevault/vault.enc`), including atomic load/save operations, and CRUD for password entries.
  - **UI**: `ui.py` defines all user interface elements, including dialogs for login, password management, generation, settings, and import/export functionalities.
  - **Imports**: `browser_import.py` handles the complex logic for importing passwords from various browsers (platform-specific) and generic CSV files.
  - **Biometric Authentication**: `biometric.py` provides an abstraction layer for platform-specific biometric (e.g., Windows Hello) and PIN authentication.
  - **Configuration**: `config.py` centralizes all application-wide constants, such as security parameters, file paths, and UI settings.
  - **Utilities**: `utils.py` contains helper functions, notably for setting secure file permissions on Windows.
  - **Vault Management**: `vault_manager.py` handles the management of recently used vault paths.
- **Security Model**:
  - **Local-only**: The application is strictly local, with no network access or cloud integration, minimizing external attack surfaces.
  - **Threat Model**: Designed to protect against unauthorized vault file access on a secure device. It does *not* protect against keyloggers, memory dumps, or a compromised operating system.
  - **Consent**: All sensitive operations, such as browser imports and biometric authentication setup, require explicit user consent via UI dialogs.
  - **Logging**: Security-relevant actions (e.g., login attempts, import consent, CSV export) are logged to `~/.securevault/logs/audit.log` for auditing purposes.
- **Platform Support**: SecureVault aims for cross-platform compatibility:
  - **Windows**: Full support, including automated browser imports for Chrome/Edge (via DPAPI) and Windows Hello biometric authentication.
  - **macOS/Linux**: Partial support. Browser imports typically require manual export from the browser. Biometric authentication relies on Touch ID (macOS) or system fingerprint services (Linux) with password fallback.
- **Dependencies**:
  - **Core**: `PyQt5` (GUI), `cryptography` (encryption), `argon2-cffi` (key derivation, optional but recommended).
  - **Platform-Specific**:
    - `pywin32` (Windows): Essential for DPAPI decryption in browser imports and setting secure file permissions.
    - `keyring` (macOS/Linux): Used for retrieving browser master keys on non-Windows systems.
    - `sqlite3` (built-in): For reading browser `Login Data` databases.
    - `shutil`, `ctypes` (built-in): Used for file operations and system calls (e.g., biometric).
- **Error Handling**: The application employs `try-except` blocks to gracefully handle expected errors (e.g., incorrect passwords, file not found) and provides descriptive messages to the user. Specific exceptions are raised for unsupported operations (e.g., non-Windows browser imports) to guide the user.

### Biometric Authentication
- **Module**: `biometric.py` provides fingerprint and PIN authentication via `BiometricManager` and `WindowsHelloHelper` (Windows-specific).
- **Supported Platforms**:
  - **Windows**: Uses Windows Hello for fingerprint authentication with PIN fallback. `WindowsHelloHelper` checks biometric availability via WMI (`Win32_Biometric`) and attempts authentication using a dynamically compiled C# script (leveraging `credui.dll`) or `ShellExecuteW` with the "runas" verb to trigger the Windows Credential Provider UI. Temporary C# files are deleted post-authentication.
  - **macOS**: Supports Touch ID with password fallback, typically via `keyring` integration.
  - **Linux**: Supports fingerprint authentication with password fallback, also typically via `keyring` integration.
- **Process**:
  - Attempts fingerprint authentication first; falls back to PIN if unavailable or failed.
  - PIN is hashed using PBKDF2-HMAC-SHA256 with `100,000` iterations and a fixed salt, stored in `~/.securevault/auth.json`.
  - Secrets (e.g., the master password's derived key) are stored in `~/.securevault/biometric.json` as base64-encoded strings, protected by the biometric/PIN authentication.
- **Security Features**:
  - Explicit user consent is required via UI dialogs (e.g., `QMessageBox` for fingerprint, `QInputDialog` for PIN setup/entry).
  - File permissions are set to `0o600` (owner read/write only) on non-Windows systems for `auth.json` and `biometric.json`. On Windows, `_set_windows_file_permissions` (from `utils.py`) applies restrictive ACLs.
  - Temporary C# files generated for Windows Hello are securely deleted.
- **Limitations**: Relies on OS-provided biometric APIs; offers no protection against a compromised OS credential store or advanced attacks that could bypass OS-level security.

## 3. Encryption Details
Encryption is managed by `CryptoManager` in `crypto.py` using symmetric encryption with a master password-derived key, following NIST SP 800-38D for AES-GCM.

### Key Derivation
- **Method**:
  - **Preferred**: Argon2id (via `argon2` library if available). Parameters are configured in `config.py`: `time_cost=2`, `memory_cost=65536` (64 MB), `parallelism=4`, `hash_len=32` bytes. Argon2id is chosen for its memory-hardness, making it highly resistant to GPU/ASIC-based brute-force attacks (OWASP recommendation).
  - **Fallback**: PBKDF2-HMAC-SHA256 (via `cryptography`) with `310,000` iterations. This is used if the `argon2-cffi` library is not installed or available.
- **Salt**: A 32-byte (256-bit) cryptographically secure random value generated using `os.urandom()`. It is stored unencrypted in the vault file header, which is standard cryptographic practice and does not compromise security.
- **Key Size**: The derived key is 32 bytes (256 bits), suitable for AES-256.
- **Process**: The `derive_key(password: str, salt: bytes) -> bytes` method encodes the master password to UTF-8 and then uses either Argon2's `hash_secret_raw` or PBKDF2 to generate the key.
- **Security Notes**: Argon2id represents a modern, strong key derivation function. The PBKDF2 fallback, while still secure, is less resistant to specialized hardware attacks. No pepper (device-specific secret) is currently used, which means the security relies solely on the master password and salt.

### Encryption Algorithm
- **Cipher**: AES-256-GCM (Galois/Counter Mode) is used for authenticated encryption, providing confidentiality, integrity, and authenticity. Implemented via `cryptography.hazmat.primitives.ciphers`.
- **Nonce**: A 12-byte (96-bit) cryptographically secure random value generated using `os.urandom()` for each encryption operation. It is stored unencrypted in the vault file and ensures that encrypting the same plaintext with the same key produces different ciphertext, preventing certain types of attacks.
- **Tag**: A 16-byte (128-bit) authentication tag is generated during encryption and stored in the vault file. This tag is crucial for verifying data integrity and authenticity during decryption; any tampering with the ciphertext or associated data will cause decryption to fail with an `InvalidTag` exception.
- **Process**: `encrypt(plaintext: bytes, key: bytes) -> (ciphertext, nonce, tag)` initializes an AES cipher with the derived key and GCM mode with the nonce, then encrypts the plaintext and finalizes with the authentication tag.
- **Decryption**: `decrypt(ciphertext, key, nonce, tag) -> plaintext` uses the key, nonce, and tag to decrypt the ciphertext. If the tag verification fails, an `InvalidTag` exception is raised, indicating potential tampering.
- **Additional Security**:
  - **Constant-time comparison**: The `secure_compare(a, b)` method uses `hmac.compare_digest` to compare cryptographic values in constant time, mitigating timing side-channel attacks. This is available for use but not directly in the core vault unlock flow.
  - **Memory clearing**: The `clear_bytes(data: bytes)` function attempts to zero out sensitive bytearrays from memory. While Python's garbage collector can make guaranteed memory wiping challenging, this is a best-effort practice to reduce residual data exposure.

### Data Encrypted
- Password entries (site, username, password, URL, notes, dates) are serialized to JSON and encrypted as a single blob.
- Metadata (version, last_modified) is included in the JSON and encrypted.

## 4. Vault Storage
### File Format and Location
- **Location**: The primary vault file is `~/.securevault/vault.enc`. The `~` refers to the user’s home directory, resolved via `os.path.expanduser("~")`. The `.securevault` directory is created if it doesn't exist using `os.makedirs(app_dir, exist_ok=True)`.
- **Atomic Saves**: To prevent data loss or corruption during unexpected application termination (e.g., power failure), all save operations are atomic. Data is first written to a temporary file (`.tmp`), and then this temporary file is atomically renamed/replaced with the actual vault file.
- **File Permissions**: To restrict unauthorized access:
  - On non-Windows systems (macOS, Linux), file permissions for `vault.enc`, `auth.json`, and `biometric.json` are set to `0o600` (owner read/write only) using `os.chmod(stat.S_IRUSR | stat.S_IWUSR)`.
  - On Windows, the `_set_windows_file_permissions` function from `utils.py` is used to apply restrictive Access Control Lists (ACLs), granting full control only to the current user/owner and removing access for others.
- **File Format**:
  The `vault.enc` file has a structured binary header followed by the encrypted data:
  - **Magic Bytes**: `b'SVPM'` (4 bytes) - A unique identifier to confirm the file is a SecureVault password manager file.
  - **Version**: 4-byte unsigned integer (little-endian), currently `1`.
  - **Salt Size**: 4-byte unsigned integer, indicating the size of the following salt (always 32 bytes).
  - **Salt**: 32 bytes - The random salt used for key derivation.
  - **Nonce Size**: 4-byte unsigned integer, indicating the size of the following nonce (always 12 bytes).
  - **Nonce**: 12 bytes - The unique nonce used for AES-256-GCM encryption.
  - **Tag Size**: 4-byte unsigned integer, indicating the size of the following authentication tag (always 16 bytes).
  - **Tag**: 16 bytes - The authentication tag generated by AES-256-GCM.
  - **Ciphertext Size**: 4-byte unsigned integer, indicating the size of the encrypted data.
  - **Ciphertext**: The remainder of the file, containing the AES-256-GCM encrypted JSON data.
- **Additional Files**:
  - `auth.json`: Located in `~/.securevault/`, this file stores the PBKDF2-HMAC-SHA256 hash of the user's PIN (base64-encoded) for biometric authentication. It is protected by restrictive file permissions.
  - `biometric.json`: Also in `~/.securevault/`, this file stores base64-encoded secrets (specifically, the derived encryption key for the vault) that are protected by biometric/PIN authentication. It also has restrictive file permissions.
- **Data Structure**: The plaintext data within the vault is a JSON object containing a list of `PasswordEntry` dataclasses. Each `PasswordEntry` includes fields such as `id` (UUID string), `site`, `username`, `password`, `url`, `notes`, `date_added`, and `date_modified` (all strings).
- **Locking**: When the vault is unlocked, the decrypted entries and the encryption key (`_key`) are held in memory. Upon locking or application exit, the `_key` and `_entries` are cleared from memory (with best-effort byte zeroing for the key).

### Salt Details
The salt is a 32-byte cryptographically secure random value generated using `os.urandom(32)`. Its primary purpose is to ensure that even if two users have the same master password, their derived encryption keys will be different, protecting against precomputed attacks like rainbow tables.
- **Generation**: Generated once when a new vault is created.
- **Storage**: Stored unencrypted in the `vault.enc` header. This is a standard and safe practice as salts are not considered secret.
- **Usage**: Combined with the master password via Argon2id (or PBKDF2) to derive the 256-bit AES key.
- **Security**: The salt is never stored in memory post-lock or in any OS credential manager, only within the `vault.enc` file.

### Exporting and Backups
- **Manual Export**: Users can manually copy the `~/.securevault/vault.enc` file to create a backup. This backup is fully encrypted and can be restored by placing it back in the `.securevault` directory or by using the UI's restore function.
- **Backup Export (UI)**: Accessible via Settings > Backup tab. Prompts the user for a save location and filename (default: `securevault_backup_YYYYMMDD_HHMMSS.enc`). Uses `shutil.copy2()` to preserve file metadata. The backup file is an exact, encrypted copy of the `vault.enc` file.
- **Restore**: Via Settings > Restore tab. Allows selecting an `.enc` file. A warning is displayed about overwriting current data, and the application requires a restart to load the restored vault with its original master password.
- **CSV Export (Unencrypted)**: Available from the main window. Prompts for a CSV file location. Exports passwords in plaintext (`Site,Username,Password,URL,Notes`). A prominent warning dialog informs the user of the security risks associated with storing unencrypted data. Users are advised to store the exported file securely or delete it after use.

### Encryption Key Management
- **Key Storage**: The actual 256-bit AES encryption key is *never* stored persistently. It is derived on-the-fly from the master password and the vault's unique salt during the unlock process.
  - **In Memory**: While the vault is unlocked, the derived key (`_key: bytes`) is held in the `StorageManager` instance.
  - **Clearing**: Upon locking the vault or application exit, the `_key` is explicitly cleared from memory using `crypto.clear_bytes(bytearray(self._key))` and then set to `None`.
- **Master Password**: The master password entered by the user (or retrieved via biometric authentication) is never stored or logged. It is used solely for key derivation.
- **No Key Escrow**: SecureVault does not implement any key escrow mechanism. If the master password is lost, the data is irrecoverable.

## 5. Import/Export Processes
### Browser Imports (`browser_import.py`)
- **Consent**: Explicit user consent is required via a UI acknowledgment dialog before any browser import is initiated.
- **Supported Browsers**:
  - **Chrome (Windows)**: The `BrowserImporter` copies the `Login Data` SQLite database from `%LOCALAPPDATA%\Google\Chrome\User Data\Default` (or similar paths for other profiles). It then decrypts the stored passwords using `win32crypt.CryptUnprotectData`, which leverages Windows DPAPI (Data Protection API) with the master key extracted from the browser's `Local State` file.
  - **Edge (Windows)**: Similar to Chrome, it targets `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data` and uses DPAPI for decryption.
  - **Firefox (All Platforms)**: Automatic import is *not* supported if a primary password is set or on non-Windows platforms. The application raises an exception and directs the user to manually export passwords via `about:logins` in Firefox.
  - **Chromium-based Browsers (macOS/Linux)**: Automatic import is *not* supported. The application raises an exception and directs the user to manually export passwords via `chrome://settings/passwords` (or equivalent) due to the complexity of securely accessing the OS keychain or other credential stores from Python in a cross-platform manner.
- **Process**: For supported browsers, the module extracts the URL, username, and encrypted password from the browser's database. It then decrypts the password (if applicable), generates a UUID for the entry, and adds it to the SecureVault.

### CSV Imports and Exports
- **CSV Import**:
  - The `CSVImporter` class handles parsing. It first sniffs the delimiter (e.g., comma, semicolon) from the file's content.
  - It then heuristically maps CSV headers (e.g., `site`, `website`, `url` can all map to the `site` field) to the `PasswordEntry` fields using predefined mappings in `config.py`.
  - Rows with incomplete data (missing site, username, or password) are skipped.
  - Each successfully parsed row is converted into a `PasswordEntry` with a generated UUID ID and added to the vault.
- **CSV Export**: As described in "Exporting and Backups," this function exports all vault entries to a plaintext CSV file. A critical warning is displayed to the user about the security implications of storing unencrypted data.

## 6. User Interface and Flow (`ui.py`)
- **StartupDialog**: The initial dialog presented to the user, allowing them to select an existing vault from a list of recent vaults, browse for a vault file, or create a new one. It ensures a vault path is selected before proceeding.
- **LoginDialog**: Handles user authentication. For new vaults, it prompts for master password creation and enforces strong password policies (length, character types) using `PasswordStrengthValidator`. For existing vaults, it attempts to unlock using the master password or biometric authentication (if enabled). It limits login attempts to `config.MAX_LOGIN_ATTEMPTS` before returning to the startup screen.
- **MainWindow**: The primary interface for managing passwords. It features:
  - **Entry Table**: Displays password entries with columns for Site/App, Username, Password (hidden by default), Notes, Date Added, and Actions (copy username, copy password, edit, delete).
  - **Search Functionality**: Allows filtering entries by site, username, or notes.
  - **Actions**: Buttons for adding new entries, importing (browser/CSV), exporting (CSV), and accessing settings.
  - **Context Menu**: Provides quick actions (copy, edit, delete) for individual entries.
  - **Timers**: Implements an auto-lock mechanism (configurable timeout, default 5 minutes) to secure the vault after inactivity, and a clipboard auto-clear timer (default 30 seconds) for copied passwords.
  - **Audit Logging**: Records security-relevant actions (e.g., login attempts, import consent, CSV export) via `_log_action`.
- **PasswordGeneratorDialog**: A utility dialog for generating strong, customizable passwords based on user-selected criteria (length, character types, exclusion of ambiguous characters) using Python's `secrets` module.
- **PasswordEntryDialog**: Used for adding or editing individual password entries. It includes input fields for site, username, password, URL, and notes, along with password visibility toggle and integration with the password generator.
- **DuplicateEntriesDialog**: A specialized dialog to help users identify and resolve duplicate password entries within their vault, offering options to delete selected duplicates or keep one and delete others in a group.
- **SettingsDialog**: Provides access to various application configurations across multiple tabs:
  - **Security**: Allows changing the master password, enabling/disabling/changing PIN authentication, and configuring auto-lock and clipboard clear timeouts.
  - **Vault**: Displays the current vault location and allows moving the vault file to a new location.
  - **Backup**: Facilitates creating encrypted backups and restoring from existing backup files.
  - **About**: Displays application version, author, and legal disclaimer.
- **ChangeMasterPasswordDialog**: A dedicated dialog for securely changing the master password, requiring the old password and enforcing strong new password policies.
- **PasswordStrengthValidator**: A static utility class used across UI components to enforce minimum password strength requirements (length, presence of uppercase, lowercase, digits, and special characters).

## 7. File-by-File Breakdown
### `app/__init__.py`
- **Purpose**: Defines application-wide metadata such as `__version__` and `__author__`, and includes the overarching legal notice and threat model for the application.

### `app/main.py`
- **Role**: The primary entry point for the SecureVault application. It initializes the PyQt5 application, sets up high DPI scaling, handles application-level signals (like `SIGINT`), and manages the overall application flow through different UI states (startup, login, main window).
- **Key Class**: `PasswordManagerApp` orchestrates the display of `StartupDialog`, `LoginDialog`, and `MainWindow`.
- **Methods**:
  - `_get_default_storage_path()`: Determines the default location for the vault file (`~/.securevault/vault.enc`).
  - `_get_last_used_vault()` / `_save_last_used_vault()`: Manages the most recently accessed vault path.
  - `run()`: Contains the main application loop, transitioning between UI states.
  - `cleanup()`: Ensures the vault is locked upon application exit.

### `app/crypto.py`
- **Role**: Encapsulates all cryptographic operations.
- **Key Class**: `CryptoManager`.
- **Functionality**:
  - `generate_salt()`: Creates cryptographically secure random salts.
  - `derive_key()`: Derives a 256-bit encryption key from a master password and salt using Argon2id (preferred) or PBKDF2-HMAC-SHA256 (fallback).
  - `encrypt()`: Performs AES-256-GCM encryption, returning ciphertext, nonce, and authentication tag.
  - `decrypt()`: Performs AES-256-GCM decryption, validating the authentication tag.
  - `secure_compare()`: Provides a constant-time comparison function to mitigate timing attacks.
  - `clear_bytes()`: Attempts to zero out sensitive bytearrays from memory.

### `app/browser_import.py`
- **Role**: Manages the import of password entries from web browsers and CSV files.
- **Key Classes**:
  - `BrowserImporter`: Handles platform-specific logic for extracting and decrypting passwords from browsers.
  - `CSVImporter`: Parses CSV files, sniffs delimiters, and maps headers to `PasswordEntry` fields.
- **Functionality**:
  - Supports Chrome/Edge on Windows using DPAPI for decryption.
  - Provides instructions for manual export from Firefox and other Chromium-based browsers on macOS/Linux.
  - Includes logic for handling browser `Login Data` SQLite databases and `Local State` files.

### `app/storage.py`
- **Role**: Core module for managing the encrypted password vault file.
- **Key Classes**:
  - `PasswordEntry`: A dataclass representing a single password entry.
  - `StorageManager`: Manages file I/O, encryption/decryption, and CRUD operations for password entries.
- **Functionality**:
  - `create_new_vault()`: Initializes a new vault with a master password and generates a salt.
  - `unlock()`: Decrypts and loads vault data using the master password.
  - `unlock_with_biometric()`: Decrypts and loads vault data using a key stored via biometric authentication.
  - `lock()`: Clears sensitive data from memory and resets the vault state.
  - `add_entry()`, `update_entry()`, `delete_entry()`, `get_entries()`: Standard CRUD operations for password entries.
  - `change_master_password()`: Re-encrypts the vault with a new master password.
  - `_save()`: Atomically saves encrypted vault data to disk, ensuring data integrity and applying restrictive file permissions.
  - `_set_file_permissions()`: Sets platform-specific file permissions (using `utils._set_windows_file_permissions` on Windows).

### `app/ui.py`
- **Role**: Implements the entire graphical user interface of the application.
- **Key Classes**:
  - `StartupDialog`, `LoginDialog`, `MainWindow`, `PasswordEntryDialog`, `PasswordGeneratorDialog`, `SettingsDialog`, `ChangeMasterPasswordDialog`, `DuplicateEntriesDialog`.
- **Functionality**:
  - Handles user interaction, displays password entries, manages settings, and facilitates import/export.
  - Integrates `PasswordStrengthValidator` for master password and generated password validation.
  - Manages auto-lock and clipboard clearing timers.
  - Orchestrates background worker threads (`BrowserImportWorker`, `CSVImportWorker`) for long-running import tasks.

### `app/biometric.py`
- **Role**: Provides an abstraction layer for biometric and PIN authentication.
- **Key Classes**:
  - `WindowsHelloHelper`: Windows-specific implementation for interacting with Windows Hello.
  - `BiometricManager`: Manages the overall biometric authentication flow, including PIN setup, verification, and secure secret storage/retrieval.
- **Functionality**:
  - `authenticate()`: Attempts fingerprint authentication first, then falls back to PIN.
  - `store_secret()`, `retrieve_secret()`, `delete_secret()`: Manages base64-encoded secrets (e.g., derived master key) in `biometric.json`.
  - `_save_auth_hash()`: Stores PBKDF2-hashed PIN in `auth.json`.

### `app/config.py`
- **Role**: Centralized repository for all application configuration constants.
- **Content**:
  - Application metadata (version, author, name, disclaimer).
  - Security parameters (salt size, key sizes, Argon2/PBKDF2 parameters, login attempt limits).
  - UI settings (auto-lock/clipboard timeouts, password hidden text).
  - File and directory names (`.securevault`, `vault.enc`, `audit.log`).
  - Browser-specific paths and header mappings for imports.

### `app/utils.py`
- **Role**: Provides general utility functions.
- **Key Function**:
  - `_set_windows_file_permissions(filepath: str)`: A critical function for Windows that uses `pywin32` to apply highly restrictive Access Control Lists (ACLs) to sensitive files, ensuring only the owner has read/write access. It logs warnings if `pywin32` is not fully available or if permissions cannot be fully hardened.

### `app/vault_manager.py`
- **Role**: Manages the list of recently accessed vault files.
- **Functionality**:
  - `get_recent_vault_paths()`: Loads paths from `~/.securevault/recent_vaults.txt` and filters out non-existent files.
  - `save_recent_vault_path()`: Adds a new path to the recent list, ensuring uniqueness and limiting the list size to `config.MAX_RECENT_VAULTS`.

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
- **Behavioral Analysis**: The application's actions, such as accessing browser password databases (e.g., Chrome’s `Login Data` SQLite) and decrypting data via system APIs (e.g., `win32crypt` on Windows), can mimic the behavior of credential-stealing malware. Similarly, the dynamic compilation and execution of C# scripts for Windows Hello authentication can be flagged as suspicious.
- **PyInstaller Packaging**: Executables bundled with PyInstaller often resemble packed or obfuscated malware, leading to heuristic detection by antivirus engines.
- **Why It’s Safe**:
  - **Explicit User Consent**: All sensitive operations, including browser imports and biometric authentication setup, require explicit user consent through clear UI dialogs.
  - **Local-Only Operation**: SecureVault is designed to be strictly local. There is no network activity or telemetry, which can be verified via packet sniffing or code review.
  - **Temporary File Cleanup**: Any temporary files created during operations (e.g., C# scripts for Windows Hello) are securely deleted post-use.
  - **Open-Source and Auditable**: The entire codebase is open-source, allowing for public scrutiny and auditing to confirm its benign nature.
- **Mitigation**: Users experiencing false positives are advised to add `dist\SecureVault.exe` to their antivirus allowlist or build the application from source to avoid PyInstaller-related detections.

### Potential Vulnerabilities and Mitigations
- **Predictable Storage Locations**: The default storage location for sensitive files (`~/.securevault/vault.enc`, `auth.json`, `biometric.json`) is well-known. While file permissions are set restrictively, a sophisticated attacker with elevated privileges could potentially target these locations.
  - **Mitigation**: File permissions (e.g., `0o600` on Unix-like systems, restrictive ACLs on Windows) are applied to limit access. Future versions could consider offering user-configurable vault paths to further decentralize storage.
- **Plaintext CSV Exports**: The option to export passwords to an unencrypted CSV file poses a significant risk if the exported file is mishandled or left unsecured.
  - **Mitigation**: The application displays prominent warning dialogs to the user before proceeding with a plaintext export. Users are strongly advised to store such exports securely or delete them immediately after use. Future enhancements could include an option for encrypted CSV exports.
- **No Pepper in Key Derivation**: The current key derivation process does not incorporate a device-specific secret (pepper). This means that if an attacker gains access to the vault file and the master password, they can decrypt the vault without needing access to the original device.
  - **Mitigation**: While not a direct vulnerability, adding a device-specific secret (e.g., derived from a Trusted Platform Module (TPM) or other hardware-backed key storage) in future versions could enhance resistance to offline attacks, making it harder to decrypt the vault on a different machine.
- **Memory Clearing Limitations**: Due to Python's garbage collection mechanisms, achieving true, guaranteed secure memory wiping of sensitive data (like the master password or derived key) is challenging. While `crypto.clear_bytes()` attempts to zero out bytearrays, residual data might theoretically persist in memory for a short period.
  - **Mitigation**: Users are advised to be aware of the risks associated with memory dumps, especially on compromised systems. The current implementation represents a best-effort approach within Python's capabilities.
- **Biometric Risks**: The biometric authentication relies on OS-provided credential stores (e.g., Windows Hello, macOS Keychain). If the underlying operating system's credential store is compromised, the biometric protection could be bypassed.
  - **Mitigation**: Users are encouraged to maintain strong device security (e.g., BitLocker, secure boot, strong OS login credentials). The UI provides warnings about these dependencies.
- **PIN Hashing Iterations**: The PBKDF2-HMAC-SHA256 iterations for PINs (currently 100,000) are reasonable but could be increased to align with more aggressive modern recommendations (e.g., 310,000+ iterations). This is a trade-off between security strength and user experience (authentication speed).
  - **Mitigation**: The current iteration count provides a good balance. Future updates could allow users to configure this or automatically adjust based on system performance.
- **Audit Log Security**: The `audit.log` file, which records security-relevant actions, is stored in plain text and lacks integrity protection. An attacker with file system access could read or tamper with these logs to hide their activities.
  - **Mitigation**: While the logs provide valuable forensic information, they are not tamper-proof. Future improvements could include encrypting or integrity-protecting the logs (e.g., with HMAC) to enhance their reliability.
- **Windows Hello Integration Complexity**: The current Windows Hello implementation involves dynamic C# compilation or `ShellExecuteW` to interact with the Windows Credential Provider. This approach, while effective, introduces complexity and could be brittle or introduce unforeseen side effects compared to a direct API call (if available and easily accessible from Python).
  - **Mitigation**: This design choice was made to avoid external dependencies and provide a native user experience. Ongoing monitoring for more robust Python-native Windows Hello integration methods is warranted.
- **Side-Channel Risks**: There is no explicit protection implemented against advanced side-channel attacks (e.g., power analysis, cache timing attacks). These are generally difficult to mitigate in high-level languages like Python.
  - **Mitigation**: This is a limitation inherent to the chosen technology stack. Auditors should verify that the application is deployed on secure hardware environments where such advanced attacks are less feasible.

## 10. Auditing SecureVault
This section provides a checklist for security auditors to systematically review the SecureVault codebase and deployment.

### Audit Checklist
- [ ] **Code Review**:
  - Verify `app/crypto.py` uses Argon2id (or PBKDF2 fallback) with the specified parameters (`config.py`).
  - Check `app/storage.py` for atomic saves and correct application of file permissions (e.g., `0o600` on non-Windows, restrictive ACLs on Windows via `app/utils.py`).
  - Confirm the absence of network calls in all application files (e.g., no `socket`, `requests`, or similar libraries used for external communication).
  - Review `app/biometric.py` for secure PIN hashing (PBKDF2-HMAC-SHA256 with sufficient iterations) and proper temporary file cleanup (especially for Windows Hello C# scripts).
  - Examine `app/browser_import.py` for correct handling of browser database access and decryption, ensuring user consent is always obtained.
  - Verify `app/ui.py` implements robust input validation, password strength checks, and proper handling of sensitive data in the UI.
- [ ] **Cryptography**:
  - Validate AES-256-GCM usage per NIST SP 800-38D, specifically checking for correct 12-byte nonce and 16-byte authentication tag generation and usage.
  - Ensure all salt and nonce generation uses `os.urandom()` for cryptographic randomness.
  - Verify PBKDF2 parameters in `app/biometric.py` (iterations, salt) and `app/crypto.py` (fallback) are consistent with `config.py` and current best practices.
  - Confirm that derived keys are cleared from memory after use (best-effort in Python).
- [ ] **Security Features**:
  - Test consent dialogs for browser imports (`app/browser_import.py`) and biometric authentication (`app/biometric.py`) to ensure they are unskippable.
  - Verify the functionality and timing of clipboard clearing and auto-lock timers (`app/ui.py`).
  - Check file permissions for `~/.securevault/vault.enc`, `auth.json`, and `biometric.json` on target operating systems.
  - Review the audit log (`~/.securevault/logs/audit.log`) for completeness and accuracy of recorded security-relevant actions.
- [ ] **Edge Cases and Resilience**:
  - Test handling of corrupted `vault.enc`, `auth.json`, or `biometric.json` files to ensure graceful failure and error reporting.
  - Simulate failed login attempts (e.g., exceeding the 5-attempt limit) and biometric failures to verify proper application behavior.
  - Assess the application's behavior under resource constraints or unexpected system events.
- [ ] **Build Process**:
  - Verify `build.bat` and `password_manager.spec` for correct PyInstaller configuration, ensuring no sensitive data is inadvertently bundled or exposed.
  - Check for unnecessary dependencies or hidden imports in the PyInstaller build that could introduce vulnerabilities.
- [ ] **Dependencies**:
  - Audit all third-party dependencies (`cryptography`, `PyQt5`, `argon2-cffi`, `pywin32`, `keyring`) for known vulnerabilities using tools like `pip-audit` or by checking CVE databases.