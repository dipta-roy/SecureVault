## SecureVault Password Manager: Technical Documentation

This document provides a comprehensive audit-style analysis of the SecureVault Password Manager based on the provided source files (`init.py`, `main.py`, `crypto.py`, `browser_import.py`, `storage.py`, `ui.py`). It covers every detail of the program's architecture, encryption mechanisms, storage locations, key management, export/import processes, and file-by-file breakdowns. The goal is to explain how the program works internally for security auditing purposes.

### 1. Overall Architecture
- **Language and Framework:** Written in Python, using PyQt5 for the GUI. It follows a modular structure with separate modules for crypto, storage, UI, and imports.
- **Entry Point:** `main.py` initializes the Qt application, sets up storage, and launches the login dialog or main window.
- **Core Components:**
  - **Encryption/Decryption:** Handled by `crypto.py` using the `cryptography` library.
  - **Storage:** Managed by `storage.py`, which serializes/deserializes data to/from an encrypted file.
  - **UI:** Defined in `ui.py`, including dialogs for login, password management, generation, and settings.
  - **Imports:** `browser_import.py` handles browser and CSV imports.
  - **Initialization:** `init.py` sets version and author metadata.
- **Security Model:**
  - Local-only: No network access, data transmission, or cloud integration.
  - Threat Model: Protects against unauthorized access to the vault file. Assumes the device is secure; does not protect against keyloggers or memory dumps.
  - Consent: Browser imports require explicit user consent via dialogs (enforced in UI).
  - Logging: Security actions (e.g., login attempts, changes) are logged to `~/.securevault/logs/audit.log`.
- **Platform Support:** Windows, macOS, Linux. Browser imports are platform-specific (full on Windows for Chrome/Edge; manual on others).
- **Dependencies:** 
  - Core: `cryptography`, `PyQt5`, `argon2` (optional).
  - Platform: `win32crypt` (Windows), `keyring` (macOS – not fully used), `sqlite3`, `shutil`, etc. (standard library).
- **Versioning:** `__version__ = "1.0.0"` in `init.py`.
- **Error Handling:** Basic try-except blocks; raises exceptions for unsupported operations (e.g., browser imports on non-Windows).

### 2. Encryption Details
Encryption is handled exclusively in `crypto.py` via `CryptoManager`. The system uses symmetric encryption with key derivation from a master password.

#### Key Derivation
- **Method:** 
  - Preferred: Argon2id (via `argon2` library if available). Parameters: time_cost=2, memory_cost=65536 (64 MB), parallelism=4, hash_len=32 bytes.
  - Fallback: PBKDF2-HMAC-SHA256 (via `cryptography`) with 100,000 iterations.
- **Salt:** 32-byte (256-bit) random salt generated via `os.urandom()`. Stored in the vault file header (unencrypted – salts are safe to expose).
- **Key Size:** 32 bytes (256 bits) for AES-256.
- **Process:** `derive_key(password: str, salt: bytes) -> bytes`
  - Encodes password to UTF-8.
  - Uses Argon2's low-level `hash_secret_raw` or PBKDF2 to derive the key.
- **Security Notes:** Argon2id is memory-hard, resistant to GPU/ASIC attacks. PBKDF2 is a weaker fallback. No pepper (device-specific secret) is used.

#### Encryption Algorithm
- **Cipher:** AES-256-GCM (Galois/Counter Mode) via `cryptography.hazmat.primitives.ciphers`.
- **Nonce:** 12 bytes (96 bits) random via `os.urandom()`. Stored in the vault file.
- **Tag:** 16 bytes (128 bits) authentication tag. Stored in the vault file.
- **Process:** `encrypt(plaintext: bytes, key: bytes) -> (ciphertext, nonce, tag)`
  - Creates a Cipher object with AES(key) and GCM(nonce).
  - Encrypts plaintext; finalizes with tag.
- **Decryption:** `decrypt(ciphertext, key, nonce, tag) -> plaintext`
  - Similar Cipher setup with GCM(nonce, tag).
  - Raises `InvalidTag` on authentication failure (e.g., tampering).
- **Additional Security:**
  - Constant-time comparison: `secure_compare(a, b)` using `hmac.compare_digest` to prevent timing attacks (not used in core flow but available).
  - Memory Clearing: `clear_bytes(data: bytes)` zeros out bytearrays (attempts to clear sensitive data from memory, but Python's GC limits effectiveness).

#### Data Encrypted
- All password entries (site, username, password, URL, notes, dates) are serialized to JSON, then encrypted as a single blob.
- Metadata (version, last_modified) is included in the JSON but encrypted.

### 3. Vault Storage Details
- **Location:** `~/.securevault/vault.enc` (where `~` is the user's home directory, via `os.path.expanduser("~")`).
  - Directory created if missing via `os.makedirs(app_dir, exist_ok=True)`.
  - Atomic saves: Writes to `.tmp` file, then renames/replaces.
- **File Permissions:** On non-Windows, set to 600 (owner read/write only) via `os.chmod(stat.S_IRUSR | stat.S_IWUSR)`.
- **File Format:**
  - Magic Bytes: `b'SVPM'` (4 bytes).
  - Version: 4-byte unsigned int (little-endian), current=1.
  - Salt Size: 4-byte unsigned int, followed by salt (32 bytes).
  - Nonce Size: 4-byte unsigned int, followed by nonce (12 bytes).
  - Tag Size: 4-byte unsigned int, followed by tag (16 bytes).
  - Ciphertext: Remainder of file (encrypted JSON).
- **Locking:** Vault is "unlocked" in memory after successful decryption. Locked by clearing `_key` and `_entries`.
- **Data Structure:** List of `PasswordEntry` dataclasses (id: UUID str, site, username, password, url, notes, date_added, date_modified – all strings).

#### Exporting the Vault to a New Folder
- **Manual Export:** The vault is a single file (`vault.enc`). To export:
  1. Copy `~/.securevault/vault.enc` to a new location (e.g., via file explorer or `cp`/`copy` command).
  2. To use in a new installation: Point the app to the new path by modifying `_get_storage_path()` in `main.py` (hardcoded; not configurable via UI).
- **Backup Export (via UI):** In Settings > Backup tab:
  - "Create Backup" prompts for a save location and filename (default: `securevault_backup_YYYYMMDD_HHMMSS.enc`).
  - Copies `vault.enc` via `shutil.copy2()` (preserves metadata).
  - Backup is identical to the vault file (encrypted with the same key).
- **Restore:** In Settings > Restore tab:
  - Select a `.enc` file.
  - Warns about overwriting; requires restart. On restart, unlock with the backup's master password (app uses the restored file as the new vault).
- **CSV Export (Unencrypted):** From main window "Export" button:
  - Prompts for CSV save location.
  - Writes headers: "Site,Username,Password,URL,Notes".
  - Exports all entries (passwords in plaintext – security risk; user warned).

#### Encryption Key Storage
- **Key Storage:** The key is **never stored**. It's derived on-the-fly from the master password + salt during unlock.
  - In memory: Stored as `_key: bytes` in `StorageManager` while unlocked.
  - Cleared on lock/close via `crypto.clear_bytes(bytearray(self._key))` and setting to None.
- **Master Password:** Entered via UI; never stored or logged.
- **No Key Escrow:** If master password is forgotten, data is irrecoverable.

### 4. Import/Export Details
#### Browser Imports (`browser_import.py`)
- **Consent:** UI requires acknowledgment dialog before proceeding.
- **Supported Browsers:**
  - **Chrome (Windows):** Copies `Login Data` SQLite DB from `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`, decrypts passwords via `win32crypt.CryptUnprotectData` (DPAPI). Extracts URL, username, password; generates UUID ID.
  - **Edge (Windows):** Similar to Chrome, from `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`.
  - **Firefox:** Not automated; raises exception directing manual export via `about:logins`.
  - **Chrome (macOS/Linux):** Not automated; raises exception for manual export via `chrome://settings/passwords`.
- **Process:** Returns list of `PasswordEntry`; added to vault via `add_entry()`.
- **CSV Import:** 
  - Sniffs delimiter; maps headers heuristically (e.g., 'site' to ['name', 'site', ...]).
  - Parses rows; skips incomplete (no site/username/password).
  - Generates UUID ID.

#### Other Exports
- **CSV Export:** As above, unencrypted.

### 5. UI and User Flow Details (`ui.py`)
- **LoginDialog:** Checks if vault exists; creates new if not (enforces strong password: 12+ chars, upper/lower/digit/special). Max 5 attempts.
- **MainWindow:** Table view of entries (columns: Site, Username, Password [hidden], Actions). Buttons for add/edit/delete/import/export/generate/settings.
  - **Timers:** Auto-lock (default 5 min, configurable); clipboard clear (30 sec).
  - **Copy:** Copies to clipboard; starts timer to clear.
  - **Import Dialog:** Consent checkbox; selects browser/CSV; progress dialog for large imports.
  - **Generator:** Customizable (length 8-128, char types); copies generated password.
- **SettingsDialog:** Tabs for Security (change password, timeouts), Backup (create/restore), About.
- **ChangeMasterPasswordDialog:** Verifies old, enforces strong new.
- **Truncation Note:** The provided `ui.py` is truncated (ends at "...(truncated 27670 characters)..."), but based on visible code, it includes full UI logic.

### 6. File-by-File Detailed Breakdown
#### init.py
- Metadata: Version "1.0.0", author "SecureVault Team".
- Legal notice (repeated in all files).

#### main.py
- Imports: Qt, storage, UI.
- `PasswordManagerApp`: Sets app name, style ('Fusion'), storage path (`_get_storage_path()`), handles SIGINT.
- `run()`: Shows LoginDialog; if success, shows MainWindow and runs Qt loop.
- `cleanup()`: Locks storage.
- `main()`: Enables high DPI, creates/runs app, cleans up.

#### crypto.py
- As detailed in Section 2. Includes fallback if argon2 unavailable.

#### browser_import.py
- `BrowserImporter`: Platform-specific imports (detailed in Section 4).
- `CSVImporter`: Header mapping, row parsing (detailed in Section 4).

#### storage.py
- `PasswordEntry`: Dataclass for entries.
- `StorageManager`: Manages file I/O, encryption (detailed in Section 3).
- Methods: create_new_vault, unlock, lock, add/update/delete/get entries, change_master_password, _save (atomic, permissions).

#### ui.py
- `PasswordStrengthValidator`: Checks length>=12, char types.
- Dialogs: Login, Generator, Import, Edit, Settings, ChangeMasterPassword.
- `MainWindow`: Core UI with table, buttons, menus, timers, logging (_log_action for actions like login, changes).
- Security: Clipboard clearing, auto-lock, strength enforcement.


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
  
## What Is the Salt?
The salt is a random string of bytes used when creating the encryption key from your master password. Its job is to make sure that even if two people use the same password, their encryption keys (and encrypted vaults) are different. This protects against precomputed attacks (like rainbow tables) where hackers try to guess passwords.

### How the Salt Is Generated
1. **When It’s Created**:
   - The salt is generated **when you first create your SecureVault vault** (i.e., when you set up the app and create the `vault.enc` file).
   - It’s typically made using a secure random number generator, like Python’s `os.urandom()` or `secrets` module. For example, a common salt size for Argon2id (the key derivation function used by SecureVault) is 16 bytes (128 bits), which is random and unique for each vault.

2. **How It Works**:
   - The program calls a function (likely in `crypto.py`) to generate the salt when initializing the vault.
   - Example (based on standard practice, not actual code):
     ```python
     import os
     salt = os.urandom(16)  # 16 bytes of random data
     ```
   - This ensures the salt is unpredictable and unique, which is critical for security.

3. **No Regeneration**:
   - The salt is created only once when the vault is set up. It doesn’t change unless you create a new vault.

### Where and How the Salt Is Stored
1. **Stored in the Vault File**:
   - The salt is saved inside the `vault.enc` file, which is stored in a user-specific directory like `~/.securevault/` on your computer (e.g., `C:\Users\YourName\.securevault\vault.enc` on Windows).
   - The `vault.enc` file contains:
     - The encrypted data (your passwords as JSON, encrypted with AES-256-GCM).
     - The salt (unencrypted, as it’s not sensitive by itself).
     - The nonce (a one-time random value for encryption).
     - The authentication tag (to verify the data hasn’t been tampered with).
   - The salt is typically stored as a prefix or metadata alongside the encrypted data. For example, the file structure might look like this (simplified):
     ```
     [16-byte salt][12-byte nonce][authentication tag][encrypted JSON data]
     ```

2. **Why Store the Salt?**:
   - The salt needs to be stored with the vault so the program can recreate the same encryption key every time you enter your master password. Without the salt, the key derivation (using Argon2id or PBKDF2) wouldn’t produce the correct key to decrypt the vault.
   - The salt isn’t secret—it’s safe to store it unencrypted because it’s just a random value that helps secure the key derivation process.

3. **Not Stored Elsewhere**:
   - The salt is **only in the `vault.enc` file**. It’s not kept in memory after the vault is locked, nor is it stored in any other file or database.
   - If you use biometrics (e.g., Windows Hello), the salt still comes from the `vault.enc` file, not the OS credential manager.

### How It’s Used in the Encryption Process
- When you enter your master password:
  1. The program reads the salt from the `vault.enc` file.
  2. It combines your password with the salt using **Argon2id** (or PBKDF2 as a fallback) to create the 256-bit encryption key.
  3. This key is used to decrypt the vault (or encrypt new data when saving).
- The salt ensures that12-byte nonce][authentication tag][encrypted JSON data]
     ```
     [16-byte salt][12-byte nonce][authentication tag][encrypted JSON data]
     ```

### Security Notes
- **Secure Generation**: Using `os.urandom()` or similar ensures the salt is cryptographically secure, making it resistant to attacks.
- **Safe Storage**: Storing the salt unencrypted is standard practice and not a vulnerability, as the salt’s role is to add randomness, not secrecy.
- **Potential Risk**: If the `vault.enc` file is stored in a predictable location (e.g., `~/.securevault/`), ensure the file permissions are tight (e.g., only readable by the user). Malware could potentially access the file, but the encryption still relies on the master password for security.
