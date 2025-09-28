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

#### ui.py (Truncated)
- `PasswordStrengthValidator`: Checks length>=12, char types.
- Dialogs: Login, Generator, Import, Edit, Settings, ChangeMasterPassword.
- `MainWindow`: Core UI with table, buttons, menus, timers, logging (_log_action for actions like login, changes).
- Security: Clipboard clearing, auto-lock, strength enforcement.
