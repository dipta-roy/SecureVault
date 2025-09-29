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

- On first run, create or select a vault file.
- Set a strong master password (minimum 12 characters with uppercase, lowercase, digits, and special characters).
- Unlock the vault to access features.
- Import passwords from browsers (with consent) or CSV.
- Add/edit entries via the GUI.
- Enable biometric unlock in settings (Windows only).

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

If you encounter issues, run from source code or submit an issue. For production use, consider whitelisting the app in your antivirus settings.

## License

This is free and unencumbered software released into the public domain. See the [UNLICENSE](UNLICENSE) file for details.