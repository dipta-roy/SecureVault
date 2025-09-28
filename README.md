# SecureVault Password Manager

A secure, cross-platform password manager with browser import capabilities and biometric authentication support.

## Legal Notice and Threat Model

**This tool is for personal use only.** It must operate only on the device where it is installed and only with the explicit consent of the device owner. It must never be used to extract or exfiltrate passwords from devices you do not own or administer. The app requires the user to acknowledge a consent dialog before fetching browser passwords.

## Features

- **Secure Storage**: All passwords are encrypted using AES-256-GCM with Argon2id key derivation
- **Master Password**: Single master password to unlock your vault
- **Biometric Authentication**: Support for Windows Hello, Touch ID, and Linux fingerprint readers
- **Multiple Vaults**: Create and manage multiple password vaults
- **Password Generator**: Generate strong, random passwords with customizable options
- **Browser Import**: Import passwords from Chrome, Firefox, and Edge (with user consent)
- **CSV Import/Export**: Import and export passwords in CSV format
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Auto-Lock**: Automatically locks after a period of inactivity
- **Clipboard Management**: Auto-clear clipboard after copying passwords

## Installation

### From Source

1. Clone the repository or extract the source files
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate