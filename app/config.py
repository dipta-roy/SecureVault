"""
Configuration constants for the SecureVault application.
"""

import os

# Application Metadata
APP_VERSION = "1.3"  # Use: Current version of the application. Type: str. Range: Semantic versioning string (e.g., "1.0.0")
APP_AUTHOR = "Dipta Roy"  # Use: Author of the application. Type: str. Range: Any valid string representing the author's name.
APP_NAME = "SecureVault Password Manager"  # Use: Full name of the application. Type: str. Range: Any valid string.
APP_TITLE_PREFIX = f"{APP_NAME} v{APP_VERSION}"  # Use: Prefix for the application window titles, combining name and version. Type: str (f-string). Range: Derived from APP_NAME and APP_VERSION.
APP_DISCLAIMER = """  # Use: Legal disclaimer displayed in the application. Type: str (multi-line). Range: Any valid string.
This tool is for personal use only. It must operate only on the device where
it is installed and only with the explicit consent of the device owner. It must
never be used to extract or exfiltrate passwords from devices you do not own or
administer.
"""

# Security Settings
SALT_SIZE = 16  # Use: Size of the cryptographic salt in bytes for key derivation. Type: int. Range: Recommended to be at least 16 bytes (128 bits) for security.
KEY_SIZE = 32  # Use: Size of the encryption key in bytes. Corresponds to AES-256. Type: int. Range: 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.
NONCE_SIZE = 12  # Use: Size of the Nonce (Number used once) in bytes for AES-GCM. Type: int. Range: 12 bytes (96 bits) is the recommended size for GCM.
TAG_SIZE = 16  # Use: Size of the authentication tag in bytes for AES-GCM. Type: int. Range: 16 bytes (128 bits) is the recommended size for GCM.
ARGON2_TIME_COST = 2  # Use: Argon2id time cost parameter. Controls the number of iterations. Type: int. Range: Typically 1 to 10. Higher values increase security but also computation time.
ARGON2_MEMORY_COST = 65536  # Use: Argon2id memory cost parameter. Controls the memory usage in KiB. Type: int. Range: Recommended to be at least 65536 (64 MB). Higher values increase security but also memory usage.
ARGON2_PARALLELISM = 4  # Use: Argon2id parallelism parameter. Controls the number of threads/lanes. Type: int. Range: Typically 1 to 8, often set to the number of CPU cores.
PBKDF2_ITERATIONS = 310000  # Use: Number of iterations for PBKDF2-HMAC-SHA256 key derivation (fallback if Argon2 is unavailable). Type: int. Range: Recommended to be at least 100,000, with higher values for stronger security.
KEY_DERIVATION_ITERATIONS = 100000  # Use: Number of iterations for PBKDF2-HMAC-SHA256 used for PIN hashing. Type: int. Range: Recommended to be at least 100,000.
PASSWORD_MIN_LENGTH = 12  # Use: Minimum required length for master passwords and generated passwords. Type: int. Range: Typically 8 to 16, but higher is better for master passwords.
MAX_LOGIN_ATTEMPTS = 5  # Use: Maximum number of failed login attempts before the application locks out or takes action. Type: int. Range: Positive integer (e.g., 3-10).
BIOMETRIC_AUTH_MESSAGE_ENABLE = "Enable PIN unlock for SecureVault"  # Use: Message displayed to the user when enabling biometric/PIN authentication. Type: str. Range: Any descriptive string.
BIOMETRIC_AUTH_MESSAGE_UNLOCK = "Unlock SecureVault with PIN"  # Use: Message displayed to the user when prompting for biometric/PIN unlock. Type: str. Range: Any descriptive string.
BIOMETRIC_AUTH_MESSAGE_UPDATE = "Update PIN authentication"  # Use: Message displayed to the user when updating biometric/PIN authentication. Type: str. Range: Any descriptive string.

# UI Settings
AUTO_LOCK_TIMEOUT_DEFAULT_MINUTES = 5  # Use: Default inactivity timeout in minutes before the vault automatically locks. Type: int. Range: 0 (disabled) to AUTO_LOCK_TIMEOUT_MAX_MINUTES.
CLIPBOARD_CLEAR_TIMEOUT_DEFAULT_SECONDS = 30  # Use: Default timeout in seconds after which copied passwords are cleared from the clipboard. Type: int. Range: CLIPBOARD_CLEAR_TIMEOUT_MIN_SECONDS to CLIPBOARD_CLEAR_TIMEOUT_MAX_SECONDS.
AUTO_LOCK_TIMEOUT_DEFAULT = AUTO_LOCK_TIMEOUT_DEFAULT_MINUTES * 60 * 1000  # Use: Default auto-lock timeout in milliseconds. Derived from AUTO_LOCK_TIMEOUT_DEFAULT_MINUTES. Type: int. Range: Derived value.
CLIPBOARD_CLEAR_TIMEOUT_DEFAULT = CLIPBOARD_CLEAR_TIMEOUT_DEFAULT_SECONDS * 1000  # Use: Default clipboard clear timeout in milliseconds. Derived from CLIPBOARD_CLEAR_TIMEOUT_DEFAULT_SECONDS. Type: int. Range: Derived value.
TABLE_PASSWORD_HIDDEN_TEXT = "••••••••"  # Use: Placeholder text displayed in the UI table for hidden passwords. Type: str. Range: Any string.
BIOMETRIC_KEY_PREFIX = "securevault_"  # Use: Prefix used for keys stored in the biometric secrets file to identify SecureVault-related secrets. Type: str. Range: Any string.

BROWSER_IMPORT_CONSENT_TEXT = (  # Use: The consent message displayed to the user before initiating a browser import. Type: str (multi-line f-string). Range: Any descriptive string.
    "SecureVault will attempt to import passwords from {browser}.\n\n"
    "IMPORTANT:\n"
    "• This will only read passwords stored on THIS device\n"
    "• You must be the owner/administrator of this device\n"
    "• Passwords will be stored encrypted in your local vault\n"
    "• No data will be transmitted off this device\n\n"
    "Do you consent to importing passwords from your browser?"
)

# Biometric Settings
WINDOWS_CSC_PATHS = [  # Use: List of common paths to the C# compiler (csc.exe) on Windows, used for dynamic compilation in Windows Hello integration. Type: list[str]. Range: List of valid file paths.
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
]
BIOMETRIC_AUTH_FILE = "auth.json"  # Use: Filename for storing biometric PIN hashes. Type: str. Range: Any valid filename.
BIOMETRIC_SECRETS_FILE = "biometric.json"  # Use: Filename for storing secrets (e.g., derived master key) protected by biometric authentication. Type: str. Range: Any valid filename.
PIN_PROMPT_ENTER = "Enter your PIN:"  # Use: Prompt message for the user to enter their PIN. Type: str. Range: Any descriptive string.
PIN_PROMPT_SETUP = "Set up your PIN for quick authentication:"  # Use: Prompt message for the user to set up their PIN. Type: str. Range: Any descriptive string.
WINDOWS_HELLO_AUTH_TIMEOUT_SECONDS = 30  # Use: Timeout in seconds for the Windows Hello authentication subprocess. Type: int. Range: Positive integer.

# Browser Import Settings
BROWSER_HEADER_MAPPINGS = {  # Use: Dictionary mapping internal password entry fields to common CSV header variations for import. Type: dict[str, list[str]]. Range: Dictionary with string keys and lists of strings as values.
    'site': ['name', 'site', 'website', 'title', 'url'],
    'username': ['username', 'user', 'login', 'email', 'account'],
    'password': ['password', 'pass', 'pwd'],
    'url': ['url', 'website', 'web site', 'site'],
    'notes': ['notes', 'note', 'comments', 'description']
}

# Browser Paths (Windows)
BROWSER_PATHS_WINDOWS = {  # Use: Dictionary of common installation paths for various browsers on Windows. Type: dict[str, str]. Range: Dictionary with string keys (browser names) and string values (paths).
    "chrome": os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google\\Chrome\\User Data\\Default"),
    "edge": os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft\\Edge\\User Data\\Default"),
    "brave": os.path.join(os.environ.get("LOCALAPPDATA", ""), "BraveSoftware\\Brave-Browser\\User Data\\Default"),
    "firefox": os.path.join(os.environ.get("APPDATA", ""), "Mozilla\\Firefox\\Profiles"),
}

CHROMIUM_LOGIN_DATA_FILE = "Login Data"  # Use: Filename for the SQLite database containing login data in Chromium-based browsers. Type: str. Range: "Login Data"
CHROMIUM_LOCAL_STATE_FILE = "Local State"  # Use: Filename for the JSON file containing local state, including encryption key, in Chromium-based browsers. Type: str. Range: "Local State"
FIREFOX_PROFILES_INI = "profiles.ini"  # Use: Filename for Firefox's profiles configuration file. Type: str. Range: "profiles.ini"
FIREFOX_LOGINS_JSON = "logins.json"  # Use: Filename for Firefox's JSON file containing login data. Type: str. Range: "logins.json"
FIREFOX_KEY4_DB = "key4.db"  # Use: Filename for Firefox's key database. Type: str. Range: "key4.db"

# Password Generator Settings
PASSWORD_GENERATOR_DEFAULT_LENGTH = 16  # Use: Default length for generated passwords. Type: int. Range: PASSWORD_GENERATOR_MIN_LENGTH to PASSWORD_GENERATOR_MAX_LENGTH.
PASSWORD_GENERATOR_MIN_LENGTH = 8  # Use: Minimum allowed length for generated passwords. Type: int. Range: Positive integer.
PASSWORD_GENERATOR_MAX_LENGTH = 128  # Use: Maximum allowed length for generated passwords. Type: int. Range: Positive integer.
PASSWORD_GENERATOR_AMBIGUOUS_CHARS = "0O1lI"  # Use: Characters considered ambiguous and can be excluded from generated passwords. Type: str. Range: Any string of characters.

# UI Settings (additional)
AUTO_LOCK_TIMEOUT_MAX_MINUTES = 60  # Use: Maximum configurable auto-lock timeout in minutes. Type: int. Range: Positive integer.
CLIPBOARD_CLEAR_TIMEOUT_MIN_SECONDS = 10  # Use: Minimum configurable clipboard clear timeout in seconds. Type: int. Range: Positive integer.
CLIPBOARD_CLEAR_TIMEOUT_MAX_SECONDS = 300  # Use: Maximum configurable clipboard clear timeout in seconds. Type: int. Range: Positive integer.

# Vault Management Settings
MAX_RECENT_VAULTS = 10  # Use: Maximum number of recently opened vault paths to remember. Type: int. Range: Positive integer.

# Application UI Settings
APP_STYLE = 'Fusion'  # Use: PyQt5 application style. Type: str. Range: Valid PyQt5 style names (e.g., 'Fusion', 'Windows', 'Macintosh').
APP_ICON_PATH = "logo/SecureVault_logo.ico"  # Use: Relative path to the application icon file. Type: str. Range: Valid relative path to an icon file.

# Application State Machine States
STATE_STARTUP = "STARTUP"  # Use: Represents the application's initial state. Type: str. Range: Any string.
STATE_LOGIN = "LOGIN"  # Use: Represents the application's login state. Type: str. Range: Any string.
STATE_MAIN_WINDOW = "MAIN_WINDOW"  # Use: Represents the application's main window state. Type: str. Range: Any string.
STATE_EXIT = "EXIT"  # Use: Represents the application's exit state. Type: str. Range: Any string.

# File and Directory Names
RECENT_VAULTS_FILE = "recent_vaults.txt"  # Use: Filename for storing the list of recently opened vault paths. Type: str. Range: Any valid filename.
AUDIT_LOG_FILE = "audit.log"  # Use: Filename for the application's security audit log. Type: str. Range: Any valid filename.
CONFIG_DIR_NAME = ".securevault"  # Use: Name of the hidden directory within the user's home directory where SecureVault stores its configuration and data files. Type: str. Range: Any valid directory name.
DEFAULT_VAULT_FILE = "vault.enc"  # Use: Default filename for the encrypted password vault. Type: str. Range: Any valid filename.
