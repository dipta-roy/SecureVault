"""
Browser password import functionality.

LEGAL NOTICE:
This module can read passwords from installed browsers. It must only be used
with explicit user consent on devices you own or administer. Never use this
to extract passwords from devices you do not own.
"""

import os
import csv
import json
import platform
import sqlite3
import shutil
import tempfile
import uuid
import base64
from typing import List, Dict, Optional, Any
from pathlib import Path

from app.storage import PasswordEntry

# Platform-specific imports
if platform.system() == "Windows":
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import win32crypt
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
elif platform.system() == "Darwin":  # macOS
    import subprocess
    import keyring


class BrowserImporter:
    """Handles importing passwords from browsers."""
    
    def __init__(self):
        """Initialize the browser importer."""
        self.system = platform.system()
    
    def import_from_browser(self, browser: str) -> List[PasswordEntry]:
        """
        Import passwords from a specific browser.
        
        Args:
            browser: Browser name (chrome, firefox, edge)
            
        Returns:
            List of password entries
            
        Raises:
            Exception: If import fails or is not supported
        """
        browser = browser.lower()
        
        if browser == "chrome":
            return self._import_chrome()
        elif browser == "firefox":
            return self._import_firefox()
        elif browser == "edge":
            return self._import_edge()
        else:
            raise ValueError(f"Unsupported browser: {browser}")
    
    def _get_windows_encryption_key(self, browser_path: str) -> Optional[bytes]:
        """Get the encryption key from the browser's Local State file on Windows."""
        local_state_path = os.path.join(browser_path, "Local State")
        if not os.path.exists(local_state_path):
            return None
        
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # The key is prefixed with 'DPAPI'
        encrypted_key = encrypted_key[5:]
        
        # Decrypt the key using Windows DPAPI
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

    def _decrypt_windows_password(self, password: bytes, key: bytes) -> str:
        """Decrypt a password on Windows using AES-256-GCM."""
        # The first 12 bytes are the nonce, the rest is the ciphertext
        nonce = password[3:15]
        ciphertext = password[15:]
        
        aesgcm = AESGCM(key)
        decrypted_password = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_password.decode("utf-8")

    def _import_chrome(self) -> List[PasswordEntry]:
        """Import passwords from Chrome."""
        if self.system == "Windows":
            return self._import_chromium_windows("Google\Chrome")
        elif self.system == "Darwin":
            return self._import_chrome_macos()
        elif self.system == "Linux":
            return self._import_chrome_linux()
        else:
            raise Exception("Chrome import not supported on this platform. Please export manually.")
    
    def _import_firefox(self) -> List[PasswordEntry]:
        """Import passwords from Firefox."""
        # Firefox stores passwords differently and requires the master password
        # For security, we'll direct users to manual export
        raise Exception(
            "Firefox password import requires manual export.\n"
            "Please go to about:logins in Firefox and export your passwords."
        )
    
    def _import_edge(self) -> List[PasswordEntry]:
        """Import passwords from Edge."""
        if self.system == "Windows":
            return self._import_chromium_windows("Microsoft\Edge")
        else:
            raise Exception("Edge import not supported on this platform. Please export manually.")

    def _import_chromium_windows(self, browser_path_suffix: str) -> List[PasswordEntry]:
        """Import passwords from a Chromium-based browser on Windows."""
        if not WIN32_AVAILABLE:
            raise Exception("Cryptography modules not available. Please install pywin32 and cryptography.")
        
        local_app_data = os.environ.get('LOCALAPPDATA')
        if not local_app_data:
            raise Exception("Cannot find browser profile directory")
        
        browser_path = os.path.join(local_app_data, browser_path_suffix, 'User Data')
        login_data_path = os.path.join(browser_path, 'Default', 'Login Data')
        
        if not os.path.exists(login_data_path):
            raise Exception("Browser profile not found")
            
        key = self._get_windows_encryption_key(browser_path)
        if not key:
            raise Exception("Could not retrieve encryption key.")

        temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_db.close()
        
        try:
            shutil.copy2(login_data_path, temp_db.name)
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            entries = []
            for url, username, encrypted_password in cursor.fetchall():
                try:
                    decrypted_password = self._decrypt_windows_password(encrypted_password, key)
                    
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    site = parsed.netloc or parsed.path
                    
                    entries.append(PasswordEntry(
                        id=str(uuid.uuid4()),
                        site=site,
                        username=username,
                        password=decrypted_password,
                        url=url
                    ))
                except Exception:
                    continue
            
            conn.close()
            return entries
            
        finally:
            try:
                os.unlink(temp_db.name)
            except:
                pass
    
    def _import_chrome_macos(self) -> List[PasswordEntry]:
        """Import Chrome passwords on macOS."""
        # Chrome on macOS uses the system keychain
        # Direct access requires elevated privileges
        raise Exception(
            "Chrome password import on macOS requires manual export.\n"
            "Please go to chrome://settings/passwords and export your passwords."
        )
    
    def _import_chrome_linux(self) -> List[PasswordEntry]:
        """Import Chrome passwords on Linux."""
        # Chrome on Linux uses various keyrings (gnome-keyring, kwallet)
        # Implementation would be complex and platform-specific
        raise Exception(
            "Chrome password import on Linux requires manual export.\n"
            "Please go to chrome://settings/passwords and export your passwords."
        )
    
    def _get_browser_paths(self) -> Dict[str, str]:
        """Returns a dictionary of common browser paths based on the OS."""
        paths = {}
        if self.system == "Windows":
            local_app_data = os.environ.get('LOCALAPPDATA')
            program_files = os.environ.get('PROGRAMFILES')
            program_files_x86 = os.environ.get('PROGRAMFILES(X86)')

            if local_app_data:
                paths["chrome"] = os.path.join(local_app_data, r"Google\Chrome\User Data")
                paths["edge"] = os.path.join(local_app_data, r"Microsoft\Edge\User Data")
                paths["brave"] = os.path.join(local_app_data, r"BraveSoftware\Brave-Browser\User Data")
                paths["opera"] = os.path.join(local_app_data, r"Opera Software\Opera Stable\User Data")
                paths["vivaldi"] = os.path.join(local_app_data, r"Vivaldi\User Data")
            if program_files:
                paths["firefox"] = os.path.join(program_files, "Mozilla Firefox")
            if program_files_x86:
                paths["firefox_x86"] = os.path.join(program_files_x86, "Mozilla Firefox")
        elif self.system == "Darwin": # macOS
            paths["chrome"] = os.path.expanduser("~/Library/Application Support/Google/Chrome")
            paths["firefox"] = os.path.expanduser("~/Library/Application Support/Firefox")
            paths["edge"] = os.path.expanduser("~/Library/Application Support/Microsoft Edge")
            paths["brave"] = os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser")
            paths["opera"] = os.path.expanduser("~/Library/Application Support/com.operasoftware.Opera")
            paths["vivaldi"] = os.path.expanduser("~/Library/Application Support/Vivaldi")
        elif self.system == "Linux":
            paths["chrome"] = os.path.expanduser("~/.config/google-chrome")
            paths["firefox"] = os.path.expanduser("~/.mozilla/firefox")
            paths["edge"] = os.path.expanduser("~/.config/microsoft-edge")
            paths["brave"] = os.path.expanduser("~/.config/BraveSoftware/Brave-Browser")
            paths["opera"] = os.path.expanduser("~/.config/opera")
            paths["vivaldi"] = os.path.expanduser("~/.config/vivaldi")
        return paths

    def _detect_installed_browsers(self) -> List[str]:
        """Detects and returns a list of installed browsers."""
        detected = []
        browser_paths = self._get_browser_paths()

        for browser, path in browser_paths.items():
            if os.path.exists(path):
                # For Firefox, check for profiles.ini to confirm installation
                if "firefox" in browser:
                    if any(Path(path).glob("profiles.ini")):
                        detected.append("firefox")
                else:
                    detected.append(browser)
        return sorted(list(set(detected))) # Remove duplicates and sort
    """Handles importing passwords from CSV files."""
    
    # Common header mappings
    HEADER_MAPPINGS = {
        'site': ['name', 'site', 'website', 'title', 'url'],
        'username': ['username', 'user', 'login', 'email', 'account'],
        'password': ['password', 'pass', 'pwd'],
        'url': ['url', 'website', 'web site', 'site'],
        'notes': ['notes', 'note', 'comments', 'description']
    }
    
    def import_from_file(self, filepath: str) -> List[PasswordEntry]:
        """
        Import passwords from a CSV file.
        
        Args:
            filepath: Path to CSV file
            
        Returns:
            List of password entries
        """
        entries = []
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            # Try to detect delimiter
            sample = f.read(1024)
            f.seek(0)
            
            sniffer = csv.Sniffer()
            try:
                delimiter = sniffer.sniff(sample).delimiter
            except:
                delimiter = ','
            
            reader = csv.DictReader(f, delimiter=delimiter)
            
            # Map headers
            header_map = self._map_headers(reader.fieldnames or [])
            
            for row in reader:
                entry = self._parse_row(row, header_map)
                if entry:
                    entries.append(entry)
        
        return entries
    
    def _map_headers(self, headers: List[str]) -> Dict[str, str]:
        """Map CSV headers to our field names."""
        header_map = {}
        headers_lower = [h.lower().strip() for h in headers]
        
        for field, variations in self.HEADER_MAPPINGS.items():
            for header in headers:
                if header.lower().strip() in variations:
                    header_map[field] = header
                    break
        
        # If no mapping found, try to guess
        if 'username' not in header_map and headers:
            # Second column is often username
            if len(headers) > 1:
                header_map['username'] = headers[1]
        
        if 'password' not in header_map and headers:
            # Third column is often password
            if len(headers) > 2:
                header_map['password'] = headers[2]
        
        if 'site' not in header_map and headers:
            # First column is often site name
            header_map['site'] = headers[0]
        
        return header_map
    
    def _parse_row(self, row: Dict[str, str], header_map: Dict[str, str]) -> Optional[PasswordEntry]:
        """Parse a CSV row into a PasswordEntry."""
        # Required fields
        site = row.get(header_map.get('site', ''), '').strip()
        username = row.get(header_map.get('username', ''), '').strip()
        password = row.get(header_map.get('password', ''), '').strip()
        
        if not site or not username or not password:
            return None
        
        # Optional fields
        url = row.get(header_map.get('url', ''), '').strip()
        notes = row.get(header_map.get('notes', ''), '').strip()
        
        # If URL is missing but site looks like a URL, use it
        if not url and (site.startswith('http://') or site.startswith('https://')):
            url = site
            # Extract domain for site name
            from urllib.parse import urlparse
            parsed = urlparse(url)
            site = parsed.netloc
        
        return PasswordEntry(
            id=str(uuid.uuid4()),
            site=site,
            username=username,
            password=password,
            url=url,
            notes=notes
        )