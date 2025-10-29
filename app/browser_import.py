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
import subprocess

from app.storage import PasswordEntry
from . import config

# Platform-specific imports
if platform.system() == "Windows":
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import win32crypt
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
elif platform.system() == "Darwin":  # macOS
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import keyring
        MAC_AVAILABLE = True
    except ImportError:
        MAC_AVAILABLE = False
elif platform.system() == "Linux":
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import keyring
        LINUX_AVAILABLE = True
    except ImportError:
        LINUX_AVAILABLE = False
else:
    keyring = None
    MAC_AVAILABLE = False
    LINUX_AVAILABLE = False


class BrowserImporter:
    """Handles importing passwords from browsers."""
    
    def __init__(self):
        """Initialize the browser importer."""
        self.system = platform.system()
    
    def import_from_browser(self, browser: str) -> List[PasswordEntry]:
        """
        Import passwords from a specific browser.
        
        Args:
            browser: Browser name (chrome, firefox, edge, brave)
            
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
        elif browser == "brave":
            return self._import_brave()
        else:
            raise ValueError(f"Unsupported browser: {browser}")
    
    def _get_master_key(self, browser_path: str) -> Optional[bytes]:
        """Get the encryption key based on platform."""
        if self.system == "Windows":
            return self._get_windows_encryption_key(browser_path)
        elif self.system == "Darwin":
            return self._get_macos_encryption_key(browser_path)
        elif self.system == "Linux":
            return self._get_linux_encryption_key(browser_path)
        else:
            return None

    def _get_windows_encryption_key(self, browser_path: str) -> Optional[bytes]:
        local_state_path = os.path.join(browser_path, config.CHROMIUM_LOCAL_STATE_FILE)
        if not os.path.exists(local_state_path):
            return None
        
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            
            encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key_b64)
            # Remove 'DPAPI' prefix
            encrypted_key = encrypted_key[5:]
            
            # Decrypt the key using Windows DPAPI
            data = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)
            return data[1]
        except Exception:
            return None

    def _get_macos_encryption_key(self, browser_path: str) -> Optional[bytes]:
        local_state_path = os.path.join(browser_path, config.CHROMIUM_LOCAL_STATE_FILE)
        if not os.path.exists(local_state_path):
            return None
        
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            
            encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key_b64)
            salt = encrypted_key[3:]  # Remove 'salt' prefix
            
            # Get the master password from keychain
            password = subprocess.check_output(
                ['security', 'find-generic-password', '-wa', config.MACOS_KEYCHAIN_SERVICE]
            ).decode().rstrip()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA1(),
                length=16,
                salt=salt,
                iterations=310000,
            )
            master_key = kdf.derive(password.encode())
            return master_key
        except Exception:
            return None

    def _get_linux_encryption_key(self, browser_path: str) -> Optional[bytes]:
        """Get the encryption key on Linux using keyring."""
        local_state_path = os.path.join(browser_path, config.CHROMIUM_LOCAL_STATE_FILE)
        if not os.path.exists(local_state_path):
            return None
        
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            
            encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key_b64)
            salt = encrypted_key[3:]  # Remove 'salt' prefix
            
            # Get the master password from keyring
            password = keyring.get_password(config.LINUX_KEYRING_SERVICE, config.LINUX_KEYRING_DEFAULT_PASSPHRASE)
            if not password:
                raise Exception("Linux keyring password not found. Please ensure a keyring is set up.")
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA1(),
                length=16,
                salt=salt,
                iterations=310000,
            )
            master_key = kdf.derive(password.encode())
            return master_key
        except Exception:
            return None

    def _decrypt_password(self, encrypted_password: bytes, master_key: bytes) -> str:
        """Decrypt a password using AES-256-GCM (cross-platform)."""
        try:
            # Handle modern AES-GCM (v10/v11 prefix)
            if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
                payload = encrypted_password[3:]
                iv = payload[:12]
                ciphertext = payload[12:]
                aesgcm = AESGCM(master_key)
                decrypted = aesgcm.decrypt(iv, ciphertext, associated_data=b'')
                return decrypted.decode('utf-8').rstrip('\x00')
            
            # Fallback for legacy (pre-v80): direct AES-CBC or DPAPI (but for non-Win, assume PBKDF2 already handled)
            else:
                # For legacy on non-Win, would need AES-CBC, but assuming modern, return empty
                return ""
        except Exception:
            return ""

    def _get_firefox_profile(self) -> str:
        """Get the path to the default Firefox profile."""
        if self.system == "Windows":
            firefox_dir = os.path.join(os.environ.get('APPDATA', ''), 'Mozilla', 'Firefox')
        elif self.system == "Darwin":
            firefox_dir = os.path.expanduser('~/Library/Application Support/Firefox')
        elif self.system == "Linux":
            firefox_dir = os.path.expanduser('~/.mozilla/firefox')
        else:
            raise Exception("Unsupported platform for Firefox")

        profiles_ini_path = os.path.join(firefox_dir, config.FIREFOX_PROFILES_INI)
        if not os.path.exists(profiles_ini_path):
            raise Exception("Firefox profiles.ini not found")

        default_profile = None
        with open(profiles_ini_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('[Profile'):
                path = None
                is_relative = True
                is_default = False
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('['):
                    l = lines[i].strip()
                    if l.startswith('Path='):
                        path = l[5:]
                    elif l.startswith('IsRelative='):
                        is_relative = l[11:].lower() == '1'
                    elif l.startswith('Default='):
                        is_default = l[8:].lower() == '1'
                    i += 1
                if is_default and path:
                    if is_relative:
                        default_profile = os.path.join(firefox_dir, 'Profiles', path)
                    else:
                        default_profile = path
                    break
            else:
                i += 1

        if not default_profile or not os.path.exists(default_profile):
            raise Exception("Default Firefox profile not found")

        return default_profile

    def _import_firefox(self) -> List[PasswordEntry]:
        """Import passwords from Firefox. Assumes no primary password is set."""
        profile_path = self._get_firefox_profile()
        logins_path = os.path.join(profile_path, config.FIREFOX_LOGINS_JSON)
        key4_path = os.path.join(profile_path, config.FIREFOX_KEY4_DB)

        if not os.path.exists(logins_path) or not os.path.exists(key4_path):
            raise Exception("Firefox logins.json or key4.db not found. Profile may be locked or corrupted.")

        # Read logins
        with open(logins_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            logins = data.get('logins', [])

        # Check for primary password and get global salt
        conn = sqlite3.connect(key4_path)
        cursor = conn.cursor()
        cursor.execute("SELECT item2 FROM metadata WHERE id = 'password'")
        row = cursor.fetchone()
        if row and row[0]:
            conn.close()
            raise Exception(
                "Firefox has a primary password set. Automatic decryption not supported.\n"
                "Please go to about:logins in Firefox and export your passwords manually."
            )

        cursor.execute("SELECT item1 FROM metadata WHERE id = 'global'")
        global_salt_hex = cursor.fetchone()[0]
        global_salt = bytes.fromhex(global_salt_hex)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=24,
            salt=global_salt,
            iterations=310000,
        )
        master_key = kdf.derive(b'')  # Empty master password

        conn.close()

        entries = []
        for login in logins:
            hostname = login.get('hostname', '')
            if not hostname:
                continue

            # Username (plain or encrypted)
            username = login.get('username', '')
            encrypted_username = login.get('encryptedUsername')
            if encrypted_username:
                enc_u = base64.b64decode(encrypted_username)
                cipher = Cipher(algorithms.TripleDES(master_key), modes.ECB())
                dec_u = cipher.decryptor()
                u_data = dec_u.update(enc_u) + dec_u.finalize()
                username = u_data.rstrip(b'\x00').decode('utf-8', errors='ignore')

            # Password
            encrypted_password = login.get('password', '')
            if not encrypted_password:
                continue
            enc_p = base64.b64decode(encrypted_password)
            cipher = Cipher(algorithms.TripleDES(master_key), modes.ECB())
            dec_p = cipher.decryptor()
            p_data = dec_p.update(enc_p) + dec_p.finalize()
            password = p_data.rstrip(b'\x00').decode('utf-8', errors='ignore')

            if not password:
                continue

            url = login.get('formSubmitURL', hostname)
            site = hostname.replace('www.', '').rpartition('/')[0]

            entries.append(PasswordEntry(
                id=str(uuid.uuid4()),
                site=site,
                username=username,
                password=password,
                url=url,
                notes=f"Created: {login.get('timeCreated', 'Unknown')}"
            ))

        return entries

    def _import_chrome(self) -> List[PasswordEntry]:
        """Import passwords from Chrome."""
        if self.system == "Windows":
            return self._import_chromium_windows(r"Google\Chrome")
        elif self.system == "Darwin":
            return self._import_chromium_macos_linux("Google/Chrome")
        elif self.system == "Linux":
            return self._import_chromium_macos_linux("google-chrome")
        else:
            raise Exception("Chrome import not supported on this platform. Please export manually.")
    
    def _import_edge(self) -> List[PasswordEntry]:
        """Import passwords from Edge."""
        if self.system == "Windows":
            return self._import_chromium_windows(r"Microsoft\Edge")
        elif self.system == "Darwin":
            return self._import_chromium_macos_linux("Microsoft Edge")
        elif self.system == "Linux":
            return self._import_chromium_macos_linux("microsoft-edge")
        else:
            raise Exception("Edge import not supported on this platform. Please export manually.")

    def _import_brave(self) -> List[PasswordEntry]:
        """Import passwords from Brave."""
        if self.system == "Windows":
            return self._import_chromium_windows(r"BraveSoftware\Brave-Browser")
        elif self.system == "Darwin":
            return self._import_chromium_macos_linux("BraveSoftware/Brave-Browser")
        elif self.system == "Linux":
            return self._import_chromium_macos_linux("BraveSoftware/Brave-Browser")
        else:
            raise Exception("Brave import not supported on this platform. Please export manually.")

    def _import_chromium_windows(self, browser_path_suffix: str) -> List[PasswordEntry]:
        """Import passwords from a Chromium-based browser on Windows."""
        if not WIN32_AVAILABLE:
            raise Exception("Cryptography and pywin32 not available. Please install pywin32 and cryptography.")
        
        local_app_data = os.environ.get('LOCALAPPDATA')
        if not local_app_data:
            raise Exception("Cannot find browser profile directory")
        
        browser_path = os.path.join(local_app_data, browser_path_suffix, 'User Data')
        login_data_path = os.path.join(browser_path, 'Default', config.CHROMIUM_LOGIN_DATA_FILE)
        
        if not os.path.exists(login_data_path):
            raise Exception("Browser profile not found")
            
        key = self._get_master_key(browser_path)
        if not key:
            raise Exception("Could not retrieve encryption key.")

        temp_db_path = tempfile.mktemp(suffix='.db')
        
        try:
            shutil.copy2(login_data_path, temp_db_path)
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            entries = []
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                if not url or not username or not encrypted_password:
                    continue
                
                decrypted_password = self._decrypt_password(encrypted_password, key)
                if not decrypted_password:
                    continue
                
                from urllib.parse import urlparse
                parsed = urlparse(url)
                site = parsed.netloc or parsed.path or ""
                
                entries.append(PasswordEntry(
                    id=str(uuid.uuid4()),
                    site=site,
                    username=username,
                    password=decrypted_password,
                    url=url,
                    notes=""  # No notes available from browser DB
                ))
            
            conn.close()
            return entries
            
        finally:
            try:
                os.unlink(temp_db_path)
            except OSError:
                pass

    def _import_chromium_macos_linux(self, browser_dir: str) -> List[PasswordEntry]:
        """Import passwords from a Chromium-based browser on macOS/Linux."""
        if self.system == "Darwin" and not MAC_AVAILABLE:
            raise Exception("Cryptography not available. Please install cryptography.")
        if self.system == "Linux" and not LINUX_AVAILABLE:
            raise Exception("Cryptography and keyring not available. Please install cryptography and keyring.")
        
        if self.system == "Darwin":
            base_path = os.path.expanduser(f"~/Library/Application Support/{browser_dir}")
        else:  # Linux
            base_path = os.path.expanduser(f"~/.config/{browser_dir}")
        
        browser_path = os.path.join(base_path, 'Default')
        login_data_path = os.path.join(browser_path, 'Default', config.CHROMIUM_LOGIN_DATA_FILE)
        
        if not os.path.exists(login_data_path):
            raise Exception("Browser profile not found")
            
        key = self._get_master_key(browser_path)
        if not key:
            raise Exception("Could not retrieve encryption key.")

        temp_db_path = tempfile.mktemp(suffix='.db')
        
        try:
            shutil.copy2(login_data_path, temp_db_path)
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            entries = []
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                if not url or not username or not encrypted_password:
                    continue
                
                decrypted_password = self._decrypt_password(encrypted_password, key)
                if not decrypted_password:
                    continue
                
                from urllib.parse import urlparse
                parsed = urlparse(url)
                site = parsed.netloc or parsed.path or ""
                
                entries.append(PasswordEntry(
                    id=str(uuid.uuid4()),
                    site=site,
                    username=username,
                    password=decrypted_password,
                    url=url,
                    notes=""  # No notes available from browser DB
                ))
            
            conn.close()
            return entries
            
        finally:
            try:
                os.unlink(temp_db_path)
            except OSError:
                pass
    
    def _get_browser_paths(self) -> Dict[str, str]:
        """Returns a dictionary of common browser paths based on the OS."""
        paths = {}
        if self.system == "Windows":
            local_app_data = os.environ.get('LOCALAPPDATA')
            if local_app_data:
                for browser, suffix in config.BROWSER_PATHS_WINDOWS.items():
                    if "firefox" in browser:
                        # Firefox path is different, it's in Program Files
                        program_files = os.environ.get('PROGRAMFILES')
                        program_files_x86 = os.environ.get('PROGRAMFILES(X86)')
                        if program_files and "firefox" == browser:
                            paths[browser] = os.path.join(program_files, suffix)
                        if program_files_x86 and "firefox_x86" == browser:
                            paths[browser] = os.path.join(program_files_x86, suffix)
                    else:
                        paths[browser] = os.path.join(local_app_data, suffix)
        elif self.system == "Darwin":  # macOS
            for browser, path in config.BROWSER_PATHS_MACOS.items():
                paths[browser] = os.path.expanduser(path)
        elif self.system == "Linux":
            for browser, path in config.BROWSER_PATHS_LINUX.items():
                paths[browser] = os.path.expanduser(path)
        return paths

    def _detect_installed_browsers(self) -> List[str]:
        """Detects and returns a list of installed browsers."""
        detected = []
        browser_paths = self._get_browser_paths()

        for browser, path in browser_paths.items():
            if os.path.exists(path):
                # For Firefox, check for profiles.ini to confirm installation
                if "firefox" in browser:
                    profiles_ini = os.path.join(Path(path).parent, "profiles.ini")
                    if os.path.exists(profiles_ini):
                        detected.append("firefox")
                else:
                    detected.append(browser)
        return sorted(list(set(detected)))  # Remove duplicates and sort

    def __init__(self):
        """Initialize the browser importer."""
        self.system = platform.system()
    
    # Common header mappings
    HEADER_MAPPINGS = config.BROWSER_HEADER_MAPPINGS
    
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
