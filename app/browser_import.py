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
from typing import List, Dict, Optional, Any
from pathlib import Path

from app.storage import PasswordEntry

# Platform-specific imports
if platform.system() == "Windows":
    try:
        import win32crypt
        WIN32CRYPT_AVAILABLE = True
    except ImportError:
        WIN32CRYPT_AVAILABLE = False
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
    
    def _import_chrome(self) -> List[PasswordEntry]:
        """Import passwords from Chrome."""
        if self.system == "Windows":
            return self._import_chrome_windows()
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
            return self._import_edge_windows()
        else:
            raise Exception("Edge import not supported on this platform. Please export manually.")
    
    def _import_chrome_windows(self) -> List[PasswordEntry]:
        """Import Chrome passwords on Windows."""
        if not WIN32CRYPT_AVAILABLE:
            raise Exception("win32crypt module not available. Please install pywin32.")
        
        # Find Chrome profile
        local_app_data = os.environ.get('LOCALAPPDATA')
        if not local_app_data:
            raise Exception("Cannot find Chrome profile directory")
        
        chrome_path = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
        
        if not os.path.exists(chrome_path):
            raise Exception("Chrome profile not found")
        
        # Copy database to temp location (Chrome locks it)
        temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_db.close()
        
        try:
            shutil.copy2(chrome_path, temp_db.name)
            
            # Connect to database
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            # Query passwords
            cursor.execute(
                "SELECT origin_url, username_value, password_value FROM logins"
            )
            
            entries = []
            for url, username, encrypted_password in cursor.fetchall():
                try:
                    # Decrypt password using Windows DPAPI
                    decrypted_password = win32crypt.CryptUnprotectData(
                        encrypted_password, None, None, None, 0
                    )[1].decode('utf-8')
                    
                    # Extract site name from URL
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
                    # Skip entries that can't be decrypted
                    continue
            
            conn.close()
            return entries
            
        finally:
            # Clean up temp file
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
    
    def _import_edge_windows(self) -> List[PasswordEntry]:
        """Import Edge passwords on Windows."""
        if not WIN32CRYPT_AVAILABLE:
            raise Exception("win32crypt module not available. Please install pywin32.")
        
        # Edge uses similar structure to Chrome
        local_app_data = os.environ.get('LOCALAPPDATA')
        if not local_app_data:
            raise Exception("Cannot find Edge profile directory")
        
        edge_path = os.path.join(local_app_data, 'Microsoft', 'Edge', 'User Data', 'Default', 'Login Data')
        
        if not os.path.exists(edge_path):
            raise Exception("Edge profile not found")
        
        # Use same logic as Chrome
        temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_db.close()
        
        try:
            shutil.copy2(edge_path, temp_db.name)
            
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT origin_url, username_value, password_value FROM logins"
            )
            
            entries = []
            for url, username, encrypted_password in cursor.fetchall():
                try:
                    decrypted_password = win32crypt.CryptUnprotectData(
                        encrypted_password, None, None, None, 0
                    )[1].decode('utf-8')
                    
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


class CSVImporter:
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