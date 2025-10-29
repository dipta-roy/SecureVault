"""
Storage management for the password manager.

LEGAL NOTICE:
This module handles secure storage of passwords. All data is encrypted locally
and never transmitted. Use only on devices you own or administer.
"""

import os
import json
import struct
import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
import threading
import stat
import platform
import hashlib
import hmac
import base64
import logging
import shutil

logger = logging.getLogger(__name__)

from app.crypto import CryptoManager
from app.biometric import BiometricManager
from app.utils import _set_windows_file_permissions
from . import config


@dataclass
class PasswordEntry:
    """Represents a single password entry."""
    id: str
    site: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    date_added: str = ""
    date_modified: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PasswordEntry':
        """Create from dictionary."""
        return cls(**data)

class StorageManager:

    """Manages encrypted storage of password entries."""
    # File format version

    VERSION = 1
    MAGIC_BYTES = b'SVPM'  # SecureVault Password Manager

    def __init__(self, filepath: str):

        """
        Initialize storage manager.
        Args:
            filepath: Path to the encrypted storage file
        """
        self.filepath = filepath
        self.crypto = CryptoManager()
        self.biometric = BiometricManager()
        self._lock = threading.Lock()
        self._key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._entries: List[PasswordEntry] = []
        self._biometric_key_id = f"{config.BIOMETRIC_KEY_PREFIX}{self._get_vault_id()}"

    def update_vault_id(self):
        """Update the biometric key ID after the vault filepath has changed."""
        self._biometric_key_id = f"{config.BIOMETRIC_KEY_PREFIX}{self._get_vault_id()}"

    def _get_vault_id(self) -> str:
        """Get a unique ID for this vault based on its path."""
        return hashlib.sha256(self.filepath.encode()).hexdigest()[:16]

    def create_new_vault(self, master_password: str) -> None:
        """
        Create a new password vault.
        Args:
            master_password: The master password for encryption
        """

        with self._lock:
            self._salt = self.crypto.generate_salt()
            self._key = self.crypto.derive_key(master_password, self._salt)
            self._entries = []
            self._save()

    def unlock(self, master_password: str) -> bool:
        """
        Unlock an existing vault.
        Args:
            master_password: The master password      
        Returns:
            True if unlock successful, False otherwise
        """
        with self._lock:
            if not os.path.exists(self.filepath):
                return False
            
            try:
                # Read file header
                with open(self.filepath, 'rb') as f:
                    magic = f.read(4)
                    if magic != self.MAGIC_BYTES:
                        logger.warning(f"Unlock: Magic bytes mismatch. Expected {self.MAGIC_BYTES}, got {magic}")
                        return False
                    
                    version = struct.unpack('<I', f.read(4))[0]
                    if version != self.VERSION:
                        logger.warning(f"Unlock: Version mismatch. Expected {self.VERSION}, got {version}")
                        return False
                    
                    # Read salt
                    salt_size = struct.unpack('<I', f.read(4))[0]
                    self._salt = f.read(salt_size)
                    
                    # Derive key
                    self._key = self.crypto.derive_key(master_password, self._salt)
                    
                    # Read and decrypt data
                    nonce_size = struct.unpack('<I', f.read(4))[0]
                    nonce = f.read(nonce_size)
                    
                    tag_size = struct.unpack('<I', f.read(4))[0]
                    tag = f.read(tag_size)
                    
                    ciphertext_size = struct.unpack('<I', f.read(4))[0]
                    ciphertext = f.read(ciphertext_size)
                
                # Decrypt
                plaintext = self.crypto.decrypt(ciphertext, self._key, nonce, tag)
                data = json.loads(plaintext.decode('utf-8'))
                
                # Load entries
                self._entries = [PasswordEntry.from_dict(e) for e in data['entries']]
                
                return True
                
            except Exception as e:
                logger.error(f"Unlock: Error during unlock process: {e}", exc_info=True)
                self._key = None
                self._salt = None
                self._entries = []
                return False

    def unlock_with_biometric(self) -> bool:
        """
        Unlock vault using PIN authentication.
        Returns:
            True if unlock successful, False otherwise
        """
        if not self.biometric.is_available():
            return False
        
        # Retrieve stored key
        stored_key_b64 = self.biometric.retrieve_secret(self._biometric_key_id)
        if not stored_key_b64:
            return False
        
        with self._lock:
            if not os.path.exists(self.filepath):
                return False
            
            try:
                # The stored key is the encryption key, base64 encoded
                self._key = base64.b64decode(stored_key_b64)
                
                # Read file header
                with open(self.filepath, 'rb') as f:
                    magic = f.read(4)
                    if magic != self.MAGIC_BYTES:
                        logger.warning(f"Unlock with biometric: Magic bytes mismatch. Expected {self.MAGIC_BYTES}, got {magic}")
                        return False
                    
                    version = struct.unpack('<I', f.read(4))[0]
                    if version != self.VERSION:
                        logger.warning(f"Unlock with biometric: Version mismatch. Expected {self.VERSION}, got {version}")
                        return False
                    
                    # Read salt
                    salt_size = struct.unpack('<I', f.read(4))[0]
                    self._salt = f.read(salt_size)
                    
                    # Read and decrypt data
                    nonce_size = struct.unpack('<I', f.read(4))[0]
                    nonce = f.read(nonce_size)
                    
                    tag_size = struct.unpack('<I', f.read(4))[0]
                    tag = f.read(tag_size)
                    
                    ciphertext_size = struct.unpack('<I', f.read(4))[0]
                    ciphertext = f.read(ciphertext_size)
                
                # Decrypt
                plaintext = self.crypto.decrypt(ciphertext, self._key, nonce, tag)
                data = json.loads(plaintext.decode('utf-8'))
                
                # Load entries
                self._entries = [PasswordEntry.from_dict(e) for e in data['entries']]
                
                return True
                
            except Exception as e:
                logger.error(f"Unlock with biometric: Error during unlock process: {e}", exc_info=True)
                self._key = None
                self._salt = None
                self._entries = []
                return False


    def enable_biometric(self, master_password: str) -> bool:
        """
        Enable PIN authentication for this vault.
        Args:
            master_password: The master password to store
        Returns:
            True if enabled successfully
        """
        if not self.biometric.is_available():
            return False

        # Verify password is correct

        if not self.is_unlocked():
            if not self.unlock(master_password):
                return False

        # Store the derived key securely, base64 encoded

        key_b64 = base64.b64encode(self._key).decode('utf-8')
        return self.biometric.store_secret(self._biometric_key_id, key_b64)

    def disable_biometric(self) -> bool:
        """
        Disable PIN authentication for this vault.
        Returns:
            True if disabled successfully
        """
        return self.biometric.delete_secret(self._biometric_key_id)

    def has_biometric_data(self) -> bool:
        """
        Check if PIN data is stored for this vault."""
        if not self.biometric.is_available():
            return False
        return self.biometric.retrieve_secret(self._biometric_key_id) is not None

    def is_unlocked(self) -> bool:
        """
        Check if vault is unlocked."""
        return self._key is not None

    def lock(self) -> None:
        """
        Lock the vault and clear sensitive data."""

        with self._lock:
            if self._key:
                self.crypto.clear_bytes(bytearray(self._key))
            self._key = None
            self._entries = []

    def add_entry(self, entry: PasswordEntry) -> None:
        """
        Add a new password entry."""
        with self._lock:
            if not self.is_unlocked():
                raise RuntimeError("Vault is locked")
            entry.date_added = datetime.datetime.now().isoformat()
            entry.date_modified = entry.date_added
            self._entries.append(entry)
            self._save()

    def update_entry(self, entry_id: str, updated_entry: PasswordEntry) -> bool:
        """
        Update an existing entry."""
        with self._lock:
            if not self.is_unlocked():
                raise RuntimeError("Vault is locked")
            for i, entry in enumerate(self._entries):
                if entry.id == entry_id:
                    updated_entry.id = entry_id
                    updated_entry.date_added = entry.date_added
                    updated_entry.date_modified = datetime.datetime.now().isoformat()
                    self._entries[i] = updated_entry
                    self._save()
                    return True
            return False

    def delete_entry(self, entry_id: str) -> bool:
        """
        Delete an entry."""
        with self._lock:
            if not self.is_unlocked():
                raise RuntimeError("Vault is locked")
            original_count = len(self._entries)
            self._entries = [e for e in self._entries if e.id != entry_id]
            if len(self._entries) < original_count:
                self._save()
                return True
            return False

    def get_entries(self) -> List[PasswordEntry]:
        """
        Get all password entries."""

        with self._lock:
            if not self.is_unlocked():
                raise RuntimeError("Vault is locked")
            return self._entries.copy()

    def find_duplicate_entries(self) -> List[List[PasswordEntry]]:
        """
        Find entries with duplicate site and username."""
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")
        from collections import defaultdict
        duplicates = defaultdict(list)
        for entry in self._entries:
            duplicates[(entry.site.lower(), entry.username.lower())].append(entry)
        return [group for group in duplicates.values() if len(group) > 1]

    def delete_entries(self, entry_ids: List[str]) -> bool:
        """
        Delete multiple entries by their IDs."""
        with self._lock:
            if not self.is_unlocked():
                raise RuntimeError("Vault is locked")
            original_count = len(self._entries)
            self._entries = [e for e in self._entries if e.id not in entry_ids]
            if len(self._entries) < original_count:
                self._save()
                return True
            return False

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """
        Change the master password."""
        with self._lock:
            if not self.is_unlocked():
                # Try to unlock with old password
                if not self.unlock(old_password):
                    return False

            # Generate new salt and derive new key
            self._salt = self.crypto.generate_salt()
            self._key = self.crypto.derive_key(new_password, self._salt)
            self._save()
            return True

    def _save(self) -> None:
        """
        Save entries to encrypted file."""
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")

        # Prepare data
        data = {
            'entries': [e.to_dict() for e in self._entries],
            'metadata': {
                'version': self.VERSION,
                'last_modified': datetime.datetime.now().isoformat()
            }
        }

        plaintext = json.dumps(data, indent=2).encode('utf-8')

        # Encrypt
        ciphertext, nonce, tag = self.crypto.encrypt(plaintext, self._key)

        try:
            # Write to file
            with open(self.filepath + '.tmp', 'wb') as f:
                # Header
                f.write(self.MAGIC_BYTES)
                f.write(struct.pack('<I', self.VERSION))

                # Salt
                f.write(struct.pack('<I', len(self._salt)))
                f.write(self._salt)

                # Nonce
                f.write(struct.pack('<I', len(nonce)))
                f.write(nonce)

                # Tag
                f.write(struct.pack('<I', len(tag)))
                f.write(tag)

                # Ciphertext
                f.write(struct.pack('<I', len(ciphertext)))
                f.write(ciphertext)

            # Atomic replace using shutil.move
            shutil.move(self.filepath + '.tmp', self.filepath)

            # Set restrictive permissions
            if not self._set_file_permissions(self.filepath):
                logger.warning(f"Failed to set secure file permissions for vault: {self.filepath}. This might indicate a permission issue.")

        except Exception as e:
            logger.error(f"Error saving vault file {self.filepath}: {e}", exc_info=True)
            if os.path.exists(self.filepath + '.tmp'):
                os.remove(self.filepath + '.tmp')
            raise # Re-raise the exception to be caught by the UI


    def _set_file_permissions(self, filepath: str) -> bool:
        """
        Set file to be readable/writable by owner only."""
        if platform.system() == 'Windows':
            return _set_windows_file_permissions(filepath)
        else:
            os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # 600
            return True