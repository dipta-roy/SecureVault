"""
Cryptographic operations for the password manager.

LEGAL NOTICE:
This module handles encryption/decryption of sensitive data. It must only be used
for legitimate personal password management on devices you own or administer.
"""

import os
import base64
import struct
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

try:
    from argon2 import PasswordHasher, Type
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    """Handles all cryptographic operations for the password manager."""
    
    # Constants
    SALT_SIZE = 32  # 256 bits
    KEY_SIZE = 32   # 256 bits for AES-256
    NONCE_SIZE = 12 # 96 bits for GCM
    TAG_SIZE = 16   # 128 bits
    
    # KDF parameters
    ARGON2_TIME_COST = 2
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 4
    PBKDF2_ITERATIONS = 100000
    
    def __init__(self):
        """Initialize the crypto manager."""
        self.backend = default_backend()
        if ARGON2_AVAILABLE:
            self.ph = PasswordHasher(
                time_cost=self.ARGON2_TIME_COST,
                memory_cost=self.ARGON2_MEMORY_COST,
                parallelism=self.ARGON2_PARALLELISM,
                hash_len=self.KEY_SIZE,
                type=Type.ID
            )
    
    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt."""
        return os.urandom(self.SALT_SIZE)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a password using Argon2id or PBKDF2.
        
        Args:
            password: The master password
            salt: Random salt for key derivation
            
        Returns:
            32-byte encryption key
        """
        if ARGON2_AVAILABLE:
            # Use Argon2id (preferred)
            # Argon2 library expects base64 encoded salt in hash format
            # So we'll use the raw hash function instead
            from argon2.low_level import hash_secret_raw
            key = hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=self.ARGON2_TIME_COST,
                memory_cost=self.ARGON2_MEMORY_COST,
                parallelism=self.ARGON2_PARALLELISM,
                hash_len=self.KEY_SIZE,
                type=Type.ID
            )
            return key
        else:
            # Fallback to PBKDF2-HMAC-SHA256
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS,
                backend=self.backend
            )
            return kdf.derive(password.encode('utf-8'))
    
    def encrypt(self, plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key
            
        Returns:
            Tuple of (ciphertext, nonce, tag)
        """
        nonce = os.urandom(self.NONCE_SIZE)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce, encryptor.tag
    
    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data
            key: 32-byte encryption key
            nonce: Nonce used for encryption
            tag: Authentication tag
            
        Returns:
            Decrypted plaintext
            
        Raises:
            InvalidTag: If authentication fails
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        return hmac.compare_digest(a, b)
    
    def clear_bytes(self, data: bytes) -> None:
        """Attempt to clear sensitive bytes from memory."""
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0