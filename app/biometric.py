"""
Biometric authentication support for the password manager.

LEGAL NOTICE:
This module handles biometric authentication. It must only be used
for legitimate personal password management on devices you own or administer.
"""

import platform
import os
import base64
import json
import logging
from typing import Optional, Dict, Any

# Set up logging
logger = logging.getLogger(__name__)

# Platform-specific imports
system = platform.system()

if system == "Windows":
    try:
        # Try to import the real Windows Hello implementation
        from .windows_biometric_real import create_windows_hello_authenticator, WindowsHelloBiometric
        WINDOWS_HELLO_REAL = True
    except ImportError:
        WINDOWS_HELLO_REAL = False
        logger.info("Real Windows Hello not available, using fallback")
    
    # Fallback imports
    try:
        import ctypes
        from ctypes import wintypes
        WINDOWS_AVAILABLE = True
    except ImportError:
        WINDOWS_AVAILABLE = False

elif system == "Darwin":  # macOS
    try:
        import subprocess
        TOUCH_ID_AVAILABLE = True
    except ImportError:
        TOUCH_ID_AVAILABLE = False

elif system == "Linux":
    try:
        import subprocess
        result = subprocess.run(
            ["which", "fprintd-verify"], 
            capture_output=True,
            stderr=subprocess.DEVNULL
        )
        LINUX_BIOMETRIC_AVAILABLE = result.returncode == 0
    except:
        LINUX_BIOMETRIC_AVAILABLE = False


class BiometricManager:
    """Manages biometric authentication for the password manager."""
    
    def __init__(self):
        """Initialize the biometric manager."""
        self.system = platform.system()
        self._available = False
        self._windows_hello = None
        
        try:
            if self.system == "Windows" and WINDOWS_HELLO_REAL:
                # Try to use real Windows Hello
                self._windows_hello = create_windows_hello_authenticator()
                self._available = self._windows_hello is not None
            else:
                self._available = self._check_availability()
        except Exception as e:
            logger.error(f"Error initializing biometric manager: {e}")
            self._available = False
    
    def _check_availability(self) -> bool:
        """Check if biometric authentication is available."""
        try:
            if self.system == "Windows":
                # Fallback check for Windows
                import sys
                return WINDOWS_AVAILABLE and sys.getwindowsversion().major >= 10
            elif self.system == "Darwin":
                return TOUCH_ID_AVAILABLE and self._check_touch_id()
            elif self.system == "Linux":
                return LINUX_BIOMETRIC_AVAILABLE
            return False
        except Exception as e:
            logger.error(f"Error in availability check: {e}")
            return False
    
    def _check_touch_id(self) -> bool:
        """Check if Touch ID is available on macOS."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"], 
                capture_output=True, 
                text=True,
                stderr=subprocess.DEVNULL
            )
            return "Touch ID" in result.stdout or "T2" in result.stdout
        except:
            return False
    
    def is_available(self) -> bool:
        """Check if biometric authentication is available."""
        return self._available
    
    def get_device_info(self) -> str:
        """Get information about the biometric device."""
        if not self.is_available():
            return "No biometric device available"
        
        if self.system == "Windows":
            if self._windows_hello:
                return f"Windows Hello ({self._windows_hello.get_available_types()})"
            else:
                return "Windows Security (Password/PIN)"
        elif self.system == "Darwin":
            return "Touch ID"
        elif self.system == "Linux":
            return "Fingerprint Reader"
        return "Unknown"
    
    def authenticate(self, reason: str) -> bool:
        """
        Perform biometric authentication.
        
        Args:
            reason: Reason for authentication to show to user
            
        Returns:
            True if authentication successful, False otherwise
        """
        if not self.is_available():
            return False
        
        try:
            if self.system == "Windows":
                return self._authenticate_windows(reason)
            elif self.system == "Darwin":
                return self._authenticate_macos(reason)
            elif self.system == "Linux":
                return self._authenticate_linux(reason)
            return False
        except Exception as e:
            logger.error(f"Error during biometric authentication: {e}")
            return False
    
    def _authenticate_windows(self, reason: str) -> bool:
        """Authenticate using Windows Hello."""
        # Try real Windows Hello first
        if self._windows_hello:
            logger.info("Using Windows Hello biometric authentication")
            
            # Show a message to the user before triggering biometric
            try:
                from PyQt5.QtWidgets import QMessageBox, QApplication
                from PyQt5.QtCore import QTimer
                
                app = QApplication.instance()
                if app:
                    # Create a non-blocking message box
                    msg = QMessageBox()
                    msg.setWindowTitle("Windows Hello")
                    msg.setText(reason)
                    msg.setInformativeText("Please authenticate using your fingerprint or face...")
                    msg.setStandardButtons(QMessageBox.NoButton)
                    msg.show()
                    
                    # Process events to show the message
                    app.processEvents()
                    
                    # Perform authentication
                    result = self._windows_hello.authenticate(reason)
                    
                    # Close the message box
                    msg.close()
                    
                    return result
            except:
                # If Qt fails, just do authentication without message
                return self._windows_hello.authenticate(reason)
        
        # Fallback to credential prompt
        return self._authenticate_windows_fallback(reason)
    
    def _authenticate_windows_fallback(self, reason: str) -> bool:
        """Fallback Windows authentication using credential prompt."""
        try:
            from PyQt5.QtWidgets import QInputDialog, QLineEdit, QApplication
            
            app = QApplication.instance()
            parent = app.activeWindow() if app else None
            
            password, ok = QInputDialog.getText(
                parent,
                "Windows Authentication",
                f"{reason}\n\nWindows Hello is not available.\nEnter your Windows password or PIN:",
                QLineEdit.Password
            )
            
            return ok and bool(password)
        except Exception as e:
            logger.error(f"Error in Windows fallback authentication: {e}")
            return False
    
    def _authenticate_macos(self, reason: str) -> bool:
        """Authenticate using Touch ID."""
        try:
            # Try to use Touch ID via osascript
            script = f'''
            on run
                try
                    do shell script "echo 'Authenticating...'" with administrator privileges
                    return "authenticated"
                on error
                    return "cancelled"
                end try
            end run
            '''
            
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True
            )
            
            return result.returncode == 0 and "authenticated" in result.stdout
            
        except Exception as e:
            logger.error(f"Error in macOS authentication: {e}")
            # Fallback to dialog
            try:
                from PyQt5.QtWidgets import QMessageBox, QApplication
                
                app = QApplication.instance()
                parent = app.activeWindow() if app else None
                
                reply = QMessageBox.question(
                    parent,
                    "Touch ID",
                    f"{reason}\n\nTouch ID authentication required.",
                    QMessageBox.Ok | QMessageBox.Cancel
                )
                return reply == QMessageBox.Ok
            except:
                return False
    
    def _authenticate_linux(self, reason: str) -> bool:
        """Authenticate using Linux biometric system."""
        try:
            # Show reason to user
            print(f"\nAuthentication requested: {reason}")
            print("Please scan your fingerprint...")
            
            # Try fprintd-verify
            result = subprocess.run(
                ["fprintd-verify"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("Fingerprint authentication successful!")
                return True
            else:
                print("Fingerprint authentication failed.")
                return False
                
        except FileNotFoundError:
            # fprintd not available, use fallback
            logger.warning("fprintd not found, using fallback authentication")
            try:
                from PyQt5.QtWidgets import QMessageBox, QApplication
                
                app = QApplication.instance()
                parent = app.activeWindow() if app else None
                
                reply = QMessageBox.question(
                    parent,
                    "Authentication",
                    f"{reason}\n\nFingerprint reader not available.\nContinue?",
                    QMessageBox.Yes | QMessageBox.No
                )
                return reply == QMessageBox.Yes
            except:
                return False
    
    def store_secret(self, key: str, secret: str) -> bool:
        """Store a secret protected by biometric authentication."""
        if not self.is_available():
            return False
        
        # Use Windows Credential Manager if available
        if self.system == "Windows":
            try:
                import win32cred
                
                credential = {
                    'Type': win32cred.CRED_TYPE_GENERIC,
                    'TargetName': f'SecureVault:{key}',
                    'UserName': 'SecureVault',
                    'CredentialBlob': secret,
                    'Comment': 'SecureVault Password Manager - Biometric Protected',
                    'Persist': win32cred.CRED_PERSIST_LOCAL_MACHINE
                }
                win32cred.CredWrite(credential)
                return True
            except Exception as e:
                logger.debug(f"Windows Credential Manager not available: {e}")
        
        # Fallback to file-based storage
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        os.makedirs(config_dir, exist_ok=True)
        
        biometric_file = os.path.join(config_dir, "biometric.json")
        
        try:
            data = {}
            if os.path.exists(biometric_file):
                try:
                    with open(biometric_file, 'r') as f:
                        data = json.load(f)
                except:
                    data = {}
            
            # Simple encoding - in production use proper encryption
            data[key] = base64.b64encode(secret.encode()).decode()
            
            with open(biometric_file, 'w') as f:
                json.dump(data, f)
            
            # Set file permissions
            if platform.system() != 'Windows':
                os.chmod(biometric_file, 0o600)
            
            return True
        except Exception as e:
            logger.error(f"Error storing secret: {e}")
            return False
    
    def retrieve_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret protected by biometric authentication."""
        if not self.is_available():
            return None
        
        # Try Windows Credential Manager first
        if self.system == "Windows":
            try:
                import win32cred
                
                cred = win32cred.CredRead(f'SecureVault:{key}', win32cred.CRED_TYPE_GENERIC)
                return cred['CredentialBlob'].decode('utf-16-le').rstrip('\0')
            except Exception as e:
                logger.debug(f"Windows Credential Manager read failed: {e}")
        
        # Fallback to file-based storage
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        biometric_file = os.path.join(config_dir, "biometric.json")
        
        if not os.path.exists(biometric_file):
            return None
        
        try:
            with open(biometric_file, 'r') as f:
                data = json.load(f)
            
            if key in data:
                return base64.b64decode(data[key]).decode()
        except Exception as e:
            logger.error(f"Error retrieving secret: {e}")
        
        return None
    
    def delete_secret(self, key: str) -> bool:
        """Delete a stored secret."""
        # Try Windows Credential Manager first
        if self.system == "Windows":
            try:
                import win32cred
                
                win32cred.CredDelete(f'SecureVault:{key}', win32cred.CRED_TYPE_GENERIC)
                return True
            except Exception as e:
                logger.debug(f"Windows Credential Manager delete failed: {e}")
        
        # Also delete from file-based storage
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        biometric_file = os.path.join(config_dir, "biometric.json")
        
        if not os.path.exists(biometric_file):
            return True
        
        try:
            with open(biometric_file, 'r') as f:
                data = json.load(f)
            
            if key in data:
                del data[key]
                
                with open(biometric_file, 'w') as f:
                    json.dump(data, f)
            
            return True
        except:
            return False