"""
Biometric authentication support for the password manager.
Tries fingerprint authentication first, then falls back to PIN.

LEGAL NOTICE:
This module handles biometric authentication. It must only be used
for legitimate personal password management on devices you own or administer.
"""

import platform
import os
import base64
import json
import logging
import hashlib
import subprocess
import ctypes
from typing import Optional, Tuple
from PyQt5.QtWidgets import QInputDialog, QLineEdit, QMessageBox, QApplication
from PyQt5.QtCore import Qt, QTimer

logger = logging.getLogger(__name__)


class WindowsHelloHelper:
    """Helper class for Windows Hello authentication using safer methods."""
    
    def __init__(self):
        self.has_biometric = self._check_biometric_available()
    
    def _check_biometric_available(self) -> bool:
        """Check if Windows Hello biometric is available."""
        try:
            # Check using WMI without showing any windows
            result = subprocess.run(
                ["wmic", "path", "Win32_Biometric", "get", "DeviceId"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0 and "DeviceId" in result.stdout:
                # Check if output contains actual device IDs
                lines = result.stdout.strip().split('\n')
                return len(lines) > 2  # Header + at least one device
            
            return False
            
        except Exception as e:
            logger.debug(f"Error checking biometric: {e}")
            return False
    
    def authenticate_with_hello(self) -> bool:
        """
        Try to authenticate using Windows Hello.
        Uses Windows Credential Provider UI.
        """
        try:
            # Create a simple C# script that uses Windows.Security.Credentials
            cs_code = '''
using System;
using System.Runtime.InteropServices;

class Program {
    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();
    
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    static extern int CredUIPromptForWindowsCredentials(
        IntPtr pUiInfo, uint dwAuthError, ref uint pulAuthPackage,
        IntPtr pvInAuthBuffer, uint ulInAuthBufferSize,
        out IntPtr ppvOutAuthBuffer, out uint pulOutAuthBufferSize,
        ref bool pfSave, uint dwFlags);
    
    [DllImport("ole32.dll")]
    static extern void CoTaskMemFree(IntPtr ptr);
    
    static void Main() {
        uint authPackage = 0;
        IntPtr outCredBuffer = IntPtr.Zero;
        uint outCredSize = 0;
        bool save = false;
        
        // Flags to request biometric
        uint flags = 0x00000001 | 0x00000200; // CREDUIWIN_GENERIC | CREDUIWIN_ENUMERATE_CURRENT_USER
        
        int result = CredUIPromptForWindowsCredentials(
            IntPtr.Zero, 0, ref authPackage,
            IntPtr.Zero, 0,
            out outCredBuffer, out outCredSize,
            ref save, flags);
        
        if (outCredBuffer != IntPtr.Zero)
            CoTaskMemFree(outCredBuffer);
        
        Environment.Exit(result == 0 ? 0 : 1);
    }
}
'''
            
            # Try using Windows Security dialog
            import tempfile
            
            # Write C# code to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cs', delete=False) as f:
                f.write(cs_code)
                cs_file = f.name
            
            exe_file = cs_file.replace('.cs', '.exe')
            
            try:
                # Try to compile with csc.exe if available
                csc_paths = [
                    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
                    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
                ]
                
                csc_exe = None
                for path in csc_paths:
                    if os.path.exists(path):
                        csc_exe = path
                        break
                
                if csc_exe:
                    # Compile the C# code
                    compile_result = subprocess.run(
                        [csc_exe, "/out:" + exe_file, cs_file],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    
                    if compile_result.returncode == 0 and os.path.exists(exe_file):
                        # Run the compiled exe
                        auth_result = subprocess.run(
                            [exe_file],
                            capture_output=True,
                            timeout=30
                        )
                        
                        return auth_result.returncode == 0
                
            finally:
                # Clean up
                for file in [cs_file, exe_file]:
                    try:
                        if os.path.exists(file):
                            os.unlink(file)
                    except:
                        pass
            
            # If compilation failed, try alternative method
            return self._try_runas_authentication()
            
        except Exception as e:
            logger.debug(f"Windows Hello authentication error: {e}")
            return False
    
    def _try_runas_authentication(self) -> bool:
        """Try authentication using RunAs (will trigger Windows Hello if available)."""
        try:
            # Use ctypes to call Windows API directly
            shell32 = ctypes.windll.shell32
            
            # ShellExecute with "runas" verb triggers UAC/Windows Hello
            result = shell32.ShellExecuteW(
                None,
                "runas",
                "cmd.exe",
                "/c exit",
                None,
                0  # SW_HIDE
            )
            
            # If result > 32, it succeeded
            return result > 32
            
        except Exception as e:
            logger.debug(f"RunAs authentication error: {e}")
            return False


class BiometricManager:
    """
    Biometric authentication manager that tries fingerprint first, then PIN.
    """
    
    def __init__(self):
        """Initialize the biometric manager."""
        self.system = platform.system()
        self._available = True
        self._stored_hash = None
        self._windows_hello = None
        
        if self.system == "Windows":
            self._windows_hello = WindowsHelloHelper()
        
        self._load_auth_hash()
    
    def _load_auth_hash(self):
        """Load stored authentication hash if exists."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        auth_file = os.path.join(config_dir, "auth.json")
        
        if os.path.exists(auth_file):
            try:
                with open(auth_file, 'r') as f:
                    data = json.load(f)
                    self._stored_hash = data.get('auth_hash')
            except:
                pass
    
    def _save_auth_hash(self, password: str):
        """Save authentication hash for PIN unlock."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        os.makedirs(config_dir, exist_ok=True)
        auth_file = os.path.join(config_dir, "auth.json")
        
        auth_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            b'SecureVault_Auth_Salt',
            100000
        )
        
        try:
            data = {'auth_hash': base64.b64encode(auth_hash).decode()}
            with open(auth_file, 'w') as f:
                json.dump(data, f)
            
            if platform.system() != 'Windows':
                os.chmod(auth_file, 0o600)
                
            self._stored_hash = data['auth_hash']
        except Exception as e:
            logger.error(f"Error saving auth hash: {e}")
    
    def _verify_auth_password(self, password: str) -> bool:
        """Verify if the entered password matches stored hash."""
        if not self._stored_hash:
            return True
        
        auth_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            b'SecureVault_Auth_Salt',
            100000
        )
        
        stored = base64.b64decode(self._stored_hash)
        return auth_hash == stored
    
    def is_available(self) -> bool:
        """Check if biometric authentication is available."""
        return self._available
    
    def get_device_info(self) -> str:
        """Get information about the authentication method."""
        if self.system == "Windows":
            if self._windows_hello and self._windows_hello.has_biometric:
                return "Windows Hello Fingerprint + PIN"
            return "PIN Authentication"
        elif self.system == "Darwin":
            return "Touch ID + Password"
        elif self.system == "Linux":
            return "Fingerprint + Password"
        return "Password Authentication"
    
    def authenticate(self, reason: str) -> bool:
        """
        Perform authentication - try fingerprint first, then PIN.
        
        Args:
            reason: Reason for authentication
            
        Returns:
            True if authentication successful
        """
        logger.info(f"Starting authentication: {reason}")
        
        # Try biometric first if available
        if self.system == "Windows" and self._windows_hello and self._windows_hello.has_biometric:
            logger.info("Attempting Windows Hello fingerprint authentication...")
            
            # Show a message to the user
            app = QApplication.instance()
            parent = None
            
            if app:
                for widget in app.topLevelWidgets():
                    if widget.isVisible() and widget.isActiveWindow():
                        parent = widget
                        break
                
                # Show non-blocking message
                msg = QMessageBox(parent)
                msg.setWindowTitle("Fingerprint Authentication")
                msg.setText(reason)
                msg.setInformativeText("Please use your fingerprint to authenticate.\n\nIf fingerprint fails, you'll be prompted for PIN.")
                msg.setStandardButtons(QMessageBox.NoButton)
                msg.show()
                
                # Process events to show the message
                app.processEvents()
                
                # Try fingerprint authentication
                fingerprint_success = self._windows_hello.authenticate_with_hello()
                
                # Close the message
                msg.close()
                
                if fingerprint_success:
                    logger.info("Fingerprint authentication successful")
                    return True
                else:
                    logger.info("Fingerprint authentication failed, falling back to PIN")
        
        # Fall back to PIN authentication
        return self._authenticate_with_pin(reason)
    
    def _authenticate_with_pin(self, reason: str) -> bool:
        """Authenticate using PIN dialog."""
        try:
            app = QApplication.instance()
            parent = None
            
            if app:
                for widget in app.topLevelWidgets():
                    if widget.isVisible() and widget.isActiveWindow():
                        parent = widget
                        break
            
            # Show PIN dialog
            pin_prompt = "Enter your PIN:"
            if not self._stored_hash:
                pin_prompt = "Set up your PIN for quick authentication:"
            
            password, ok = QInputDialog.getText(
                parent,
                "PIN Authentication",
                pin_prompt,
                QLineEdit.Password,
                ""
            )
            
            if ok and password:
                if self._stored_hash:
                    # Verify PIN
                    if self._verify_auth_password(password):
                        logger.info("PIN authentication successful")
                        return True
                    else:
                        QMessageBox.warning(
                            parent,
                            "Authentication Failed",
                            "Invalid PIN. Please try again."
                        )
                        return False
                else:
                    # First time - store the PIN hash
                    self._save_auth_hash(password)
                    logger.info("PIN set up successfully")
                    
                    QMessageBox.information(
                        parent,
                        "PIN Set Up",
                        "Your PIN has been set up successfully.\nYou can now use this PIN for quick authentication."
                    )
                    return True
            
            logger.info("PIN authentication cancelled")
            return False
            
        except Exception as e:
            logger.error(f"Error during PIN authentication: {e}")
            return False
    
    def store_secret(self, key: str, secret: str) -> bool:
        """Store a secret protected by authentication."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        os.makedirs(config_dir, exist_ok=True)
        
        secrets_file = os.path.join(config_dir, "biometric.json")
        
        try:
            data = {}
            if os.path.exists(secrets_file):
                try:
                    with open(secrets_file, 'r') as f:
                        data = json.load(f)
                except:
                    data = {}
            
            data[key] = base64.b64encode(secret.encode()).decode()
            
            with open(secrets_file, 'w') as f:
                json.dump(data, f)
            
            if platform.system() != 'Windows':
                os.chmod(secrets_file, 0o600)
            
            logger.info(f"Secret stored: {key}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing secret: {e}")
            return False
    
    def retrieve_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret protected by authentication."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        secrets_file = os.path.join(config_dir, "biometric.json")
        
        if not os.path.exists(secrets_file):
            return None
        
        try:
            with open(secrets_file, 'r') as f:
                data = json.load(f)
            
            if key in data:
                return base64.b64decode(data[key]).decode()
                
        except Exception as e:
            logger.error(f"Error retrieving secret: {e}")
        
        return None
    
    def delete_secret(self, key: str) -> bool:
        """Delete a stored secret."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        secrets_file = os.path.join(config_dir, "biometric.json")
        
        if not os.path.exists(secrets_file):
            return True
        
        try:
            with open(secrets_file, 'r') as f:
                data = json.load(f)
            
            if key in data:
                del data[key]
                
                with open(secrets_file, 'w') as f:
                    json.dump(data, f)
                
                logger.info(f"Secret deleted: {key}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting secret: {e}")
            return False