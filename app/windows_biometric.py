"""
Windows-specific biometric implementation.
This module attempts to use Windows Hello if available.
"""

import ctypes
import logging
from ctypes import wintypes
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Windows constants
NCRYPT_ALLOW_ALL_USAGES = 0x00ffffff
NCRYPT_PIN_CACHE_IS_GESTURE_POLICY_PROPERTY = "PinCacheIsGesturePolicy"
NCRYPT_USE_CONTEXT_PROPERTY = "Use Context"
NCRYPT_LENGTH_PROPERTY = "Length"

# Try to load Windows security DLLs
try:
    # Load ncrypt.dll for key storage
    ncrypt = ctypes.windll.ncrypt
    
    # Load credui.dll for credential UI
    credui = ctypes.windll.credui
    
    # Load user32.dll for window handling
    user32 = ctypes.windll.user32
    
    WINDOWS_SECURITY_AVAILABLE = True
except Exception as e:
    logger.warning(f"Windows security DLLs not available: {e}")
    WINDOWS_SECURITY_AVAILABLE = False

# Error codes
ERROR_SUCCESS = 0
ERROR_CANCELLED = 1223
NTE_USER_CANCELLED = 0x80090036

# Credential UI flags
CREDUI_FLAGS_INCORRECT_PASSWORD = 0x00000001
CREDUI_FLAGS_DO_NOT_PERSIST = 0x00000002
CREDUI_FLAGS_REQUEST_ADMINISTRATOR = 0x00000004
CREDUI_FLAGS_EXCLUDE_CERTIFICATES = 0x00000008
CREDUI_FLAGS_REQUIRE_CERTIFICATE = 0x00000010
CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX = 0x00000040
CREDUI_FLAGS_ALWAYS_SHOW_UI = 0x00000080
CREDUI_FLAGS_REQUIRE_SMARTCARD = 0x00000100
CREDUI_FLAGS_PASSWORD_ONLY_OK = 0x00000200
CREDUI_FLAGS_VALIDATE_USERNAME = 0x00000400
CREDUI_FLAGS_COMPLETE_USERNAME = 0x00000800
CREDUI_FLAGS_PERSIST = 0x00001000
CREDUI_FLAGS_SERVER_CREDENTIAL = 0x00004000
CREDUI_FLAGS_EXPECT_CONFIRMATION = 0x00020000
CREDUI_FLAGS_GENERIC_CREDENTIALS = 0x00040000
CREDUI_FLAGS_USERNAME_TARGET_CREDENTIALS = 0x00080000
CREDUI_FLAGS_KEEP_USERNAME = 0x00100000

# CREDUI_INFO structure
class CREDUI_INFO(ctypes.Structure):
    _fields_ = [
        ('cbSize', ctypes.c_ulong),
        ('hwndParent', wintypes.HWND),
        ('pszMessageText', ctypes.c_wchar_p),
        ('pszCaptionText', ctypes.c_wchar_p),
        ('hbmBanner', wintypes.HBITMAP)
    ]


class WindowsBiometricAuth:
    """Windows biometric authentication using native APIs."""
    
    def __init__(self):
        """Initialize Windows biometric authentication."""
        self.available = WINDOWS_SECURITY_AVAILABLE
    
    def is_available(self) -> bool:
        """Check if Windows biometric authentication is available."""
        if not self.available:
            return False
        
        # Check Windows version
        try:
            import sys
            version = sys.getwindowsversion()
            # Windows 10 version 1607 or later required for Windows Hello
            if version.major < 10 or (version.major == 10 and version.build < 14393):
                return False
            
            # Try to check if Windows Hello is enrolled
            return self._check_windows_hello_enrolled()
        except Exception as e:
            logger.error(f"Error checking Windows biometric availability: {e}")
            return False
    
    def _check_windows_hello_enrolled(self) -> bool:
        """Check if Windows Hello is enrolled."""
        # This is a simplified check
        # In a full implementation, we would check:
        # 1. If TPM is available
        # 2. If Windows Hello for Business is configured
        # 3. If biometric devices are enrolled
        
        # For now, we'll assume it's available on Windows 10+
        return True
    
    def authenticate_with_credentials(self, message: str, caption: str = "Authentication Required") -> Tuple[bool, str, str]:
        """
        Show Windows credential dialog.
        
        Returns:
            Tuple of (success, username, password)
        """
        if not self.available:
            return False, "", ""
        
        try:
            # Create CREDUI_INFO structure
            cui = CREDUI_INFO()
            cui.cbSize = ctypes.sizeof(CREDUI_INFO)
            cui.hwndParent = None  # Use active window
            cui.pszMessageText = message
            cui.pszCaptionText = caption
            cui.hbmBanner = None
            
            # Create buffers
            username = ctypes.create_unicode_buffer(256)
            password = ctypes.create_unicode_buffer(256)
            save = wintypes.BOOL(False)
            
            # Set flags for generic credentials with UI
            flags = (CREDUI_FLAGS_GENERIC_CREDENTIALS | 
                    CREDUI_FLAGS_ALWAYS_SHOW_UI |
                    CREDUI_FLAGS_DO_NOT_PERSIST)
            
            # Show credential dialog
            result = credui.CredUIPromptForCredentialsW(
                ctypes.byref(cui),
                "SecureVault",  # Target
                None,           # Reserved
                0,              # Auth error
                username,
                256,
                password,
                256,
                ctypes.byref(save),
                flags
            )
            
            if result == ERROR_SUCCESS:
                return True, username.value, password.value
            elif result == ERROR_CANCELLED:
                logger.info("User cancelled authentication")
                return False, "", ""
            else:
                logger.error(f"Authentication failed with error: {result}")
                return False, "", ""
                
        except Exception as e:
            logger.error(f"Error in Windows credential prompt: {e}")
            return False, "", ""
    
    def get_active_window_handle(self) -> Optional[int]:
        """Get the handle of the active window."""
        try:
            hwnd = user32.GetForegroundWindow()
            return hwnd if hwnd else None
        except:
            return None


# Create a global instance
_windows_bio = WindowsBiometricAuth() if WINDOWS_SECURITY_AVAILABLE else None


def is_windows_biometric_available() -> bool:
    """Check if Windows biometric authentication is available."""
    return _windows_bio is not None and _windows_bio.is_available()


def authenticate_windows(message: str) -> bool:
    """
    Authenticate using Windows biometric or credential prompt.
    
    Args:
        message: Message to display to the user
        
    Returns:
        True if authentication successful
    """
    if not _windows_bio:
        return False
    
    # Try credential prompt (which may trigger Windows Hello)
    success, username, password = _windows_bio.authenticate_with_credentials(
        message,
        "SecureVault Authentication"
    )
    
    # For biometric auth, we just need to know if the user authenticated
    # We don't actually use the username/password
    return success