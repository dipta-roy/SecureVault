"""
Real Windows Hello biometric implementation using Windows Biometric Framework.
This will actually trigger fingerprint/face recognition on Windows.
"""

import ctypes
import logging
import uuid
from ctypes import wintypes, POINTER, Structure, c_void_p
from typing import Optional, Callable
from enum import IntEnum

logger = logging.getLogger(__name__)

# Load Windows DLLs
try:
    winbio = ctypes.windll.winbio
    kernel32 = ctypes.windll.kernel32
    WINBIO_AVAILABLE = True
except:
    WINBIO_AVAILABLE = False
    logger.warning("Windows Biometric Framework not available")

# Windows Biometric Framework Constants
WINBIO_TYPE_MULTIPLE = 0x00000001
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_TYPE_FACIAL_FEATURES = 0x00000002
WINBIO_TYPE_VOICE = 0x00000004
WINBIO_TYPE_IRIS = 0x00000010

WINBIO_POOL_SYSTEM = 1
WINBIO_POOL_PRIVATE = 2

WINBIO_FLAG_DEFAULT = 0x00000000
WINBIO_FLAG_BASIC = 0x00010000
WINBIO_FLAG_ADVANCED = 0x00020000
WINBIO_FLAG_RAW = 0x00040000
WINBIO_FLAG_MAINTENANCE = 0x00080000

# Purpose constants
WINBIO_PURPOSE_VERIFY = 1
WINBIO_PURPOSE_IDENTIFY = 2
WINBIO_PURPOSE_ENROLL = 3
WINBIO_PURPOSE_ENROLL_FOR_VERIFICATION = 4
WINBIO_PURPOSE_ENROLL_FOR_IDENTIFICATION = 5

# Error codes
S_OK = 0
WINBIO_E_CANCELED = 0x80098004
WINBIO_E_NO_MATCH = 0x80098005
WINBIO_E_CAPTURE_ABORTED = 0x80098006

# Structures
class WINBIO_VERSION(Structure):
    _fields_ = [
        ("MajorVersion", wintypes.DWORD),
        ("MinorVersion", wintypes.DWORD)
    ]

class WINBIO_IDENTITY(Structure):
    _fields_ = [
        ("Type", wintypes.DWORD),
        ("Null", wintypes.DWORD),
        ("Wildcard", wintypes.DWORD),
        ("TemplateGuid", ctypes.c_ubyte * 16),
        ("AccountSid", c_void_p)
    ]

class WINBIO_UNIT_SCHEMA(Structure):
    _fields_ = [
        ("UnitId", wintypes.DWORD),
        ("PoolType", wintypes.DWORD),
        ("BiometricFactor", wintypes.DWORD),
        ("SensorSubType", wintypes.DWORD),
        ("Capabilities", wintypes.DWORD),
        ("DeviceInstanceId", wintypes.LPWSTR),
        ("Description", wintypes.LPWSTR),
        ("Manufacturer", wintypes.LPWSTR),
        ("Model", wintypes.LPWSTR),
        ("SerialNumber", wintypes.LPWSTR),
        ("FirmwareVersion", WINBIO_VERSION),
    ]

# Function prototypes
if WINBIO_AVAILABLE:
    # WinBioOpenSession
    winbio.WinBioOpenSession.argtypes = [
        wintypes.DWORD,  # Factor
        wintypes.DWORD,  # PoolType
        wintypes.DWORD,  # Flags
        POINTER(wintypes.DWORD),  # UnitArray
        wintypes.DWORD,  # UnitCount
        c_void_p,  # DatabaseId
        POINTER(wintypes.HANDLE)  # SessionHandle
    ]
    winbio.WinBioOpenSession.restype = wintypes.DWORD

    # WinBioCloseSession
    winbio.WinBioCloseSession.argtypes = [wintypes.HANDLE]
    winbio.WinBioCloseSession.restype = wintypes.DWORD

    # WinBioVerify
    winbio.WinBioVerify.argtypes = [
        wintypes.HANDLE,  # SessionHandle
        POINTER(WINBIO_IDENTITY),  # Identity
        wintypes.DWORD,  # SubFactor
        POINTER(wintypes.DWORD),  # UnitId
        POINTER(wintypes.BOOLEAN),  # Match
        POINTER(wintypes.DWORD),  # RejectDetail
    ]
    winbio.WinBioVerify.restype = wintypes.DWORD

    # WinBioEnumBiometricUnits
    winbio.WinBioEnumBiometricUnits.argtypes = [
        wintypes.DWORD,  # Factor
        POINTER(POINTER(WINBIO_UNIT_SCHEMA)),  # UnitSchemaArray
        POINTER(wintypes.DWORD),  # UnitCount
    ]
    winbio.WinBioEnumBiometricUnits.restype = wintypes.DWORD

    # WinBioFree
    winbio.WinBioFree.argtypes = [c_void_p]
    winbio.WinBioFree.restype = wintypes.DWORD


class WindowsHelloBiometric:
    """Real Windows Hello biometric authentication."""
    
    def __init__(self):
        """Initialize Windows Hello biometric."""
        self.available = WINBIO_AVAILABLE
        self._session_handle = None
        self._has_fingerprint = False
        self._has_face = False
        
        if self.available:
            self._check_biometric_units()
    
    def _check_biometric_units(self):
        """Check what biometric units are available."""
        try:
            # Check for fingerprint readers
            unit_array = POINTER(WINBIO_UNIT_SCHEMA)()
            unit_count = wintypes.DWORD(0)
            
            result = winbio.WinBioEnumBiometricUnits(
                WINBIO_TYPE_FINGERPRINT,
                ctypes.byref(unit_array),
                ctypes.byref(unit_count)
            )
            
            if result == S_OK and unit_count.value > 0:
                self._has_fingerprint = True
                logger.info(f"Found {unit_count.value} fingerprint reader(s)")
                
                # Free the array
                winbio.WinBioFree(unit_array)
            
            # Check for face recognition
            unit_array = POINTER(WINBIO_UNIT_SCHEMA)()
            unit_count = wintypes.DWORD(0)
            
            result = winbio.WinBioEnumBiometricUnits(
                WINBIO_TYPE_FACIAL_FEATURES,
                ctypes.byref(unit_array),
                ctypes.byref(unit_count)
            )
            
            if result == S_OK and unit_count.value > 0:
                self._has_face = True
                logger.info(f"Found {unit_count.value} facial recognition camera(s)")
                
                # Free the array
                winbio.WinBioFree(unit_array)
                
        except Exception as e:
            logger.error(f"Error checking biometric units: {e}")
    
    def is_available(self) -> bool:
        """Check if biometric authentication is available."""
        return self.available and (self._has_fingerprint or self._has_face)
    
    def get_available_types(self) -> str:
        """Get string describing available biometric types."""
        types = []
        if self._has_fingerprint:
            types.append("Fingerprint")
        if self._has_face:
            types.append("Face Recognition")
        
        return ", ".join(types) if types else "None"
    
    def authenticate(self, reason: str) -> bool:
        """
        Perform biometric authentication using Windows Hello.
        
        Args:
            reason: Message to display (note: Windows Hello doesn't show custom messages)
            
        Returns:
            True if authentication successful
        """
        if not self.is_available():
            return False
        
        session_handle = wintypes.HANDLE()
        
        try:
            # Determine which biometric type to use
            biometric_type = WINBIO_TYPE_MULTIPLE  # Let Windows choose
            if self._has_fingerprint and not self._has_face:
                biometric_type = WINBIO_TYPE_FINGERPRINT
            elif self._has_face and not self._has_fingerprint:
                biometric_type = WINBIO_TYPE_FACIAL_FEATURES
            
            # Open biometric session
            result = winbio.WinBioOpenSession(
                biometric_type,
                WINBIO_POOL_SYSTEM,
                WINBIO_FLAG_DEFAULT,
                None,  # Use all units
                0,     # Unit count
                None,  # Default database
                ctypes.byref(session_handle)
            )
            
            if result != S_OK:
                logger.error(f"Failed to open biometric session: 0x{result:08X}")
                return False
            
            logger.info("Biometric session opened, waiting for user authentication...")
            
            # Create identity for current user
            identity = WINBIO_IDENTITY()
            identity.Type = 1  # WINBIO_ID_TYPE_WILDCARD
            identity.Wildcard = 1
            
            # Verify biometric
            unit_id = wintypes.DWORD()
            match = wintypes.BOOLEAN()
            reject_detail = wintypes.DWORD()
            
            # This will trigger the actual biometric prompt
            result = winbio.WinBioVerify(
                session_handle,
                ctypes.byref(identity),
                0,  # WINBIO_SUBTYPE_ANY
                ctypes.byref(unit_id),
                ctypes.byref(match),
                ctypes.byref(reject_detail)
            )
            
            # Check result
            if result == S_OK:
                logger.info(f"Biometric verification completed. Match: {bool(match)}")
                return bool(match)
            elif result == WINBIO_E_CANCELED:
                logger.info("User cancelled biometric authentication")
                return False
            elif result == WINBIO_E_NO_MATCH:
                logger.info("Biometric did not match")
                return False
            else:
                logger.error(f"Biometric verification failed: 0x{result:08X}")
                return False
                
        except Exception as e:
            logger.error(f"Error during biometric authentication: {e}")
            return False
            
        finally:
            # Close session
            if session_handle:
                winbio.WinBioCloseSession(session_handle)


# Also try Windows Hello for Business API
try:
    from ctypes import wintypes
    import comtypes
    import comtypes.client
    from comtypes import GUID, COMMETHOD, HRESULT
    from comtypes.automation import IDispatch
    
    # Windows Hello for Business constants
    CLSID_UserConsentVerifier = GUID("{C0B2C582-A2E2-4D28-8C98-7D0EF3F52B08}")
    IID_IUserConsentVerifier = GUID("{39AAC9A8-7D66-4829-AF28-DE816B7E3C66}")
    
    WHB_AVAILABLE = True
except:
    WHB_AVAILABLE = False


def create_windows_hello_authenticator():
    """Create the appropriate Windows Hello authenticator."""
    # Try Windows Biometric Framework first
    if WINBIO_AVAILABLE:
        bio = WindowsHelloBiometric()
        if bio.is_available():
            logger.info(f"Windows Hello biometric available: {bio.get_available_types()}")
            return bio
    
    logger.info("Windows Hello biometric not available")
    return None