import platform
import os
import logging

logger = logging.getLogger(__name__)

if platform.system() == "Windows":
    try:
        import win32security
        import win32api
        import win32con
        WINDOWS_SECURITY_AVAILABLE = True
    except ImportError:
        logger.warning("pywin32 not fully installed, cannot set Windows file permissions securely.")
        WINDOWS_SECURITY_AVAILABLE = False
else:
    WINDOWS_SECURITY_AVAILABLE = False

def _set_windows_file_permissions(filepath: str) -> None:
    """
    Sets restrictive permissions on a file for Windows, granting full control
    only to the current user/owner and removing access for others.
    """
    if not WINDOWS_SECURITY_AVAILABLE:
        logger.warning(f"Skipping Windows file permission setting for {filepath}: pywin32 not available.")
        return

    try:
        # Get the SID of the current user
        current_user_name = win32api.GetUserName()
        domain_name = win32api.GetComputerName()
        current_user_sid, _, _ = win32security.LookupAccountName(None, current_user_name)

        # Get the existing security descriptor
        sd = win32security.GetFileSecurity(filepath, win32security.DACL_SECURITY_INFORMATION)
        dacl = win32security.ACL()

        # Add access allowed ACE for the current user (full control)
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.FILE_GENERIC_READ | win32con.FILE_GENERIC_WRITE | win32con.FILE_GENERIC_EXECUTE,
            current_user_sid
        )

        # Set the new DACL
        win32security.SetFileSecurity(filepath, win32security.DACL_SECURITY_INFORMATION, sd)
        win32security.SetSecurityInfo(
            filepath,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None
        )
        logger.info(f"Set restrictive permissions for {filepath} on Windows.")
    except Exception as e:
        logger.error(f"Failed to set Windows file permissions for {filepath}: {e}")

