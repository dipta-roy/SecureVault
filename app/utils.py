import platform
import os
import logging

logger = logging.getLogger(__name__)

if platform.system() == "Windows":
    try:
        import win32security
        import win32api
        import win32con
        import win32file
        WINDOWS_SECURITY_AVAILABLE = True
    except ImportError:
        logger.warning("pywin32 not fully installed, cannot set Windows file permissions securely.")
        WINDOWS_SECURITY_AVAILABLE = False
else:
    WINDOWS_SECURITY_AVAILABLE = False

def _set_windows_file_permissions(filepath: str) -> bool:
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
        current_user_sid, _, _ = win32security.LookupAccountName(None, current_user_name)

        # Create a new DACL
        dacl = win32security.ACL()

        # Add access allowed ACE for the current user (full control)
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.GENERIC_READ | win32con.GENERIC_WRITE | win32con.GENERIC_EXECUTE,
            current_user_sid
        )

        # Open the file to get a handle
        file_handle = win32file.CreateFile(
            filepath,
            win32con.WRITE_DAC, # Access for writing DACL
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE, # Allow sharing
            None, # Default security attributes
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None
        )

        try:
            # Set the new DACL using the file handle
            win32security.SetSecurityInfo(
                file_handle, # Pass the handle
                win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                dacl,
                None
            )
            logger.info(f"Set restrictive permissions for {filepath} on Windows.")
        finally:
            win32file.CloseHandle(file_handle)
    except Exception as e:
        if isinstance(e, win32api.error) and e.winerror == 5: # Access is denied
            logger.warning(f"Failed to set *additional* secure Windows file permissions for {filepath}: Access is denied. The file was created/updated, but its security could not be fully hardened. Consider running as administrator if this is a concern.")
            return True # File operation succeeded, but security hardening failed.
        else:
            logger.error(f"Failed to set Windows file permissions for {filepath}: {e}")
            return False
    return True