"""
Main entry point for the SecureVault Password Manager.

LEGAL NOTICE:
This tool is for personal use only. It must operate only on the device where 
it is installed and only with the explicit consent of the device owner. It must 
never be used to extract or exfiltrate passwords from devices you do not own or 
administer. The app requires the user to acknowledge a consent dialog before 
fetching browser passwords.
"""

import sys
import os
import signal
from typing import Optional
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from app.ui import MainWindow, LoginDialog, VaultSelectionDialog
from app.storage import StorageManager


class PasswordManagerApp:
    """Main application class for the password manager."""
    
    def __init__(self):
        """Initialize the application."""
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("SecureVault")
        self.app.setOrganizationName("SecureVault")
        
        # Set application style
        self.app.setStyle('Fusion')
        
        # Storage
        self.storage_path = self._get_default_storage_path()
        self.storage: Optional[StorageManager] = None
        
        # Windows
        self.vault_dialog: Optional[VaultSelectionDialog] = None
        self.login_dialog: Optional[LoginDialog] = None
        self.main_window: Optional[MainWindow] = None
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    def _get_default_storage_path(self) -> str:
        """Get the default path for the encrypted storage file."""
        # Use user's home directory
        home = os.path.expanduser("~")
        app_dir = os.path.join(home, ".securevault")
        
        # Create directory if it doesn't exist
        os.makedirs(app_dir, exist_ok=True)
        
        return os.path.join(app_dir, "vault.enc")
    
    def _get_last_used_vault(self) -> Optional[str]:
        """Get the path of the last used vault."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        last_vault_file = os.path.join(config_dir, "last_vault.txt")
        
        if os.path.exists(last_vault_file):
            try:
                with open(last_vault_file, 'r') as f:
                    path = f.read().strip()
                    if path and os.path.exists(path):
                        return path
            except:
                pass
        
        return None
    
    def _save_last_used_vault(self, path: str):
        """Save the last used vault path."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        os.makedirs(config_dir, exist_ok=True)
        last_vault_file = os.path.join(config_dir, "last_vault.txt")
        
        with open(last_vault_file, 'w') as f:
            f.write(path)
    
    def run(self) -> int:
        """Run the application."""
        # Check for last used vault
        last_vault = self._get_last_used_vault()
        
        if last_vault:
            # Use last vault
            vault_path = last_vault
        else:
            # Check if default vault exists
            if os.path.exists(self.storage_path):
                vault_path = self.storage_path
            else:
                # Show vault selection dialog
                self.vault_dialog = VaultSelectionDialog(self.storage_path)
                if self.vault_dialog.exec_():
                    vault_path = self.vault_dialog.selected_path or self.storage_path
                else:
                    # User cancelled, create default vault
                    vault_path = self.storage_path
        
        # Create storage manager
        self.storage = StorageManager(vault_path)
        self._save_last_used_vault(vault_path)
        
        # Show login dialog
        self.login_dialog = LoginDialog(self.storage)
        
        if self.login_dialog.exec_():
            # Login successful, show main window
            self.main_window = MainWindow(self.storage)
            self.main_window.show()
            
            # Run event loop
            return self.app.exec_()
        else:
            # Login cancelled
            return 0
    
    def cleanup(self):
        """Clean up resources."""
        if self.storage and self.storage.is_unlocked():
            self.storage.lock()


def main():
    """Main entry point."""
    # Enable high DPI scaling
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    # Create and run application
    app = PasswordManagerApp()
    
    try:
        return app.run()
    finally:
        app.cleanup()


if __name__ == "__main__":
    sys.exit(main())