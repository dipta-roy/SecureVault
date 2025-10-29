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
from PyQt5.QtGui import QIcon

from app.ui import MainWindow, LoginDialog, StartupDialog
from app.storage import StorageManager
from app import config
from app import vault_manager


class PasswordManagerApp:
    """Main application class for the password manager."""
    
    def __init__(self):
        """Initialize the application."""
        self.app = QApplication(sys.argv)
        self.app.setApplicationName(config.APP_NAME)
        self.app.setOrganizationName(config.APP_NAME)
        
        # Set application icon
        if getattr(sys, '_MEIPASS', False):
            # Running as a PyInstaller bundle
            icon_path = os.path.join(sys._MEIPASS, config.APP_ICON_PATH)
        else:
            # Running from source
            icon_path = config.APP_ICON_PATH
        self.app.setWindowIcon(QIcon(icon_path))
        
        # Set application style
        self.app.setStyle(config.APP_STYLE)
        
        # Storage
        self.storage_path = self._get_default_storage_path()
        self.running = True
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
        app_dir = os.path.join(home, config.CONFIG_DIR_NAME)
        
        # Create directory if it doesn't exist
        os.makedirs(app_dir, exist_ok=True)
        
        return os.path.join(app_dir, config.DEFAULT_VAULT_FILE)
    
    def _get_last_used_vault(self) -> Optional[str]:
        """Get the path of the last used vault."""
        recent_vaults = vault_manager.get_recent_vault_paths()
        if recent_vaults:
            return recent_vaults[0]
        return None
    
    def _save_last_used_vault(self, path: str):
        """Save the last used vault path."""
        vault_manager.save_recent_vault_path(path)
    
    def _start_new_session(self) -> bool:
        """Handles the vault selection and login process."""
        self.startup_dialog = StartupDialog(self.storage_path)
        if self.startup_dialog.exec_():
            vault_path = self.startup_dialog.selected_path
            if not vault_path: # User selected to create a new vault but didn't provide a path
                self.running = False
                return False
        else:
            # User cancelled startup dialog, terminate app
            self.running = False
            return False
        
        self.storage = StorageManager(vault_path)
        self._save_last_used_vault(vault_path)
        
        self.login_dialog = LoginDialog(self.storage)
        if self.login_dialog.exec_():
            # Login successful
            self.main_window = MainWindow(self.storage)
            self.main_window.return_to_start_screen.connect(lambda: self._handle_main_window_closed(False))
            self.main_window.exit_application.connect(lambda: self._handle_main_window_closed(True))
            self.main_window.show()
            return True
        else:
            # Login cancelled or returned to start screen
            if self.login_dialog.returned_to_start:
                return True # Go back to StartupDialog
            else:
                # User cancelled login, terminate app
                self.running = False
                return False

    def _handle_main_window_closed(self, should_exit_app: bool):
        """Handles the signal when the main window is closed."""
        if self.main_window:
            self.main_window.close()
            self.main_window = None
        
        if should_exit_app:
            self.running = False # Signal to exit
        else:
            self.running = True # Signal to return to STARTUP

    def run(self) -> int:
        """Run the application."""
        current_state = "STARTUP"
        
        while current_state != "EXIT":
            if current_state == "STARTUP":
                self.startup_dialog = StartupDialog(self.storage_path)
                if self.startup_dialog.exec_():
                    vault_path = self.startup_dialog.selected_path
                    if not vault_path:
                        current_state = "EXIT" # User selected to create a new vault but didn't provide a path
                    else:
                        self.storage = StorageManager(vault_path)
                        self._save_last_used_vault(vault_path)
                        current_state = "LOGIN"
                else:
                    current_state = "EXIT" # User cancelled startup dialog
            
            elif current_state == "LOGIN":
                self.login_dialog = LoginDialog(self.storage)
                if self.login_dialog.exec_():
                    current_state = "MAIN_WINDOW" # Login successful
                else:
                    if self.login_dialog.returned_to_start:
                        current_state = "STARTUP" # Go back to StartupDialog
                    else:
                        current_state = "EXIT" # User cancelled login
            
            elif current_state == "MAIN_WINDOW":
                self.main_window = MainWindow(self.storage)
                self.main_window.return_to_start_screen.connect(lambda: self._handle_main_window_closed(False))
                self.main_window.exit_application.connect(lambda: self._handle_main_window_closed(True))
                self.main_window.show()
                self.app.exec_() # Start event loop for MainWindow
                
                # After app.exec_() returns (MainWindow closed)
                if self.running: # If self.running is True, it means return_to_start_screen was emitted
                    current_state = "STARTUP"
                    self.running = False # Reset for next loop iteration
                else: # If self.running is False, it means exit_application was emitted
                    current_state = "EXIT"
            
        return 0
    
    def cleanup(self):
        """Clean up resources."""
        if self.storage is not None and self.storage.is_unlocked():
            self.storage.lock()


def main():
    """Main entry point."""
    import logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
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