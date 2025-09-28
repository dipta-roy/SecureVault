"""
User interface for the SecureVault Password Manager.

LEGAL NOTICE:
This tool is for personal use only. It must operate only on the device where 
it is installed and only with the explicit consent of the device owner. It must 
never be used to extract or exfiltrate passwords from devices you do not own or 
administer. The app requires the user to acknowledge a consent dialog before 
fetching browser passwords.
"""

import os
import sys
import uuid
import secrets
import string
import datetime
from typing import Optional, List, Dict, Any
from PyQt5.QtWidgets import (
    QMainWindow, QDialog, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QMessageBox, QFileDialog, QGroupBox, QCheckBox, QSpinBox, QTextEdit,
    QDialogButtonBox, QHeaderView, QMenu, QAction, QProgressDialog,
    QComboBox, QTabWidget, QFormLayout, QApplication, QInputDialog
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QIcon, QClipboard, QFont

from .storage import StorageManager, PasswordEntry
from .browser_import import BrowserImporter, CSVImporter
from .biometric import BiometricManager


class PasswordStrengthValidator:
    """Validates password strength."""
    
    @staticmethod
    def check_strength(password: str) -> tuple[bool, str]:
        """
        Check if password meets minimum requirements.
        
        Returns:
            Tuple of (is_strong, message)
        """
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        if not has_upper:
            return False, "Password must contain uppercase letters"
        if not has_lower:
            return False, "Password must contain lowercase letters"
        if not has_digit:
            return False, "Password must contain digits"
        if not has_special:
            return False, "Password must contain special characters"
        
        return True, "Password is strong"


class VaultSelectionDialog(QDialog):
    """Dialog for selecting or creating a vault."""
    
    def __init__(self, current_path: str, parent=None):
        super().__init__(parent)
        self.current_path = current_path
        self.selected_path = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Select Vault")
        self.setModal(True)
        self.setMinimumWidth(500)
        
        layout = QVBoxLayout()
        
        # Current vault info
        current_group = QGroupBox("Current Vault")
        current_layout = QVBoxLayout()
        current_layout.addWidget(QLabel(f"Location: {self.current_path}"))
        current_group.setLayout(current_layout)
        layout.addWidget(current_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        
        # Open existing vault
        open_layout = QHBoxLayout()
        self.open_button = QPushButton("Open Existing Vault")
        self.open_button.clicked.connect(self.open_existing_vault)
        open_layout.addWidget(self.open_button)
        options_layout.addLayout(open_layout)
        
        # Create new vault
        create_layout = QHBoxLayout()
        self.create_button = QPushButton("Create New Vault")
        self.create_button.clicked.connect(self.create_new_vault)
        create_layout.addWidget(self.create_button)
        options_layout.addLayout(create_layout)
        
        # Recent vaults
        self.recent_combo = QComboBox()
        self.load_recent_vaults()
        if self.recent_combo.count() > 0:
            recent_layout = QHBoxLayout()
            recent_layout.addWidget(QLabel("Recent Vaults:"))
            recent_layout.addWidget(self.recent_combo)
            open_recent_button = QPushButton("Open")
            open_recent_button.clicked.connect(self.open_recent_vault)
            recent_layout.addWidget(open_recent_button)
            options_layout.addLayout(recent_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def load_recent_vaults(self):
        """Load list of recent vaults."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        recent_file = os.path.join(config_dir, "recent_vaults.txt")
        
        if os.path.exists(recent_file):
            with open(recent_file, 'r') as f:
                for line in f:
                    path = line.strip()
                    if path and os.path.exists(path) and path != self.current_path:
                        self.recent_combo.addItem(path)
    
    def save_to_recent(self, path: str):
        """Save vault path to recent list."""
        config_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        os.makedirs(config_dir, exist_ok=True)
        recent_file = os.path.join(config_dir, "recent_vaults.txt")
        
        # Read existing recent vaults
        recent = []
        if os.path.exists(recent_file):
            with open(recent_file, 'r') as f:
                recent = [line.strip() for line in f if line.strip()]
        
        # Add new path at beginning
        if path in recent:
            recent.remove(path)
        recent.insert(0, path)
        
        # Keep only last 10
        recent = recent[:10]
        
        # Write back
        with open(recent_file, 'w') as f:
            for p in recent:
                f.write(p + '\n')
    
    def open_existing_vault(self):
        """Open an existing vault file."""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Open Vault", "", "Encrypted Vault Files (*.enc)"
        )
        
        if filename:
            self.selected_path = filename
            self.save_to_recent(filename)
            self.accept()
    
    def create_new_vault(self):
        """Create a new vault file."""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Create New Vault", "vault.enc", "Encrypted Vault Files (*.enc)"
        )
        
        if filename:
            self.selected_path = filename
            self.save_to_recent(filename)
            self.accept()
    
    def open_recent_vault(self):
        """Open a recent vault."""
        path = self.recent_combo.currentText()
        if path and os.path.exists(path):
            self.selected_path = path
            self.save_to_recent(path)
            self.accept()


class LoginDialog(QDialog):
    """Login dialog for the password manager."""
    
    def __init__(self, storage: StorageManager, parent=None):
        super().__init__(parent)
        self.storage = storage
        self.biometric = BiometricManager()
        self.attempts = 0
        self.max_attempts = 5
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("SecureVault - Login")
        self.setModal(True)
        self.setFixedSize(400, 300)
        
        layout = QVBoxLayout()
        
        # Logo/Title
        title = QLabel("SecureVault Password Manager")
        title.setAlignment(Qt.AlignCenter)
        font = title.font()
        font.setPointSize(16)
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)
        
        # Vault location
        vault_label = QLabel(f"Vault: {os.path.basename(self.storage.filepath)}")
        vault_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(vault_label)
        
        # Check if vault exists
        vault_exists = os.path.exists(self.storage.filepath)
        
        if vault_exists:
            # Existing vault - login
            layout.addWidget(QLabel("Enter your master password:"))
            
            self.password_input = QLineEdit()
            self.password_input.setEchoMode(QLineEdit.Password)
            self.password_input.returnPressed.connect(self.login)
            layout.addWidget(self.password_input)
            
            button_layout = QHBoxLayout()
            
            self.login_button = QPushButton("Unlock")
            self.login_button.clicked.connect(self.login)
            button_layout.addWidget(self.login_button)
            
            # Add biometric button if available
            if self.biometric.is_available() and self.storage.has_biometric_data():
                self.biometric_button = QPushButton("🔐 Unlock with Biometrics")
                self.biometric_button.clicked.connect(self.biometric_login)
                button_layout.addWidget(self.biometric_button)
            
            layout.addLayout(button_layout)
            
            self.status_label = QLabel("")
            self.status_label.setStyleSheet("color: red")
            layout.addWidget(self.status_label)
        else:
            # New vault - create
            layout.addWidget(QLabel("Create a new vault with a strong master password:"))
            
            self.password_input = QLineEdit()
            self.password_input.setEchoMode(QLineEdit.Password)
            self.password_input.textChanged.connect(self.check_password_strength)
            layout.addWidget(self.password_input)
            
            layout.addWidget(QLabel("Confirm password:"))
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.confirm_input)
            
            self.strength_label = QLabel("")
            layout.addWidget(self.strength_label)
            
            self.create_button = QPushButton("Create Vault")
            self.create_button.clicked.connect(self.create_vault)
            self.create_button.setEnabled(False)
            layout.addWidget(self.create_button)
        
        layout.addStretch()
        self.setLayout(layout)
        
        # Focus password input
        self.password_input.setFocus()
    
    def check_password_strength(self):
        """Check and display password strength."""
        password = self.password_input.text()
        is_strong, message = PasswordStrengthValidator.check_strength(password)
        
        if is_strong:
            self.strength_label.setStyleSheet("color: green")
            self.create_button.setEnabled(True)
        else:
            self.strength_label.setStyleSheet("color: red")
            self.create_button.setEnabled(False)
        
        self.strength_label.setText(message)
    
    def create_vault(self):
        """Create a new vault."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return
        
        is_strong, message = PasswordStrengthValidator.check_strength(password)
        if not is_strong:
            QMessageBox.warning(self, "Weak Password", message)
            return
        
        try:
            self.storage.create_new_vault(password)
            
            # Ask about biometric setup
            if self.biometric.is_available():
                reply = QMessageBox.question(
                    self, "Biometric Setup",
                    "Would you like to enable biometric unlock for this vault?",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    if self.biometric.authenticate("Enable biometric unlock for SecureVault"):
                        self.storage.enable_biometric(password)
                        QMessageBox.information(self, "Success", 
                            "Vault created with biometric unlock enabled!")
                    else:
                        QMessageBox.warning(self, "Biometric Setup Failed",
                            "Biometric authentication failed. You can enable it later in settings.")
                else:
                    QMessageBox.information(self, "Success", "Vault created successfully!")
            else:
                QMessageBox.information(self, "Success", "Vault created successfully!")
            
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create vault: {str(e)}")
    
    def login(self):
        """Attempt to login with password."""
        password = self.password_input.text()
        
        if self.storage.unlock(password):
            self.accept()
        else:
            self.attempts += 1
            remaining = self.max_attempts - self.attempts
            
            if remaining > 0:
                self.status_label.setText(f"Invalid password. {remaining} attempts remaining.")
                self.password_input.clear()
                self.password_input.setFocus()
            else:
                QMessageBox.critical(self, "Locked Out", "Maximum login attempts exceeded.")
                self.reject()
    
    def biometric_login(self):
        """Attempt to login with biometrics."""
        if self.biometric.authenticate("Unlock SecureVault"):
            if self.storage.unlock_with_biometric():
                self.accept()
            else:
                QMessageBox.warning(self, "Error", 
                    "Biometric unlock failed. Please use your master password.")
        else:
            self.status_label.setText("Biometric authentication failed.")


class PasswordGeneratorDialog(QDialog):
    """Dialog for generating passwords."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generated_password = ""
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Password Generator")
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QGridLayout()
        
        options_layout.addWidget(QLabel("Length:"), 0, 0)
        self.length_spin = QSpinBox()
        self.length_spin.setMinimum(8)
        self.length_spin.setMaximum(128)
        self.length_spin.setValue(16)
        self.length_spin.valueChanged.connect(self.generate_password)
        options_layout.addWidget(self.length_spin, 0, 1)
        
        self.uppercase_check = QCheckBox("Uppercase (A-Z)")
        self.uppercase_check.setChecked(True)
        self.uppercase_check.toggled.connect(self.generate_password)
        options_layout.addWidget(self.uppercase_check, 1, 0)
        
        self.lowercase_check = QCheckBox("Lowercase (a-z)")
        self.lowercase_check.setChecked(True)
        self.lowercase_check.toggled.connect(self.generate_password)
        options_layout.addWidget(self.lowercase_check, 1, 1)
        
        self.digits_check = QCheckBox("Digits (0-9)")
        self.digits_check.setChecked(True)
        self.digits_check.toggled.connect(self.generate_password)
        options_layout.addWidget(self.digits_check, 2, 0)
        
        self.symbols_check = QCheckBox("Symbols (!@#$...)")
        self.symbols_check.setChecked(True)
        self.symbols_check.toggled.connect(self.generate_password)
        options_layout.addWidget(self.symbols_check, 2, 1)
        
        self.exclude_ambiguous_check = QCheckBox("Exclude ambiguous (0O1lI)")
        self.exclude_ambiguous_check.toggled.connect(self.generate_password)
        options_layout.addWidget(self.exclude_ambiguous_check, 3, 0, 1, 2)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Generated password
        password_group = QGroupBox("Generated Password")
        password_layout = QVBoxLayout()
        
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setFont(QFont("Consolas", 12))
        password_layout.addWidget(self.password_display)
        
        button_layout = QHBoxLayout()
        self.regenerate_button = QPushButton("Regenerate")
        self.regenerate_button.clicked.connect(self.generate_password)
        button_layout.addWidget(self.regenerate_button)
        
        self.copy_button = QPushButton("Copy to Clipboard")
        self.copy_button.clicked.connect(self.copy_password)
        button_layout.addWidget(self.copy_button)
        
        password_layout.addLayout(button_layout)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
        
        # Generate initial password
        self.generate_password()
    
    def generate_password(self):
        """Generate a new password based on selected options."""
        length = self.length_spin.value()
        
        # Build character set
        chars = ""
        if self.uppercase_check.isChecked():
            chars += string.ascii_uppercase
        if self.lowercase_check.isChecked():
            chars += string.ascii_lowercase
        if self.digits_check.isChecked():
            chars += string.digits
        if self.symbols_check.isChecked():
            chars += string.punctuation
        
        if not chars:
            self.password_display.setText("Select at least one character type")
            return
        
        # Exclude ambiguous characters if requested
        if self.exclude_ambiguous_check.isChecked():
            ambiguous = "0O1lI"
            chars = ''.join(c for c in chars if c not in ambiguous)
        
        # Generate password using secrets module
        self.generated_password = ''.join(secrets.choice(chars) for _ in range(length))
        self.password_display.setText(self.generated_password)
    
    def copy_password(self):
        """Copy generated password to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.generated_password)
        
        # Show temporary notification
        self.copy_button.setText("Copied!")
        QTimer.singleShot(1000, lambda: self.copy_button.setText("Copy to Clipboard"))
    
    def get_password(self) -> str:
        """Get the generated password."""
        return self.generated_password


class PasswordEntryDialog(QDialog):
    """Dialog for adding/editing password entries."""
    
    def __init__(self, entry: Optional[PasswordEntry] = None, parent=None):
        super().__init__(parent)
        self.entry = entry
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Edit Entry" if self.entry else "Add Entry")
        self.setModal(True)
        self.setMinimumWidth(500)
        
        layout = QFormLayout()
        
        # Site/App name
        self.site_input = QLineEdit()
        if self.entry:
            self.site_input.setText(self.entry.site)
        layout.addRow("Site/App Name:", self.site_input)
        
        # Username
        self.username_input = QLineEdit()
        if self.entry:
            self.username_input.setText(self.entry.username)
        layout.addRow("Username:", self.username_input)
        
        # Password
        password_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        if self.entry:
            self.password_input.setText(self.entry.password)
        password_layout.addWidget(self.password_input)
        
        self.show_password_button = QPushButton("Show")
        self.show_password_button.setCheckable(True)
        self.show_password_button.toggled.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password_button)
        
        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.generate_password)
        password_layout.addWidget(self.generate_button)
        
        layout.addRow("Password:", password_layout)
        
        # URL
        self.url_input = QLineEdit()
        if self.entry:
            self.url_input.setText(self.entry.url)
        layout.addRow("URL:", self.url_input)
        
        # Notes
        self.notes_input = QTextEdit()
        self.notes_input.setMaximumHeight(100)
        if self.entry:
            self.notes_input.setPlainText(self.entry.notes)
        layout.addRow("Notes:", self.notes_input)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        
        self.setLayout(layout)
    
    def toggle_password_visibility(self, checked: bool):
        """Toggle password visibility."""
        if checked:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_button.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_button.setText("Show")
    
    def generate_password(self):
        """Open password generator dialog."""
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec_():
            self.password_input.setText(dialog.get_password())
    
    def validate_and_accept(self):
        """Validate input and accept dialog."""
        if not self.site_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Site/App name is required")
            return
        
        if not self.username_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Username is required")
            return
        
        if not self.password_input.text():
            QMessageBox.warning(self, "Validation Error", "Password is required")
            return
        
        self.accept()
    
    def get_entry(self) -> PasswordEntry:
        """Get the password entry from the dialog."""
        return PasswordEntry(
            id=self.entry.id if self.entry else str(uuid.uuid4()),
            site=self.site_input.text().strip(),
            username=self.username_input.text().strip(),
            password=self.password_input.text(),
            url=self.url_input.text().strip(),
            notes=self.notes_input.toPlainText().strip()
        )


class BrowserImportWorker(QThread):
    """Worker thread for browser import."""
    
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, browser: str):
        super().__init__()
        self.browser = browser
        self.importer = BrowserImporter()
    
    def run(self):
        """Run the import process."""
        try:
            self.progress.emit(0, f"Importing from {self.browser}...")
            entries = self.importer.import_from_browser(self.browser)
            self.finished.emit(entries)
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self, storage: StorageManager):
        super().__init__()
        self.storage = storage
        self.biometric = BiometricManager()
        self.clipboard_timer = QTimer()
        self.clipboard_timer.timeout.connect(self.clear_clipboard)
        self.auto_lock_timer = QTimer()
        self.auto_lock_timer.timeout.connect(self.auto_lock)
        self.auto_lock_timeout = 300000  # 5 minutes default
        self.init_ui()
        self.load_entries()
        self.start_auto_lock_timer()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle(f"SecureVault Password Manager - {os.path.basename(self.storage.filepath)}")
        self.setGeometry(100, 100, 1000, 600)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search entries...")
        self.search_input.textChanged.connect(self.filter_entries)
        toolbar_layout.addWidget(self.search_input)
        
        self.add_button = QPushButton("Add Entry")
        self.add_button.clicked.connect(self.add_entry)
        toolbar_layout.addWidget(self.add_button)
        
        self.import_button = QPushButton("Import")
        self.import_button.clicked.connect(self.show_import_menu)
        toolbar_layout.addWidget(self.import_button)
        
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_csv)
        toolbar_layout.addWidget(self.export_button)
        
        self.settings_button = QPushButton("Settings")
        self.settings_button.clicked.connect(self.show_settings)
        toolbar_layout.addWidget(self.settings_button)
        
        layout.addLayout(toolbar_layout)
        
        # Password table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Site/App", "Username", "Password", "Notes", "Date Added", "Actions"
        ])
        
        # Configure table
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 200)  # Site
        self.table.setColumnWidth(1, 200)  # Username
        self.table.setColumnWidth(2, 150)  # Password
        self.table.setColumnWidth(3, 150)  # Notes
        self.table.setColumnWidth(4, 150)  # Date
        
        # Hide password column by default
        self.table.setColumnHidden(2, True)
        
        # Context menu
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        layout.addWidget(self.table)
        
        # Status bar
        self.statusBar().showMessage("Vault unlocked")
        
        # Reset activity on any interaction
        self.installEventFilter(self)
    
    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        open_vault_action = QAction("Open Vault...", self)
        open_vault_action.setShortcut("Ctrl+O")
        open_vault_action.triggered.connect(self.open_vault)
        file_menu.addAction(open_vault_action)
        
        close_vault_action = QAction("Close Vault", self)
        close_vault_action.setShortcut("Ctrl+W")
        close_vault_action.triggered.connect(self.close_vault)
        file_menu.addAction(close_vault_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("Edit")
        
        add_entry_action = QAction("Add Entry", self)
        add_entry_action.setShortcut("Ctrl+N")
        add_entry_action.triggered.connect(self.add_entry)
        edit_menu.addAction(add_entry_action)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        show_passwords_action = QAction("Show Passwords", self)
        show_passwords_action.setCheckable(True)
        show_passwords_action.toggled.connect(self.toggle_password_visibility)
        view_menu.addAction(show_passwords_action)
    
    def eventFilter(self, obj, event):
        """Reset auto-lock timer on user activity."""
        if event.type() in [event.MouseButtonPress, event.KeyPress]:
            self.start_auto_lock_timer()
        return super().eventFilter(obj, event)
    
    def start_auto_lock_timer(self):
        """Start or restart the auto-lock timer."""
        self.auto_lock_timer.stop()
        if self.auto_lock_timeout > 0:
            self.auto_lock_timer.start(self.auto_lock_timeout)
    
    def auto_lock(self):
        """Auto-lock the vault due to inactivity."""
        reply = QMessageBox.question(
            self, "Auto-Lock", 
            "The vault will be locked due to inactivity. Continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.close_vault()
    
    def open_vault(self):
        """Open a different vault."""
        dialog = VaultSelectionDialog(self.storage.filepath, self)
        if dialog.exec_() and dialog.selected_path:
            # Close current vault
            self.close_vault(switch_vault=True, new_vault_path=dialog.selected_path)
    
    def close_vault(self, switch_vault=False, new_vault_path=None):
        """Close the current vault."""
        # Stop timers
        self.clipboard_timer.stop()
        self.auto_lock_timer.stop()
        
        # Clear clipboard if it contains password
        clipboard = QApplication.clipboard()
        if clipboard.text():
            clipboard.clear()
        
        # Lock storage
        self.storage.lock()
        
        if switch_vault and new_vault_path:
            # Switch to new vault
            from .main import PasswordManagerApp
            app = QApplication.instance()
            
            # Update storage path
            self.storage = StorageManager(new_vault_path)
            
            # Show login dialog for new vault
            login_dialog = LoginDialog(self.storage)
            if login_dialog.exec_():
                # Update window
                self.setWindowTitle(f"SecureVault Password Manager - {os.path.basename(new_vault_path)}")
                self.load_entries()
                self.start_auto_lock_timer()
                self.statusBar().showMessage("Vault switched successfully")
            else:
                # If login cancelled, close application
                self.close()
        else:
            # Just close the application
            self.close()
    
    def toggle_password_visibility(self, checked: bool):
        """Toggle password column visibility."""
        if checked:
            self.table.setColumnHidden(2, False)
            # Show actual passwords
            for row in range(self.table.rowCount()):
                entry_id = self.table.item(row, 0).data(Qt.UserRole)
                entries = self.storage.get_entries()
                entry = next((e for e in entries if e.id == entry_id), None)
                if entry:
                    self.table.setItem(row, 2, QTableWidgetItem(entry.password))
        else:
            self.table.setColumnHidden(2, True)
    
    def load_entries(self):
        """Load entries into the table."""
        self.table.setRowCount(0)
        entries = self.storage.get_entries()
        
        for entry in entries:
            self.add_entry_to_table(entry)
    
    def add_entry_to_table(self, entry: PasswordEntry):
        """Add an entry to the table."""
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # Store entry ID in first column
        site_item = QTableWidgetItem(entry.site)
        site_item.setData(Qt.UserRole, entry.id)
        self.table.setItem(row, 0, site_item)
        
        self.table.setItem(row, 1, QTableWidgetItem(entry.username))
        self.table.setItem(row, 2, QTableWidgetItem("••••••••"))
        self.table.setItem(row, 3, QTableWidgetItem(entry.notes[:50] + "..." if len(entry.notes) > 50 else entry.notes))
        
        # Format date
        if entry.date_added:
            try:
                date = datetime.datetime.fromisoformat(entry.date_added)
                date_str = date.strftime("%Y-%m-%d %H:%M")
            except:
                date_str = entry.date_added
        else:
            date_str = ""
        self.table.setItem(row, 4, QTableWidgetItem(date_str))
        
        # Actions widget
        actions_widget = QWidget()
        actions_layout = QHBoxLayout()
        actions_layout.setContentsMargins(0, 0, 0, 0)
        
        copy_user_btn = QPushButton("📋")
        copy_user_btn.setToolTip("Copy username")
        copy_user_btn.setMaximumWidth(30)
        copy_user_btn.clicked.connect(lambda: self.copy_username(entry))
        actions_layout.addWidget(copy_user_btn)
        
        copy_pass_btn = QPushButton("🔑")
        copy_pass_btn.setToolTip("Copy password")
        copy_pass_btn.setMaximumWidth(30)
        copy_pass_btn.clicked.connect(lambda: self.copy_password(entry))
        actions_layout.addWidget(copy_pass_btn)
        
        edit_btn = QPushButton("✏️")
        edit_btn.setToolTip("Edit")
        edit_btn.setMaximumWidth(30)
        edit_btn.clicked.connect(lambda: self.edit_entry(entry.id))
        actions_layout.addWidget(edit_btn)
        
        delete_btn = QPushButton("🗑️")
        delete_btn.setToolTip("Delete")
        delete_btn.setMaximumWidth(30)
        delete_btn.clicked.connect(lambda: self.delete_entry(entry.id))
        actions_layout.addWidget(delete_btn)
        
        actions_widget.setLayout(actions_layout)
        self.table.setCellWidget(row, 5, actions_widget)
    
    def filter_entries(self):
        """Filter entries based on search text."""
        search_text = self.search_input.text().lower()
        
        for row in range(self.table.rowCount()):
            show = True
            if search_text:
                # Check site, username, and notes
                site = self.table.item(row, 0).text().lower()
                username = self.table.item(row, 1).text().lower()
                notes = self.table.item(row, 3).text().lower()
                
                show = search_text in site or search_text in username or search_text in notes
            
            self.table.setRowHidden(row, not show)
    
    def show_context_menu(self, position):
        """Show context menu for table."""
        item = self.table.itemAt(position)
        if not item:
            return
        
        row = item.row()
        entry_id = self.table.item(row, 0).data(Qt.UserRole)
        
        menu = QMenu()
        
        copy_user_action = menu.addAction("Copy Username")
        copy_pass_action = menu.addAction("Copy Password")
        menu.addSeparator()
        edit_action = menu.addAction("Edit")
        delete_action = menu.addAction("Delete")
        
        action = menu.exec_(self.table.mapToGlobal(position))
        
        if action == copy_user_action:
            self.copy_username_by_id(entry_id)
        elif action == copy_pass_action:
            self.copy_password_by_id(entry_id)
        elif action == edit_action:
            self.edit_entry(entry_id)
        elif action == delete_action:
            self.delete_entry(entry_id)
    
    def add_entry(self):
        """Add a new password entry."""
        dialog = PasswordEntryDialog(parent=self)
        if dialog.exec_():
            entry = dialog.get_entry()
            self.storage.add_entry(entry)
            self.add_entry_to_table(entry)
            self.statusBar().showMessage("Entry added", 2000)
    
    def edit_entry(self, entry_id: str):
        """Edit an existing entry."""
        # Find entry
        entries = self.storage.get_entries()
        entry = next((e for e in entries if e.id == entry_id), None)
        if not entry:
            return
        
        dialog = PasswordEntryDialog(entry, parent=self)
        if dialog.exec_():
            updated_entry = dialog.get_entry()
            if self.storage.update_entry(entry_id, updated_entry):
                self.load_entries()
                self.statusBar().showMessage("Entry updated", 2000)
    
    def delete_entry(self, entry_id: str):
        """Delete an entry."""
        reply = QMessageBox.question(
            self, "Confirm Delete",
            "Are you sure you want to delete this entry?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if self.storage.delete_entry(entry_id):
                self.load_entries()
                self.statusBar().showMessage("Entry deleted", 2000)
    
    def copy_username_by_id(self, entry_id: str):
        """Copy username by entry ID."""
        entries = self.storage.get_entries()
        entry = next((e for e in entries if e.id == entry_id), None)
        if entry:
            self.copy_username(entry)
    
    def copy_password_by_id(self, entry_id: str):
        """Copy password by entry ID."""
        entries = self.storage.get_entries()
        entry = next((e for e in entries if e.id == entry_id), None)
        if entry:
            self.copy_password(entry)
    
    def copy_username(self, entry: PasswordEntry):
        """Copy username to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(entry.username)
        self.statusBar().showMessage("Username copied to clipboard", 2000)
    
    def copy_password(self, entry: PasswordEntry):
        """Copy password to clipboard with auto-clear."""
        clipboard = QApplication.clipboard()
        clipboard.setText(entry.password)
        
        # Start timer to clear clipboard
        self.clipboard_timer.stop()
        self.clipboard_timer.start(30000)  # 30 seconds
        
        self.statusBar().showMessage("Password copied to clipboard (auto-clear in 30s)", 2000)
    
    def clear_clipboard(self):
        """Clear the clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.clear()
        self.statusBar().showMessage("Clipboard cleared", 2000)
    
    def show_import_menu(self):
        """Show import options menu."""
        menu = QMenu()
        
        csv_action = menu.addAction("Import from CSV file...")
        menu.addSeparator()
        
        # Browser import options
        browser_menu = menu.addMenu("Import from browser")
        chrome_action = browser_menu.addAction("Google Chrome")
        firefox_action = browser_menu.addAction("Mozilla Firefox")
        edge_action = browser_menu.addAction("Microsoft Edge")
        
        action = menu.exec_(self.import_button.mapToGlobal(self.import_button.rect().bottomLeft()))
        
        if action == csv_action:
            self.import_csv()
        elif action == chrome_action:
            self.import_from_browser("chrome")
        elif action == firefox_action:
            self.import_from_browser("firefox")
        elif action == edge_action:
            self.import_from_browser("edge")
    
    def import_csv(self):
        """Import passwords from CSV file."""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Import CSV", "", "CSV Files (*.csv)"
        )
        
        if filename:
            try:
                importer = CSVImporter()
                entries = importer.import_from_file(filename)
                
                # Add entries to storage
                added = 0
                for entry in entries:
                    self.storage.add_entry(entry)
                    added += 1
                
                self.load_entries()
                QMessageBox.information(
                    self, "Import Complete",
                    f"Successfully imported {added} entries"
                )
                
                # Log the import
                self._log_action("CSV_IMPORT", f"Imported {added} entries from {filename}")
                
            except Exception as e:
                QMessageBox.critical(
                    self, "Import Error",
                    f"Failed to import CSV: {str(e)}"
                )
    
    def import_from_browser(self, browser: str):
        """Import passwords from a browser."""
        # Show consent dialog
        consent_dialog = QMessageBox(self)
        consent_dialog.setWindowTitle("Browser Password Import Consent")
        consent_dialog.setText(
            f"SecureVault will attempt to import passwords from {browser}.\n\n"
            "IMPORTANT:\n"
            "• This will only read passwords stored on THIS device\n"
            "• You must be the owner/administrator of this device\n"
            "• Passwords will be stored encrypted in your local vault\n"
            "• No data will be transmitted off this device\n\n"
            "Do you consent to importing passwords from your browser?"
        )
        consent_dialog.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        consent_dialog.setDefaultButton(QMessageBox.No)
        
        if consent_dialog.exec_() != QMessageBox.Yes:
            return
        
        # Log consent
        self._log_action("BROWSER_IMPORT_CONSENT", f"User consented to import from {browser}")
        
        # Create progress dialog
        progress = QProgressDialog("Importing browser passwords...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.show()
        
        # Create worker thread
        self.import_worker = BrowserImportWorker(browser)
        self.import_worker.progress.connect(lambda v, msg: (progress.setValue(v), progress.setLabelText(msg)))
        self.import_worker.finished.connect(lambda entries: self._handle_browser_import_finished(entries, progress))
        self.import_worker.error.connect(lambda err: self._handle_browser_import_error(err, progress, browser))
        
        # Start import
        self.import_worker.start()
    
    def _handle_browser_import_finished(self, entries: List[PasswordEntry], progress: QProgressDialog):
        """Handle successful browser import."""
        progress.close()
        
        if not entries:
            QMessageBox.information(
                self, "No Passwords Found",
                "No passwords were found in the browser profile."
            )
            return
        
        # Add entries to storage
        added = 0
        for entry in entries:
            self.storage.add_entry(entry)
            added += 1
        
        self.load_entries()
        QMessageBox.information(
            self, "Import Complete",
            f"Successfully imported {added} passwords from browser"
        )
        
        # Log the import
        self._log_action("BROWSER_IMPORT_SUCCESS", f"Imported {added} entries")
    
    def _handle_browser_import_error(self, error: str, progress: QProgressDialog, browser: str):
        """Handle browser import error."""
        progress.close()
        
        # Check if it's a platform limitation
        if "not supported" in error.lower() or "manual export" in error.lower():
            # Show manual export instructions
            instructions = self._get_manual_export_instructions(browser)
            
            msg = QMessageBox(self)
            msg.setWindowTitle("Manual Export Required")
            msg.setText(f"Automatic import from {browser} is not available on this platform.")
            msg.setDetailedText(instructions)
            msg.exec_()
        else:
            QMessageBox.critical(
                self, "Import Error",
                f"Failed to import from browser: {error}"
            )
    
    def _get_manual_export_instructions(self, browser: str) -> str:
        """Get manual export instructions for a browser."""
        if browser.lower() == "chrome":
            return (
                "To export passwords from Chrome:\n\n"
                "1. Open Chrome and go to chrome://settings/passwords\n"
                "2. Click the three dots menu next to 'Saved Passwords'\n"
                "3. Select 'Export passwords'\n"
                "4. Save the CSV file\n"
                "5. Use 'Import from CSV file' in SecureVault to import the file"
            )
        elif browser.lower() == "firefox":
            return (
                "To export passwords from Firefox:\n\n"
                "1. Open Firefox and go to about:logins\n"
                "2. Click the three dots menu\n"
                "3. Select 'Export Logins'\n"
                "4. Save the CSV file\n"
                "5. Use 'Import from CSV file' in SecureVault to import the file"
            )
        elif browser.lower() == "edge":
            return (
                "To export passwords from Edge:\n\n"
                "1. Open Edge and go to edge://settings/passwords\n"
                "2. Click the three dots menu next to 'Saved passwords'\n"
                "3. Select 'Export passwords'\n"
                "4. Save the CSV file\n"
                "5. Use 'Import from CSV file' in SecureVault to import the file"
            )
        else:
            return "Please check your browser's documentation for password export instructions."
    
    def export_csv(self):
        """Export passwords to CSV file."""
        # Show warning dialog
        reply = QMessageBox.warning(
            self, "Export Warning",
            "This will export all passwords in PLAIN TEXT.\n\n"
            "The exported file will NOT be encrypted.\n"
            "Anyone with access to this file can see all passwords.\n\n"
            "Are you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # Get filename
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export to CSV", "passwords.csv", "CSV Files (*.csv)"
        )
        
        if filename:
            try:
                entries = self.storage.get_entries()
                
                # Write CSV
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['site', 'username', 'password', 'url', 'notes'])
                    
                    for entry in entries:
                        writer.writerow([
                            entry.site,
                            entry.username,
                            entry.password,
                            entry.url,
                            entry.notes
                        ])
                
                QMessageBox.information(
                    self, "Export Complete",
                    f"Exported {len(entries)} entries to {filename}\n\n"
                    "Remember to delete this file after use!"
                )
                
                # Log the export
                self._log_action("CSV_EXPORT", f"Exported {len(entries)} entries to {filename}")
                
            except Exception as e:
                QMessageBox.critical(
                    self, "Export Error",
                    f"Failed to export CSV: {str(e)}"
                )
    
    def show_settings(self):
        """Show settings dialog."""
        dialog = SettingsDialog(self.storage, self.auto_lock_timeout, self)
        if dialog.exec_():
            # Update auto-lock timeout
            self.auto_lock_timeout = dialog.get_auto_lock_timeout()
            self.start_auto_lock_timer()
    
    def _log_action(self, action: str, details: str):
        """Log security-relevant actions."""
        log_dir = os.path.join(os.path.expanduser("~"), ".securevault", "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, "audit.log")
        timestamp = datetime.datetime.now().isoformat()
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"{timestamp} | {action} | {details}\n")
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop timers
        self.clipboard_timer.stop()
        self.auto_lock_timer.stop()
        
        # Clear clipboard if it contains password
        clipboard = QApplication.clipboard()
        if clipboard.text():
            clipboard.clear()
        
        # Lock storage
        self.storage.lock()
        
        event.accept()


class SettingsDialog(QDialog):
    """Settings dialog."""
    
    def __init__(self, storage: StorageManager, current_timeout: int, parent=None):
        super().__init__(parent)
        self.storage = storage
        self.biometric = BiometricManager()
        self.current_timeout = current_timeout
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        # Create tabs
        tabs = QTabWidget()
        
        # Security tab
        security_tab = QWidget()
        security_layout = QFormLayout()
        
        # Change master password
        change_password_btn = QPushButton("Change Master Password")
        change_password_btn.clicked.connect(self.change_master_password)
        security_layout.addRow("Master Password:", change_password_btn)
        
        # Biometric settings
        if self.biometric.is_available():
            biometric_group = QGroupBox("Biometric Authentication")
            biometric_layout = QVBoxLayout()
            
            self.biometric_enabled = QCheckBox("Enable biometric unlock")
            self.biometric_enabled.setChecked(self.storage.has_biometric_data())
            self.biometric_enabled.toggled.connect(self.toggle_biometric)
            biometric_layout.addWidget(self.biometric_enabled)
            
            biometric_info = QLabel(f"Device: {self.biometric.get_device_info()}")
            biometric_info.setWordWrap(True)
            biometric_layout.addWidget(biometric_info)
            
            biometric_group.setLayout(biometric_layout)
            security_layout.addRow(biometric_group)
        
        # Auto-lock timeout
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setMinimum(0)
        self.timeout_spin.setMaximum(60)
        self.timeout_spin.setValue(self.current_timeout // 60000)  # Convert to minutes
        self.timeout_spin.setSuffix(" minutes")
        self.timeout_spin.setSpecialValueText("Disabled")
        security_layout.addRow("Auto-lock timeout:", self.timeout_spin)
        
        # Clipboard timeout
        self.clipboard_spin = QSpinBox()
        self.clipboard_spin.setMinimum(10)
        self.clipboard_spin.setMaximum(300)
        self.clipboard_spin.setValue(30)
        self.clipboard_spin.setSuffix(" seconds")
        security_layout.addRow("Clear clipboard after:", self.clipboard_spin)
        
        security_tab.setLayout(security_layout)
        tabs.addTab(security_tab, "Security")
        
        # Vault tab
        vault_tab = QWidget()
        vault_layout = QFormLayout()
        
        # Current vault location
        vault_location = QLabel(self.storage.filepath)
        vault_location.setWordWrap(True)
        vault_layout.addRow("Current location:", vault_location)
        
        # Change vault location
        change_location_btn = QPushButton("Change Vault Location")
        change_location_btn.clicked.connect(self.change_vault_location)
        vault_layout.addRow("", change_location_btn)
        
        vault_tab.setLayout(vault_layout)
        tabs.addTab(vault_tab, "Vault")
        
        # Backup tab
        backup_tab = QWidget()
        backup_layout = QVBoxLayout()
        
        backup_info = QLabel(
            "Regular backups are recommended to prevent data loss.\n"
            "The backup file is encrypted with your master password."
        )
        backup_info.setWordWrap(True)
        backup_layout.addWidget(backup_info)
        
        backup_btn = QPushButton("Create Backup")
        backup_btn.clicked.connect(self.create_backup)
        backup_layout.addWidget(backup_btn)
        
        restore_btn = QPushButton("Restore from Backup")
        restore_btn.clicked.connect(self.restore_backup)
        backup_layout.addWidget(restore_btn)
        
        backup_layout.addStretch()
        backup_tab.setLayout(backup_layout)
        tabs.addTab(backup_tab, "Backup")
        
        # About tab
        about_tab = QWidget()
        about_layout = QVBoxLayout()
        
        about_text = QLabel(
            "<h3>SecureVault Password Manager</h3>"
            "<p>Version 1.0.0</p>"
            "<p><b>Legal Notice:</b><br>"
            "This tool is for personal use only. It must operate only on the device "
            "where it is installed and only with the explicit consent of the device owner. "
            "It must never be used to extract or exfiltrate passwords from devices you "
            "do not own or administer.</p>"
        )
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        about_layout.addStretch()
        
        about_tab.setLayout(about_layout)
        tabs.addTab(about_tab, "About")
        
        layout.addWidget(tabs)
        
        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def toggle_biometric(self, enabled: bool):
        """Toggle biometric authentication."""
        if enabled:
            # Enable biometric
            password, ok = QInputDialog.getText(
                self, "Enable Biometric",
                "Enter your master password to enable biometric unlock:",
                QLineEdit.Password
            )
            
            if ok and password:
                if self.biometric.authenticate("Enable biometric unlock for SecureVault"):
                    if self.storage.enable_biometric(password):
                        QMessageBox.information(self, "Success", 
                            "Biometric unlock enabled successfully!")
                    else:
                        QMessageBox.warning(self, "Error", 
                            "Failed to enable biometric unlock. Check your master password.")
                        self.biometric_enabled.setChecked(False)
                else:
                    QMessageBox.warning(self, "Error", 
                        "Biometric authentication failed.")
                    self.biometric_enabled.setChecked(False)
            else:
                self.biometric_enabled.setChecked(False)
        else:
            # Disable biometric
            if self.storage.disable_biometric():
                QMessageBox.information(self, "Success", 
                    "Biometric unlock disabled.")
            else:
                QMessageBox.warning(self, "Error", 
                    "Failed to disable biometric unlock.")
                self.biometric_enabled.setChecked(True)
    
    def change_master_password(self):
        """Change the master password."""
        dialog = ChangeMasterPasswordDialog(self.storage, self)
        dialog.exec_()
    
    def change_vault_location(self):
        """Change vault file location."""
        new_location, _ = QFileDialog.getSaveFileName(
            self, "Select New Vault Location", 
            os.path.basename(self.storage.filepath),
            "Encrypted Files (*.enc)"
        )
        
        if new_location:
            try:
                import shutil
                # Copy vault to new location
                shutil.copy2(self.storage.filepath, new_location)
                
                # Update storage path
                old_location = self.storage.filepath
                self.storage.filepath = new_location
                
                # Save to recent vaults
                dialog = VaultSelectionDialog("", self)
                dialog.save_to_recent(new_location)
                
                QMessageBox.information(
                    self, "Success",
                    f"Vault moved to:\n{new_location}\n\n"
                    f"The old vault file at:\n{old_location}\n"
                    "has been kept as a backup."
                )
                
                # Update parent window title
                if self.parent():
                    self.parent().setWindowTitle(
                        f"SecureVault Password Manager - {os.path.basename(new_location)}"
                    )
                
            except Exception as e:
                QMessageBox.critical(
                    self, "Error",
                    f"Failed to move vault: {str(e)}"
                )
    
    def create_backup(self):
        """Create a backup of the vault."""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Create Backup", 
            f"securevault_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.enc",
            "Encrypted Files (*.enc)"
        )
        
        if filename:
            try:
                import shutil
                shutil.copy2(self.storage.filepath, filename)
                QMessageBox.information(
                    self, "Backup Created",
                    f"Backup saved to: {filename}\n\n"
                    "Keep this file safe. You'll need your master password to restore it."
                )
            except Exception as e:
                QMessageBox.critical(
                    self, "Backup Error",
                    f"Failed to create backup: {str(e)}"
                )
    
    def restore_backup(self):
        """Restore from a backup file."""
        reply = QMessageBox.warning(
            self, "Restore Warning",
            "Restoring from backup will REPLACE all current data.\n\n"
            "Are you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Backup File", "", "Encrypted Files (*.enc)"
        )
        
        if filename:
            QMessageBox.information(
                self, "Restart Required",
                "Please restart the application and use your backup's master password to unlock."
            )
    
    def get_auto_lock_timeout(self) -> int:
        """Get the auto-lock timeout in milliseconds."""
        return self.timeout_spin.value() * 60000


class ChangeMasterPasswordDialog(QDialog):
    """Dialog for changing master password."""
    
    def __init__(self, storage: StorageManager, parent=None):
        super().__init__(parent)
        self.storage = storage
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Change Master Password")
        self.setModal(True)
        self.setFixedWidth(400)
        
        layout = QFormLayout()
        
        # Current password
        self.current_input = QLineEdit()
        self.current_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Current Password:", self.current_input)
        
        # New password
        self.new_input = QLineEdit()
        self.new_input.setEchoMode(QLineEdit.Password)
        self.new_input.textChanged.connect(self.check_password_strength)
        layout.addRow("New Password:", self.new_input)
        
        # Confirm new password
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Confirm Password:", self.confirm_input)
        
        # Strength indicator
        self.strength_label = QLabel("")
        layout.addRow("", self.strength_label)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.change_password)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.Ok).setEnabled(False)
        self.ok_button = buttons.button(QDialogButtonBox.Ok)
        layout.addRow(buttons)
        
        self.setLayout(layout)
    
    def check_password_strength(self):
        """Check and display password strength."""
        password = self.new_input.text()
        is_strong, message = PasswordStrengthValidator.check_strength(password)
        
        if is_strong:
            self.strength_label.setStyleSheet("color: green")
            self.ok_button.setEnabled(True)
        else:
            self.strength_label.setStyleSheet("color: red")
            self.ok_button.setEnabled(False)
        
        self.strength_label.setText(message)
    
    def change_password(self):
        """Change the master password."""
        current = self.current_input.text()
        new = self.new_input.text()
        confirm = self.confirm_input.text()
        
        if new != confirm:
            QMessageBox.warning(self, "Error", "New passwords do not match")
            return
        
        is_strong, message = PasswordStrengthValidator.check_strength(new)
        if not is_strong:
            QMessageBox.warning(self, "Weak Password", message)
            return
        
        if self.storage.change_master_password(current, new):
            # Update biometric data if enabled
            if self.storage.has_biometric_data():
                reply = QMessageBox.question(
                    self, "Update Biometric",
                    "Would you like to update biometric authentication with the new password?",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    biometric = BiometricManager()
                    if biometric.authenticate("Update biometric authentication"):
                        self.storage.enable_biometric(new)
            
            QMessageBox.information(
                self, "Success", 
                "Master password changed successfully!"
            )
            self.accept()
        else:
            QMessageBox.critical(
                self, "Error",
                "Failed to change password. Please check your current password."
            )