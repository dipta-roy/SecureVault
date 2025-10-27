# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for SecureVault Password Manager

import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect all app modules
hiddenimports = collect_submodules('app')

# Add platform-specific imports
if sys.platform == 'win32':
    hiddenimports.extend(['win32crypt', 'win32api'])

a = Analysis(
    ['app/main.py'],
    pathex=[],
    binaries=[],
    datas=[('logo/SecureVault_logo.ico', 'logo')],
    hiddenimports=hiddenimports + [
        'cryptography',
        'argon2',
        'PyQt5',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWidgets',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SecureVault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='logo/SecureVault_logo.ico'  # Add your icon file here if you have one
)

# For macOS, create an app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='SecureVault.app',
        icon=None,  # Add your icon file here if you have one
        bundle_identifier='com.securevault.passwordmanager',
        info_plist={
            'NSHighResolutionCapable': 'True',
            'LSMinimumSystemVersion': '10.12.0',
        },
    )