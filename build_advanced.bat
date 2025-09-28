@echo off
REM Advanced build script for SecureVault Password Manager (Windows)
REM Includes options for debug builds, console mode, and custom icons

setlocal enabledelayedexpansion

echo SecureVault Password Manager - Advanced Build Script
echo ==================================================
echo.

REM Parse command line arguments
set BUILD_TYPE=release
set CONSOLE_MODE=no
set CLEAN_ONLY=no
set ICON_FILE=

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--debug" (
    set BUILD_TYPE=debug
    shift
    goto :parse_args
)
if /i "%~1"=="--console" (
    set CONSOLE_MODE=yes
    shift
    goto :parse_args
)
if /i "%~1"=="--clean" (
    set CLEAN_ONLY=yes
    shift
    goto :parse_args
)
if /i "%~1"=="--icon" (
    set ICON_FILE=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--help" (
    goto :show_help
)
shift
goto :parse_args

:args_done

echo Build configuration:
echo   Build type: %BUILD_TYPE%
echo   Console mode: %CONSOLE_MODE%
if not "%ICON_FILE%"=="" echo   Icon file: %ICON_FILE%
echo.

REM Clean build directories
if exist "build" (
    echo Cleaning build directory...
    rmdir /s /q build
)
if exist "dist" (
    echo Cleaning dist directory...
    rmdir /s /q dist
)

if "%CLEAN_ONLY%"=="yes" (
    echo Clean complete.
    exit /b 0
)

REM Check Python
python --version 2>NUL
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.10 or higher from https://www.python.org
    pause
    exit /b 1
)

REM Create virtual environment if needed
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install/upgrade dependencies
echo Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

REM Create temporary spec file with custom options
echo Creating build specification...
set SPEC_FILE=temp_build.spec

echo # -*- mode: python ; coding: utf-8 -*- > %SPEC_FILE%
echo import sys >> %SPEC_FILE%
echo from PyInstaller.utils.hooks import collect_data_files, collect_submodules >> %SPEC_FILE%
echo. >> %SPEC_FILE%
echo block_cipher = None >> %SPEC_FILE%
echo. >> %SPEC_FILE%
echo # Collect all app modules >> %SPEC_FILE%
echo hiddenimports = collect_submodules('app') >> %SPEC_FILE%
echo. >> %SPEC_FILE%
echo # Add platform-specific imports >> %SPEC_FILE%
echo if sys.platform == 'win32': >> %SPEC_FILE%
echo     hiddenimports.extend(['win32crypt', 'win32api']) >> %SPEC_FILE%
echo. >> %SPEC_FILE%
echo a = Analysis( >> %SPEC_FILE%
echo     ['app/main.py'], >> %SPEC_FILE%
echo     pathex=[], >> %SPEC_FILE%
echo     binaries=[], >> %SPEC_FILE%
echo     datas=[], >> %SPEC_FILE%
echo     hiddenimports=hiddenimports + [ >> %SPEC_FILE%
echo         'cryptography', >> %SPEC_FILE%
echo         'argon2', >> %SPEC_FILE%
echo         'PyQt5', >> %SPEC_FILE%
echo         'PyQt5.QtCore', >> %SPEC_FILE%
echo         'PyQt5.QtGui', >> %SPEC_FILE%
echo         'PyQt5.QtWidgets', >> %SPEC_FILE%
echo     ], >> %SPEC_FILE%
echo     hookspath=[], >> %SPEC_FILE%
echo     hooksconfig={}, >> %SPEC_FILE%
echo     runtime_hooks=[], >> %SPEC_FILE%
echo     excludes=[], >> %SPEC_FILE%
echo     win_no_prefer_redirects=False, >> %SPEC_FILE%
echo     win_private_assemblies=False, >> %SPEC_FILE%
echo     cipher=block_cipher, >> %SPEC_FILE%
echo     noarchive=False, >> %SPEC_FILE%
echo ) >> %SPEC_FILE%
echo. >> %SPEC_FILE%
echo pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher) >> %SPEC_FILE%
echo. >> %SPEC_FILE%

if "%BUILD_TYPE%"=="debug" (
    set DEBUG_FLAG=True
) else (
    set DEBUG_FLAG=False
)

if "%CONSOLE_MODE%"=="yes" (
    set CONSOLE_FLAG=True
) else (
    set CONSOLE_FLAG=False
)

if not "%ICON_FILE%"=="" (
    set ICON_PARAM='%ICON_FILE%'
) else (
    set ICON_PARAM=None
)

echo exe = EXE( >> %SPEC_FILE%
echo     pyz, >> %SPEC_FILE%
echo     a.scripts, >> %SPEC_FILE%
echo     a.binaries, >> %SPEC_FILE%
echo     a.zipfiles, >> %SPEC_FILE%
echo     a.datas, >> %SPEC_FILE%
echo     [], >> %SPEC_FILE%
echo     name='SecureVault', >> %SPEC_FILE%
echo     debug=%DEBUG_FLAG%, >> %SPEC_FILE%
echo     bootloader_ignore_signals=False, >> %SPEC_FILE%
echo     strip=False, >> %SPEC_FILE%
echo     upx=True, >> %SPEC_FILE%
echo     upx_exclude=[], >> %SPEC_FILE%
echo     runtime_tmpdir=None, >> %SPEC_FILE%
echo     console=%CONSOLE_FLAG%, >> %SPEC_FILE%
echo     disable_windowed_traceback=False, >> %SPEC_FILE%
echo     argv_emulation=False, >> %SPEC_FILE%
echo     target_arch=None, >> %SPEC_FILE%
echo     codesign_identity=None, >> %SPEC_FILE%
echo     entitlements_file=None, >> %SPEC_FILE%
echo     icon=%ICON_PARAM% >> %SPEC_FILE%
echo ) >> %SPEC_FILE%

REM Build the executable
echo.
echo Building SecureVault...
echo This may take several minutes...
echo.

pyinstaller %SPEC_FILE% --clean

REM Clean up temp spec file
del %SPEC_FILE%

REM Check build result
if exist "dist\SecureVault.exe" (
    echo.
    echo ========================================
    echo Build successful!
    echo ========================================
    echo.
    
    REM Get file info
    for %%F in ("dist\SecureVault.exe") do (
        set FILE_SIZE=%%~zF
        set /a FILE_SIZE_MB=!FILE_SIZE! / 1048576
        echo Executable: dist\SecureVault.exe
        echo File size: !FILE_SIZE_MB! MB
    )
    
    REM Create run script
    echo @echo off > "dist\Run SecureVault.bat"
    echo cd /d "%%~dp0" >> "dist\Run SecureVault.bat"
    echo start "" SecureVault.exe >> "dist\Run SecureVault.bat"
    
    REM Create README for distribution
    echo SecureVault Password Manager > "dist\README.txt"
    echo =========================== >> "dist\README.txt"
    echo. >> "dist\README.txt"
    echo To run SecureVault: >> "dist\README.txt"
    echo   - Double-click SecureVault.exe >> "dist\README.txt"
    echo   - Or double-click "Run SecureVault.bat" >> "dist\README.txt"
    echo. >> "dist\README.txt"
    echo First time use: >> "dist\README.txt"
    echo   1. Create a strong master password >> "dist\README.txt"
    echo   2. Add your passwords >> "dist\README.txt"
    echo   3. Enable biometric unlock (optional) >> "dist\README.txt"
    echo. >> "dist\README.txt"
    echo Security notes: >> "dist\README.txt"
    echo   - Keep your master password safe >> "dist\README.txt"
    echo   - Create regular backups >> "dist\README.txt"
    echo   - Never share your vault file >> "dist\README.txt"
    
    echo.
    echo Distribution package created in: dist\
    echo.
    
    if "%BUILD_TYPE%"=="debug" (
        echo Debug build created - includes console output
    )
) else (
    echo.
    echo ========================================
    echo Build failed!
    echo ========================================
    echo.
    echo Check the error messages above.
    echo.
    pause
    exit /b 1
)

REM Deactivate virtual environment
call deactivate

echo.
echo Build complete!
pause
exit /b 0

:show_help
echo.
echo Usage: build_advanced.bat [options]
echo.
echo Options:
echo   --debug      Create a debug build with console output
echo   --console    Show console window (for troubleshooting)
echo   --clean      Clean build directories only
echo   --icon FILE  Use custom icon file
echo   --help       Show this help message
echo.
echo Examples:
echo   build_advanced.bat                    # Standard release build
echo   build_advanced.bat --debug           # Debug build
echo   build_advanced.bat --icon myicon.ico # Build with custom icon
echo   build_advanced.bat --clean           # Clean build directories
echo.
pause
exit /b 0