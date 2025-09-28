@echo off
REM Build script for SecureVault Password Manager (Windows)

echo SecureVault Password Manager - Build Script
echo ==========================================
echo.

REM Check Python version
python --version 2>NUL
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.10 or higher from https://www.python.org
    pause
    exit /b 1
)

REM Check Python version is 3.10+
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Found Python version: %PYTHON_VERSION%

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo Error: Failed to activate virtual environment
    pause
    exit /b 1
)

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

REM Install PyInstaller
echo Installing PyInstaller...
pip install pyinstaller
if errorlevel 1 (
    echo Error: Failed to install PyInstaller
    pause
    exit /b 1
)

REM Clean previous builds
echo Cleaning previous builds...
if exist "build" rmdir /s /q build
if exist "dist" rmdir /s /q dist

REM Create the executable
echo Building executable...
echo This may take a few minutes...
pyinstaller password_manager.spec
if errorlevel 1 (
    echo Error: Build failed!
    echo Check the error messages above for details.
    pause
    exit /b 1
)

REM Check if build was successful
if exist "dist\SecureVault.exe" (
    echo.
    echo ========================================
    echo Build successful!
    echo ========================================
    echo.
    echo Executable location: dist\SecureVault.exe
    echo File size: 
    for %%A in ("dist\SecureVault.exe") do echo %%~zA bytes
    echo.
    echo To run the application:
    echo   1. Navigate to the dist folder
    echo   2. Double-click SecureVault.exe
    echo.
    echo Or run from command line:
    echo   dist\SecureVault.exe
    echo.
    
    REM Create a simple batch file to run the app
    echo @echo off > "dist\Run SecureVault.bat"
    echo start SecureVault.exe >> "dist\Run SecureVault.bat"
    
    echo A batch file "Run SecureVault.bat" has been created in the dist folder
    echo for easy launching.
) else (
    echo.
    echo ========================================
    echo Build failed!
    echo ========================================
    echo.
    echo The executable was not created.
    echo Check the error messages above for details.
    echo.
    echo Common issues:
    echo   - Missing dependencies
    echo   - Antivirus blocking PyInstaller
    echo   - Insufficient permissions
    echo.
    pause
    exit /b 1
)

REM Deactivate virtual environment
call deactivate

echo.
echo ========================================
echo Build process complete!
echo ========================================
echo.
echo Next steps:
echo   1. Test the executable in dist\SecureVault.exe
echo   2. Distribute the entire dist folder to users
echo   3. Users can run SecureVault.exe directly
echo.
echo Security notes:
echo   - The executable contains all dependencies
echo   - No Python installation required on target machine
echo   - Keep your master password secure
echo   - Regular backups are recommended
echo.

pause