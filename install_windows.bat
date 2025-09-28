@echo off
echo SecureVault Password Manager - Windows Setup
echo ===========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python 3.10 or later from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)

echo Python found:
python --version
echo.

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo.
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo.
echo Installing requirements...
pip install -r requirements.txt

REM Additional Windows-specific packages
echo.
echo Installing Windows-specific packages...
pip install pywin32

REM Post-install for pywin32
echo.
echo Running pywin32 post-install...
python venv\Scripts\pywin32_postinstall.py -install

echo.
echo ===========================================
echo Installation complete!
echo ===========================================
echo.
echo To run SecureVault:
echo   1. Run: venv\Scripts\activate.bat
echo   2. Run: python -m app.main
echo.
echo Or build an executable:
echo   Run: build.bat
echo.
pause