
### build.sh

```bash
#!/bin/bash
# Build script for SecureVault Password Manager (macOS/Linux)

echo "SecureVault Password Manager - Build Script"
echo "=========================================="

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.10"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo "Error: Python 3.10+ is required. Found: $python_version"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Install PyInstaller
echo "Installing PyInstaller..."
pip install pyinstaller

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build dist

# Create the executable
echo "Building executable..."
pyinstaller password_manager.spec

# Check if build was successful
if [ -f "dist/SecureVault" ] || [ -f "dist/SecureVault.app" ]; then
    echo ""
    echo "Build successful!"
    echo "Executable location: dist/SecureVault"
    echo ""
    echo "To run the application:"
    echo "  ./dist/SecureVault"
else
    echo ""
    echo "Build failed! Check the error messages above."
    exit 1
fi

# Deactivate virtual environment
deactivate

echo "Build complete!"