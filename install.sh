#!/bin/bash

# Neluxmatizer - Installation Script
# This script installs all necessary dependencies for Neluxmatizer

set -e  # Exit on error

echo "🔍 Neluxmatizer - Advanced Web Vulnerability Scanner"
echo "=================================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7+ first."
    echo "   On Debian/Ubuntu: sudo apt-get install python3 python3-pip"
    echo "   On Fedora/RHEL: sudo dnf install python3 python3-pip"
    echo "   On macOS: brew install python3"
    exit 1
fi

# Check Python version (minimum 3.7)
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    echo "❌ Python 3.7+ is required. Found Python $PYTHON_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"

# Check if pip3 is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Installing pip..."
    python3 -m ensurepip --upgrade || {
        echo "❌ Failed to install pip. Please install pip manually."
        exit 1
    }
fi

echo "✅ pip3 detected"

# Function to install packages
install_packages() {
    local pip_cmd=$1
    echo ""
    echo "📦 Installing dependencies from requirements.txt..."
    
    if [ -f "requirements.txt" ]; then
        $pip_cmd install --upgrade pip
        $pip_cmd install -r requirements.txt
        echo ""
        echo "🌐 Installing Chromium for Playwright (headless URL discovery)..."
        python3 -m playwright install chromium || {
            echo "⚠️  playwright install chromium failed — Neluxmatizer will warn at runtime and continue without headless crawl."
        }
        if command -v dpkg >/dev/null 2>&1 && dpkg -s python3-playwright >/dev/null 2>&1; then
            echo ""
            echo "⚠️  Tenés python3-playwright del APT y además pip instaló playwright."
            echo "   Si ves KeyError: deviceDescriptors en el crawl headless, usá solo uno:"
            echo "   sudo apt remove python3-playwright && pip install -U playwright && python3 -m playwright install chromium"
        fi
        echo "✅ All dependencies installed successfully!"
    else
        echo "❌ requirements.txt not found in current directory"
        exit 1
    fi
}

# Function to create virtual environment
create_venv() {
    echo ""
    echo "🐍 Creating virtual environment..."
    
    # Check if venv module is available
    if ! python3 -m venv --help &> /dev/null; then
        echo "❌ venv module not available. Installing python3-venv..."
        echo "   On Debian/Ubuntu: sudo apt-get install python3-venv"
        exit 1
    fi
    
    python3 -m venv neluxmatizer_env
    echo "✅ Virtual environment created: neluxmatizer_env"
    
    # Activate and install
    echo ""
    echo "📦 Installing dependencies in virtual environment..."
    source neluxmatizer_env/bin/activate
    install_packages "pip"
    deactivate
    
    echo ""
    echo "✅ Virtual environment setup complete!"
}

# Function to make script executable
make_executable() {
    echo ""
    echo "🔧 Making neluxmatizer.py executable..."
    chmod +x neluxmatizer.py
    echo "✅ neluxmatizer.py is now executable"
}

# Function to create output directories
create_directories() {
    echo ""
    echo "📁 Creating output directories..."
    mkdir -p output/poc
    mkdir -p reports
    echo "✅ Output directories created"
}

# Main installation
echo ""
echo "Choose installation method:"
echo "1) Install globally (requires sudo)"
echo "2) Create virtual environment (recommended)"
echo "3) Install in user directory (no sudo required)"
echo "4) Skip installation (manual setup)"
echo ""
read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        echo ""
        echo "⚠️  Installing globally (requires sudo privileges)..."
        if [ "$EUID" -ne 0 ]; then
            echo "   Requesting sudo privileges..."
        fi
        install_packages "sudo pip3"
        make_executable
        create_directories
        ;;
    2)
        create_venv
        make_executable
        create_directories
        echo ""
        echo "📋 Next steps:"
        echo "1. Activate virtual environment: source neluxmatizer_env/bin/activate"
        echo "2. Run the tool: python neluxmatizer.py -h"
        echo ""
        echo "To deactivate: deactivate"
        ;;
    3)
        echo ""
        echo "📦 Installing in user directory..."
        install_packages "pip3 install --user"
        make_executable
        create_directories
        echo ""
        echo "⚠️  Note: You may need to add ~/.local/bin to your PATH"
        ;;
    4)
        echo ""
        echo "📋 Manual installation instructions:"
        echo "1. Install Python 3.7+"
        echo "2. Install dependencies: pip3 install -r requirements.txt"
        echo "3. Install browser: python3 -m playwright install chromium"
        echo "4. Make executable: chmod +x neluxmatizer.py"
        echo "5. Create directories: mkdir -p output/poc reports"
        echo "6. Run: python3 neluxmatizer.py -h"
        make_executable
        create_directories
        ;;
    *)
        echo "❌ Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "🎉 Installation completed!"
echo ""
echo "📖 Quick start examples:"
echo "  python3 neluxmatizer.py -u https://example.com -a -o results.txt -poc"
echo "  python3 neluxmatizer.py -u https://example.com -xss -sqli -poc -t 100"
echo "  python3 neluxmatizer.py -l urls.txt -ssrf -obd https://your-oob-domain.com -poc"
echo ""
echo "📚 For more information, see README.md"
echo "💡 Run 'python3 neluxmatizer.py -h' for all available options"
echo ""
