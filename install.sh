#!/bin/bash

# Neluxmatizer - Installation Script
# This script installs all necessary dependencies for Neluxmatizer

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

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
# $1 = pip invocation (e.g. "pip", "pip3 install --user", "sudo pip3" — deprecated on PEP 668 distros)
# $2 = python binary for import tests and playwright (default: python3)
install_packages() {
    local pip_cmd=$1
    local py_verify="${2:-python3}"
    echo ""
    echo "📦 Installing dependencies from requirements.txt..."
    
    if [ -f "requirements.txt" ]; then
        $pip_cmd install --upgrade pip
        $pip_cmd install -r requirements.txt
        echo ""
        echo "🔎 Verifying PoC stack (selenium, Pillow)..."
        "$py_verify" -c "import selenium; import PIL; print('   ✅ selenium + Pillow import OK')" || {
            echo "   ⚠️  selenium or Pillow import failed — run: pip install -r requirements.txt"
        }
        echo ""
        echo "🌐 Installing Chromium for Playwright (headless URL discovery)..."
        "$py_verify" -m playwright install chromium || {
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
    
    if [ -d neluxmatizer_env ]; then
        echo "ℹ️  Ya existe neluxmatizer_env — se reutiliza y se actualizan dependencias."
    else
        python3 -m venv neluxmatizer_env
        echo "✅ Virtual environment created: neluxmatizer_env"
    fi
    
    # Activate and install
    echo ""
    echo "📦 Installing dependencies in virtual environment..."
    source neluxmatizer_env/bin/activate
    install_packages "pip" "${SCRIPT_DIR}/neluxmatizer_env/bin/python"
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

# Install a shell launcher so the tool can be run as: neluxmatizer [args]
# No hacemos cd al árbol de instalación: -p/-l/-o y output/ deben ser relativos al cwd del usuario.
# Python pone el directorio del script en sys.path; los imports funcionan sin cd.
# $1 = Python interpreter: command name (python3) or absolute path (venv/bin/python)
# $2 = destination directory for the wrapper (e.g. /usr/local/bin or ~/.local/bin)
# Override system bin dir: NELUXMATIZER_BINDIR=/usr/bin ./install.sh
write_neluxmatizer_wrapper() {
    local python_ref="$1"
    local bin_dir="$2"
    local install_root
    install_root="$(readlink -f "$SCRIPT_DIR")"
    local dest="${bin_dir%/}/neluxmatizer"
    local tmp
    tmp="$(mktemp)"

    local python_abs
    if [ -x "$python_ref" ]; then
        python_abs="$(readlink -f "$python_ref" 2>/dev/null || echo "$python_ref")"
    elif command -v "$python_ref" &>/dev/null; then
        python_abs="$(command -v "$python_ref")"
        python_abs="$(readlink -f "$python_abs" 2>/dev/null || echo "$python_abs")"
    else
        echo "❌ Intérprete Python no encontrado: $python_ref"
        rm -f "$tmp"
        return 1
    fi

    local py_q home_q
    py_q=$(printf '%q' "$python_abs")
    home_q=$(printf '%q' "$install_root")

    cat > "$tmp" <<EOF
#!/usr/bin/env bash
# Neluxmatizer — generado por install.sh
NELUXMATIZER_HOME=$home_q
export NELUXMATIZER_HOME
exec $py_q "\$NELUXMATIZER_HOME/neluxmatizer.py" "\$@"
EOF
    chmod +x "$tmp"
    mkdir -p "$bin_dir"

    if [[ "$bin_dir" == /usr/* ]] || [[ "$bin_dir" == /opt/* ]]; then
        if [ "${EUID:-0}" -eq 0 ]; then
            mv "$tmp" "$dest"
        else
            sudo mv "$tmp" "$dest"
        fi
    else
        mv "$tmp" "$dest"
    fi
    echo "✅ Comando instalado: $dest"
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
echo "1) System command in PATH (venv + sudo solo para /usr/local/bin/neluxmatizer; Kali/Debian OK)"
echo "2) Virtual environment + ~/.local/bin/neluxmatizer (recommended, no sudo)"
echo "3) Install in user directory (no sudo required)"
echo "4) Skip installation (manual setup)"
echo ""
read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        echo ""
        echo "📌 PEP 668 (Kali/Debian): pip global al sistema está bloqueado."
        echo "   Se crea neluxmatizer_env aquí y solo hace falta sudo para copiar el lanzador a PATH."
        echo ""
        create_venv
        make_executable
        create_directories
        BINDIR="${NELUXMATIZER_BINDIR:-/usr/local/bin}"
        echo ""
        echo "📎 Instalando neluxmatizer en $BINDIR (sudo solo para este paso)"
        if [ "$EUID" -ne 0 ]; then
            echo "   Se pedirá la contraseña de sudo..."
        fi
        write_neluxmatizer_wrapper "${SCRIPT_DIR}/neluxmatizer_env/bin/python" "$BINDIR"
        ;;
    2)
        create_venv
        make_executable
        create_directories
        echo ""
        echo "📎 Instalando comando neluxmatizer en ~/.local/bin (usa el Python del venv)"
        mkdir -p "${HOME}/.local/bin"
        write_neluxmatizer_wrapper "${SCRIPT_DIR}/neluxmatizer_env/bin/python" "${HOME}/.local/bin"
        echo ""
        echo "📋 Next steps:"
        echo "1. Asegurate de tener ~/.local/bin en el PATH (ej.: export PATH=\"\$HOME/.local/bin:\$PATH\")"
        echo "2. Ejecutá: neluxmatizer -h   (o activá el venv y usá python neluxmatizer.py como antes)"
        echo ""
        echo "To deactivate (si usás el venv a mano): deactivate"
        ;;
    3)
        echo ""
        echo "📦 Installing in user directory..."
        install_packages "pip3 install --user"
        make_executable
        create_directories
        echo ""
        echo "📎 Instalando comando neluxmatizer en ~/.local/bin"
        mkdir -p "${HOME}/.local/bin"
        write_neluxmatizer_wrapper python3 "${HOME}/.local/bin"
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
        echo "6. Run: neluxmatizer -h  (si instalaste el comando abajo) o python3 neluxmatizer.py -h"
        make_executable
        create_directories
        echo ""
        echo "📎 Instalando comando neluxmatizer en ~/.local/bin"
        mkdir -p "${HOME}/.local/bin"
        write_neluxmatizer_wrapper python3 "${HOME}/.local/bin"
        ;;
    *)
        echo "❌ Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "🎉 Installation completed!"
echo ""
echo "📖 Quick start (desde cualquier directorio, si neluxmatizer está en el PATH):"
echo "  neluxmatizer -u https://example.com -a -o results.txt -poc"
echo "  neluxmatizer -u https://example.com -xss -sqli -poc -t 100"
echo "  neluxmatizer -l urls.txt -ssrf -obd https://your-oob-domain.com -poc"
echo ""
echo "📚 Equivalente: python3 $SCRIPT_DIR/neluxmatizer.py ..."
echo "💡 neluxmatizer -h  (o python3 neluxmatizer.py -h desde el directorio del proyecto)"
echo ""
