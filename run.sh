#!/bin/bash

# Host Discovery Tool Startup Script

echo "🔍 Starting Host Discovery Tool..."
echo "=================================="

# Check if uv is installed, install if not
if ! command -v uv &> /dev/null; then
    echo "📦 uv is not installed. Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    
    # Add common uv installation paths to PATH
    export PATH="/root/.local/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    
    # Debug: Check where uv might be installed
    echo "🔍 Checking for uv installation..."
    for path in "/root/.local/bin/uv" "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        if [ -f "$path" ]; then
            echo "✅ Found uv at: $path"
        fi
    done
    
    # Verify installation
    if command -v uv &> /dev/null; then
        echo "✅ uv installed successfully at: $(which uv)"
    else
        echo "❌ Failed to install uv. Please install manually:"
        echo "   curl -LsSf https://astral.sh/uv/install.sh | sh"
        echo "   Then add the installation directory to your PATH"
        exit 1
    fi
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "❌ nmap is not installed. Please install nmap first:"
    echo "   Ubuntu/Debian: sudo apt-get install nmap"
    echo "   CentOS/RHEL:   sudo yum install nmap"
    exit 1
fi

# Check if we're running as root or have sudo access
if ! sudo -n true 2>/dev/null; then
    echo "⚠️  This tool requires sudo privileges for nmap scans."
    echo "   Please run this script with sudo or configure passwordless sudo for nmap."
    echo "   Example: sudo ./run.sh"
    exit 1
fi

echo "✅ Sudo privileges confirmed"

# Ensure uv is in PATH (include all common installation locations)
export PATH="/root/.local/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

# Activate virtual environment and install dependencies
if [ -d ".venv" ]; then
    echo "📦 Activating virtual environment and installing dependencies..."
    source .venv/bin/activate
    uv pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies. Please check your virtual environment."
        exit 1
    fi
else
    echo "📦 Creating virtual environment and installing dependencies..."
    uv venv
    source .venv/bin/activate
    uv pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies. Please check your Python environment."
        exit 1
    fi
fi

echo "✅ Dependencies installed successfully!"
echo ""
echo "🚀 Starting the web application..."
echo "   Open your browser and go to: http://localhost:5000"
echo "   Press Ctrl+C to stop the server"
echo ""

# Start the Flask application using the virtual environment Python
.venv/bin/python app.py
