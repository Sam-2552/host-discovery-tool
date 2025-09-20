#!/bin/bash

# Setup script to configure passwordless sudo for nmap
# This allows the host discovery tool to run nmap without password prompts

echo "🔧 Setting up passwordless sudo for nmap..."
echo "=========================================="

# Check if we're running as root
if [ "$EUID" -eq 0 ]; then
    echo "❌ Please don't run this script as root. Run it as your regular user."
    exit 1
fi

# Create sudoers entry for nmap
echo "📝 Creating sudoers entry for nmap..."

# Create a temporary sudoers file
TEMP_SUDOERS="/tmp/nmap_sudoers"
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap" > "$TEMP_SUDOERS"

# Check if the entry already exists
if sudo grep -q "NOPASSWD.*nmap" /etc/sudoers 2>/dev/null; then
    echo "✅ Passwordless sudo for nmap is already configured"
else
    echo "🔐 Adding nmap to sudoers (you may be prompted for your password)..."
    
    # Add the entry to sudoers
    if sudo cp /etc/sudoers /etc/sudoers.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null; then
        echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee -a /etc/sudoers > /dev/null
        
        if [ $? -eq 0 ]; then
            echo "✅ Successfully configured passwordless sudo for nmap"
            echo "   You can now run ./run.sh without password prompts"
        else
            echo "❌ Failed to configure sudoers. Please run manually:"
            echo "   sudo visudo"
            echo "   Add this line: $USER ALL=(ALL) NOPASSWD: /usr/bin/nmap"
        fi
    else
        echo "❌ Failed to backup sudoers file. Please run manually:"
        echo "   sudo visudo"
        echo "   Add this line: $USER ALL=(ALL) NOPASSWD: /usr/bin/nmap"
    fi
fi

# Clean up
rm -f "$TEMP_SUDOERS"

echo ""
echo "🚀 Setup complete! You can now run:"
echo "   ./run.sh"
echo ""
echo "💡 Alternative: Run with sudo directly:"
echo "   sudo ./run.sh"
