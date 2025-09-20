# 🔍 Host Discovery Tool

A powerful web-based host discovery tool that performs progressive network scanning using `nmap` with a clean, real-time UI. Discover active hosts, open ports, and potential firewalls across your network infrastructure.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)
![nmap](https://img.shields.io/badge/nmap-Required-red.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- **Progressive Port Scanning**: Automatically escalates from 25 → 50 → 100 → 1024 ports for undiscovered hosts
- **Real-time UI Updates**: Live progress tracking with WebSocket communication
- **Firewall Detection**: Automatically flags hosts with 80%+ open ports as potential firewalls
- **Multiple Input Methods**: Support for CIDR ranges, IP ranges, and custom IP lists
- **Export Functionality**: Download scan results while scanning is in progress
- **Clean Statistics Dashboard**: Track IPs provided, active hosts, ping responses, and open ports
- **Sudo Integration**: Secure privilege escalation for `nmap` operations

## 🚀 Quick Start

### Prerequisites

- Linux/macOS system
- Python 3.8+
- `nmap` installed
- Sudo privileges

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/host-discovery-tool.git
   cd host-discovery-tool
   ```

2. **Run the setup script**
   ```bash
   sudo ./run.sh
   ```

   The script will automatically:
   - Install `uv` if not present
   - Create virtual environment
   - Install dependencies
   - Start the web application

3. **Access the web interface**
   - Open your browser to `http://localhost:5000`
   - Start scanning your network!

## 📖 Usage

### Input Methods

**CIDR Range:**
```
192.168.1.0/24
```

**IP Range:**
```
192.168.1.1-192.168.1.100
```

**Custom IP List:**
```
192.168.1.1
192.168.1.5
192.168.1.10
```

### Scan Process

1. **Ping Scan**: Discovers all responsive hosts
2. **Port Scan 25**: Scans top 25 ports on all hosts
3. **Progressive Scanning**: For hosts with no open ports:
   - Port Scan 50
   - Port Scan 100  
   - Port Scan 1024

### UI Features

- **Real-time Statistics**: Track progress and results
- **Live Updates**: See hosts and ports as they're discovered
- **Firewall Detection**: Automatically flag suspicious hosts
- **Export Results**: Download scan data anytime

## 🛠️ Technical Details

### Architecture

- **Backend**: Flask with SocketIO for real-time communication
- **Frontend**: HTML/CSS/JavaScript with responsive design
- **Scanner**: Python wrapper around `nmap` commands
- **Dependencies**: Managed with `uv` for fast, reliable installs

### nmap Commands Used

**Ping Scan:**
```bash
sudo nmap -sn -n -PE -PS <target> -oA ping
sudo nmap -sn -n -PE -PS -iL <ip_list> -oA ping
```

**Port Scan:**
```bash
sudo nmap -Pn -sS --top-ports <count> <target> -oA port
sudo nmap -Pn -sS --top-ports <count> -iL <ip_list> -oA port
```

### Security Considerations

- Requires sudo privileges for `nmap` operations
- Supports passwordless sudo configuration
- Temporary files are automatically cleaned up
- No sensitive data stored in logs

## 🔧 Configuration

### Passwordless Sudo Setup

For automated scanning without password prompts:

```bash
./setup_sudo.sh
```

This configures sudo to allow `nmap` commands without password prompts.

### Manual Setup

If you prefer manual configuration:

```bash
# Add to /etc/sudoers.d/nmap
echo "yourusername ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/nmap
```

## 📊 API Endpoints

- `POST /start_scan` - Start new scan
- `POST /stop_scan` - Stop current scan  
- `GET /scan_status` - Get current scan status
- `GET /export_results` - Download scan results

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Pull Request Process

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed
4. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
5. **Push to your branch**
   ```bash
   git push origin feature/amazing-feature
   ```
6. **Open a Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/host-discovery-tool.git
cd host-discovery-tool

# Install development dependencies
sudo ./run.sh

# Make changes and test
# Run tests (when available)
python -m pytest tests/
```

### Code Style

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings for functions and classes
- Include type hints where appropriate

## 📝 Changelog

### [Unreleased]
- Initial release
- Progressive port scanning implementation
- Real-time UI with WebSocket updates
- Firewall detection algorithm
- Export functionality

### [v1.0.0] - 2024-01-XX
- **Added**
  - Progressive port scanning (25 → 50 → 100 → 1024)
  - Real-time UI updates via SocketIO
  - Firewall detection (80%+ open ports)
  - Multiple input methods (CIDR, range, custom list)
  - Export functionality
  - Statistics dashboard
  - Sudo integration and passwordless setup

- **Changed**
  - Migrated from file upload to textarea input
  - Improved error handling and logging
  - Enhanced UI responsiveness

- **Fixed**
  - Target parameter passing issues
  - File upload content handling
  - Sudo password prompt handling
  - nmap command execution reliability

## 🐛 Bug Reports

Found a bug? Please report it!

### Before Reporting

1. **Check existing issues** - Search for similar problems
2. **Test latest version** - Ensure you're using the most recent code
3. **Gather information** - Collect relevant details

### Bug Report Template

```markdown
**Bug Description**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment**
- OS: [e.g. Ubuntu 22.04]
- Python: [e.g. 3.9.7]
- nmap: [e.g. 7.80]
- Browser: [e.g. Chrome 120]

**Additional Context**
Any other context about the problem.
```

### Reporting Process

1. **Create a new issue** using the bug report template
2. **Label appropriately** (bug, enhancement, question)
3. **Provide detailed information** following the template
4. **Be patient** - we'll respond as soon as possible

### Known Issues

- **Sudo Requirements**: Some systems may require manual sudo configuration
- **Large Networks**: Very large networks may take significant time to scan
- **Firewall Detection**: May flag legitimate services as firewalls in some cases

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [nmap](https://nmap.org/) - The network mapper
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [SocketIO](https://socket.io/) - Real-time communication
- [uv](https://github.com/astral-sh/uv) - Fast Python package manager

## 📞 Support

- **Documentation**: Check this README and inline code comments
- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and general help

---

**Made with ❤️ for network administrators and security professionals**