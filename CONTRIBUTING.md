# Contributing to Host Discovery Tool

Thank you for your interest in contributing to the Host Discovery Tool! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- `nmap` installed
- Sudo privileges
- Git

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/yourusername/host-discovery-tool.git
   cd host-discovery-tool
   ```

2. **Set up the development environment**
   ```bash
   sudo ./run.sh
   ```

3. **Verify the setup**
   - Open `http://localhost:5000` in your browser
   - Test a small scan to ensure everything works

## 📋 Contribution Guidelines

### Code Style

- **Python**: Follow PEP 8 guidelines
- **JavaScript**: Use consistent indentation (2 spaces)
- **HTML/CSS**: Use consistent formatting
- **Comments**: Write clear, descriptive comments
- **Docstrings**: Include docstrings for functions and classes

### Commit Messages

Use clear, descriptive commit messages:

```bash
# Good examples
git commit -m "Add firewall detection algorithm"
git commit -m "Fix port scan timeout handling"
git commit -m "Update UI responsive design for mobile"

# Avoid
git commit -m "fix stuff"
git commit -m "update"
```

### Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clean, well-documented code
   - Test your changes thoroughly
   - Update documentation if needed

3. **Test your changes**
   ```bash
   # Test the application
   sudo ./run.sh
   
   # Test different scan scenarios
   # - Small IP ranges
   # - Large networks
   # - Edge cases
   ```

4. **Commit and push**
   ```bash
   git add .
   git commit -m "Descriptive commit message"
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request**
   - Use the PR template
   - Provide clear description of changes
   - Include screenshots if UI changes
   - Reference any related issues

## 🐛 Bug Reports

### Before Submitting

1. **Search existing issues** - Check if the bug is already reported
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
3. Enter '...'
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

## ✨ Feature Requests

### Before Submitting

1. **Check existing issues** - Ensure the feature isn't already requested
2. **Consider scope** - Is this within the project's goals?
3. **Think about implementation** - How might this be implemented?

### Feature Request Template

```markdown
**Feature Description**
A clear description of the feature you'd like to see.

**Use Case**
Describe the problem this feature would solve.

**Proposed Solution**
Describe how you think this should work.

**Alternatives**
Describe any alternative solutions you've considered.

**Additional Context**
Any other context about the feature request.
```

## 🧪 Testing

### Manual Testing

Before submitting changes, test:

- **Small networks** (1-10 IPs)
- **Medium networks** (100+ IPs)
- **Different input formats** (CIDR, ranges, custom lists)
- **Edge cases** (invalid IPs, empty inputs)
- **UI responsiveness** (different screen sizes)
- **Export functionality**

### Test Scenarios

```bash
# Test different input types
192.168.1.1
192.168.1.0/24
192.168.1.1-192.168.1.10

# Test edge cases
# Empty input
# Invalid IPs
# Very large ranges
```

## 📚 Documentation

### Code Documentation

- **Functions**: Include docstrings with parameters and return values
- **Classes**: Document purpose and main methods
- **Complex logic**: Add inline comments explaining the approach

### User Documentation

- **README**: Keep installation and usage instructions up to date
- **API**: Document any new endpoints or changes
- **Examples**: Provide clear usage examples

## 🔒 Security Considerations

### nmap Commands

- **Never modify core nmap commands** without careful consideration
- **Test security implications** of any changes
- **Document any security-related changes**

### Sudo Usage

- **Minimize sudo requirements** where possible
- **Document sudo usage** clearly
- **Test passwordless sudo setup** on different systems

## 🏷️ Issue Labels

We use these labels to categorize issues:

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Improvements to documentation
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention is needed
- `question` - Further information is requested

## 📞 Getting Help

- **GitHub Issues**: For bug reports and feature requests
- **GitHub Discussions**: For questions and general help
- **Code Review**: Ask questions in PR comments

## 🎯 Project Goals

The Host Discovery Tool aims to:

- **Simplify network scanning** with an intuitive web interface
- **Provide real-time feedback** during long-running scans
- **Detect potential security issues** like firewalls
- **Support various input formats** for flexibility
- **Maintain security best practices** in implementation

## 📝 Release Process

1. **Version bumping** - Update version numbers
2. **Changelog updates** - Document all changes
3. **Testing** - Comprehensive testing of new features
4. **Documentation** - Update README and other docs
5. **Release notes** - Clear communication of changes

---

Thank you for contributing to the Host Discovery Tool! 🚀
