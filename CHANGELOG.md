# Changelog

All notable changes to the Host Discovery Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release
- Progressive port scanning implementation (25 → 50 → 100 → 1024)
- Real-time UI with WebSocket updates
- Firewall detection algorithm (80%+ open ports flagged)
- Export functionality for scan results
- Statistics dashboard with live updates
- Multiple input methods (CIDR ranges, IP ranges, custom IP lists)
- Sudo integration and passwordless setup script
- Comprehensive error handling and logging
- Responsive web interface

### Changed
- Migrated from file upload to textarea input for better UX
- Improved error handling and user feedback
- Enhanced UI responsiveness and visual design

### Fixed
- Target parameter passing issues between frontend and backend
- File upload content handling problems
- Sudo password prompt handling
- nmap command execution reliability
- WebSocket event emission and reception
- Temporary file cleanup and management

## [v1.0.0] - 2024-01-XX

### Added
- Progressive port scanning (25 → 50 → 100 → 1024)
- Real-time UI updates via SocketIO
- Firewall detection (80%+ open ports)
- Multiple input methods (CIDR, range, custom list)
- Export functionality
- Statistics dashboard
- Sudo integration and passwordless setup

### Changed
- Migrated from file upload to textarea input
- Improved error handling and logging
- Enhanced UI responsiveness

### Fixed
- Target parameter passing issues
- File upload content handling
- Sudo password prompt handling
- nmap command execution reliability

---

## Version History

- **v1.0.0**: Initial release with core functionality
- **Unreleased**: Development version with latest features

## Contributing

When adding new features or fixing bugs, please update this changelog following the format above.
