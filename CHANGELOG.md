# Changelog

All notable changes to security-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.2] - 2025-01-22

### Changed
- **BREAKING**: Renamed crate from `embeddenator-security-mcp` to `security-mcp`
- Improved prompt injection patterns for better detection coverage
- Replaced manual Default implementations with `#[default]` derive attribute
- Fixed unused variable warning in PII redaction
- Updated test cases for more realistic injection scenarios

### Fixed
- Pattern matching for "disregard all" variant of prompt injection
- Clippy warnings for derivable Default implementations

## [0.1.0-alpha.1] - 2025-01-19

### Added
- Initial security MCP server implementation
- JSON-RPC 2.0 over stdio transport
- Security screening tools:
  - `screen_input` - Screen user input for security threats
  - `screen_output` - Screen AI output for PII/secrets
  - `check_safe` - Quick safety check
  - `scan_full` - Comprehensive security scan
- Detection capabilities:
  - PII detection (email, SSN, credit cards, phone numbers)
  - Secret detection (API keys, tokens, passwords)
  - Injection detection (SQL, command, prompt injection)
- Configurable severity thresholds
- Risk scoring and automated blocking

[Unreleased]: https://github.com/tzervas/security-mcp/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/tzervas/security-mcp/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/tzervas/security-mcp/releases/tag/v0.1.0-alpha.1
