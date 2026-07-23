# Changelog

All notable changes to security-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **MCP handshake was unparseable to conforming clients.** `initialize` serialized its result in
  snake_case (`protocol_version`, `server_info`, `list_changed`; also `input_schema` and `is_error`
  on the tool path) where the MCP wire format is camelCase, so clients dropped the connection with
  no diagnostic — the server itself built, started, and returned a well-formed JSON-RPC frame, so
  manual stdio smoke tests looked healthy. Added `#[serde(rename_all = "camelCase")]` to
  `ToolsCapability`, `InitializeResult`, `Tool` and `CallToolResult`. Fields with an explicit
  `#[serde(rename = …)]` (`type`, `enum`) are unaffected.

### Added
- Regression tests pinning the MCP wire names in both directions (camelCase present, snake_case
  absent) so a struct edit cannot silently break the handshake again.
- README: Claude Code (CLI) registration via `claude mcp add`, alongside the existing
  Cursor / VS Code and Claude Desktop examples.

## [0.2.0-alpha] - 2026-07-21

### Added
- Fleet CI standards: PR/issue templates, `fleet-ci.yml`, `fleet-security.yml`, meta issue-close/reopen workflows (`docs/FLEET_STANDARDS.md`).

### Changed
- CI hardened for self-hosted runners: no bare `sudo apt-get`, pinned gitleaks install, guarded system deps, `CARGO_BUILD_JOBS`/toolchain setup for fleet cargo jobs.
- gitleaks allowlist scoped to intentional detector-fixture secret shapes (`src/patterns.rs`, smoke tests) so fleet-security scans stay green without masking real findings.
- Version bump `0.1.7-alpha` → `0.2.0-alpha` (CI/fleet hardening; still alpha — Wave B proxy/wrap path and eval harness remain open per `docs/ROADMAP.md`).

## [0.1.7-alpha] - 2026-07-16

### Added
- 5-minute path in README (`cargo build` / `cargo test` / `security-mcp --stdio`).
- MCP host examples: `docs/mcp.example.json` (Claude Desktop), `.mcp.json.example` (Cursor / VS Code).
- `CLAUDE.md` with cargo / check.sh command surface for agents.
- Optional `.pre-commit-config.yaml` (fmt + pre-push full `scripts/check.sh`); primary gate remains `./scripts/check.sh`.

### Changed
- `scripts/check.sh` and `docs/LOCAL_CHECKS.md` note pre-commit as optional convenience.
- Version bump `0.1.6-alpha` → `0.1.7-alpha` (docs / agent-surface production polish).

### Prior unreleased notes (landed earlier on main)
- `LICENSE` file (MIT, matching `Cargo.toml`'s declared license).
- `tests/smoke.rs`: black-box integration smoke tests against the public API.
- README: clarified content/text screener (not repo/CVE scanner).
- Chore: tero-index / AGENTS / local CI parity hygiene.

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

[Unreleased]: https://github.com/tzervas/security-mcp/compare/v0.2.0-alpha...HEAD
[0.2.0-alpha]: https://github.com/tzervas/security-mcp/compare/v0.1.7-alpha...v0.2.0-alpha
[0.1.7-alpha]: https://github.com/tzervas/security-mcp/compare/v0.1.0-alpha.2...v0.1.7-alpha
[0.1.0-alpha.2]: https://github.com/tzervas/security-mcp/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/tzervas/security-mcp/releases/tag/v0.1.0-alpha.1
