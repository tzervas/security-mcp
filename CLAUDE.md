# CLAUDE.md — security-mcp

Alpha **content/text screener** MCP (prompt injection, PII, secrets). Not a repo/CVE scanner.

## Commands

```bash
# Build
cargo build
cargo build --release

# Tests
cargo test --all-features

# Full local gate (fmt + clippy -D warnings + build + test)
./scripts/check.sh
./scripts/check.sh --fix   # apply rustfmt

# Run MCP over stdio (clients wire stdin/stdout)
cargo run -- --stdio
# or after install:
security-mcp --stdio

# Help / version
cargo run -- --help
cargo run -- --version
```

## Layout

| Path | Role |
|------|------|
| `src/main.rs` | CLI (`--stdio`, HTTP host/port, wrap mode) |
| `src/server.rs` | MCP HTTP + stdio transport |
| `src/pipeline.rs` | Screening pipeline + config |
| `src/detectors.rs` / `patterns.rs` / `screeners.rs` | Heuristic detectors |
| `src/tools.rs` | MCP tool handlers |
| `tests/smoke.rs` | Public API + stdio e2e smoke |
| `docs/mcp.example.json` | Claude Desktop MCP snippet |
| `.mcp.json.example` | Cursor / VS Code MCP snippet |

## Agent rules

- Prefer `./scripts/check.sh` before claiming work complete.
- Detection is **regex + entropy** — document false-positive expectations; do not claim DLP/compliance accuracy.
- Optional pre-commit: `pre-commit install` (see `.pre-commit-config.yaml`); day-to-day gate is `scripts/check.sh`.
- See [AGENTS.md](AGENTS.md) for Tero / cabal workflow notes.
- Leave mycelium isolated.

## Status

Alpha (`0.1.x-alpha`). Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md). Assessment: [docs/ASSESSMENT.md](docs/ASSESSMENT.md).
