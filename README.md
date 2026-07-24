# security-mcp

<!-- FLEET-BADGES:BEGIN -->
[![CI](https://github.com/tzervas/security-mcp/actions/workflows/fleet-ci.yml/badge.svg?branch=main)](https://github.com/tzervas/security-mcp/actions/workflows/fleet-ci.yml?query=branch%3Amain)
[![Security](https://github.com/tzervas/security-mcp/actions/workflows/fleet-security.yml/badge.svg?branch=main)](https://github.com/tzervas/security-mcp/actions/workflows/fleet-security.yml?query=branch%3Amain)
<!-- FLEET-BADGES:END -->

MCP server for security screening: prompt-injection defense, PII detection, and secrets scanning
**in text content passed through an MCP conversation** (tool calls, model input/output).

This crate is intended to sit “in front of” other tools/servers, so inputs and outputs can be screened consistently.

**Status:** Alpha (`0.2.0-alpha`). Heuristic regex + entropy detectors — not a compliance certificate.

## 5-minute path

```bash
git clone https://github.com/tzervas/security-mcp.git
cd security-mcp

cargo build
cargo test --all-features

# MCP over stdio (hosts attach to stdin/stdout; Ctrl-C to stop)
cargo run -- --stdio
# after install:  cargo install --path . && security-mcp --stdio
```

Expected: `cargo test` passes; `security-mcp --stdio` waits for JSON-RPC lines (no banner on stdout).
Full local gate: `./scripts/check.sh`. Client snippets: [docs/mcp.example.json](docs/mcp.example.json)
(Claude Desktop) and [.mcp.json.example](.mcp.json.example) (Cursor / VS Code).

## What This Is NOT

**This is a content/text screener, not a repository, dependency, or supply-chain scanner.** It does
not clone or walk a filesystem or git tree, does not resolve a dependency graph, and does not shell
out to (or replace) tools like `cargo audit`, `gitleaks`, `trivy`, or `semgrep`. If you need CVE/SBOM
scanning, git-history secret scanning, or static analysis of a codebase, use those tools — this one is
for screening the *text* flowing through an MCP session at request/response time.

## Status

Alpha / under active development. Rules and thresholds will evolve.

## What It Does Today (Code-Backed)

- Runs an MCP-compatible JSON-RPC server over HTTP or stdio.
- Screens text in two directions:
  - **Input screening** (prompt-injection patterns, suspicious encodings)
  - **Output screening** (PII/secrets patterns, high-entropy tokens)
- Supports batch scanning with CPU-parallelism (`rayon`).
- Detection is **regex + entropy pattern matching**, not machine-learning classification and not a
  DLP/data-classification engine — treat matches as heuristic signals to review, not certainties, and
  expect both false positives and false negatives.

## What It Does Not Do Yet

- Full DLP-grade PII detection (this is heuristic/pattern-based today).
- Policy-driven redaction across structured formats beyond plain text.
- Filesystem or git-tree scanning (scanning a repo's files/history for secrets or vulnerable deps).
- Integration with external security tools (`cargo audit`, `gitleaks`, `semgrep`, `trivy`, etc.).
- Validated detection-accuracy metrics (precision/recall) — current patterns are unbenchmarked against
  a labeled corpus; treat detection quality as unverified until such a benchmark exists.

## Running

```bash
cargo run -- --help
cargo run -- --stdio          # MCP clients (required for stdio hosts)
cargo run -- --host 127.0.0.1 --port 3001   # HTTP mode
```

## MCP client config

Copy the example that matches your host (replace `command` with an absolute path if needed):

| Host | Example file |
|------|----------------|
| Cursor / VS Code Copilot | [.mcp.json.example](.mcp.json.example) |
| Claude Desktop | [docs/mcp.example.json](docs/mcp.example.json) |
| Claude Code (CLI) | `claude mcp add` — see below |

Claude Code registers stdio servers from the CLI rather than a config file:

```bash
# -s user makes it available in every project; use -s project for one repo
claude mcp add security-mcp -s user -- /absolute/path/to/security-mcp --stdio
claude mcp list   # expect: security-mcp: … - ✔ Connected
```

Cursor / VS Code (`mcp.json` or `.vscode/mcp.json`):

```json
{
  "servers": {
    "security-mcp": {
      "type": "stdio",
      "command": "security-mcp",
      "args": ["--stdio"]
    }
  }
}
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "security-mcp",
      "args": ["--stdio"]
    }
  }
}
```

> **Important:** The `--stdio` flag is required for stdio hosts. Without it, the server defaults to HTTP on port 3001.

## Local checks & pre-commit

```bash
./scripts/check.sh            # fmt + clippy + build + test (primary gate)
pre-commit install            # optional; see .pre-commit-config.yaml
pre-commit run --all-files
```

Details: [docs/LOCAL_CHECKS.md](docs/LOCAL_CHECKS.md). Agent notes: [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md).

## False Positive Triage & Expected Rates

This tool uses heuristic rules (regex pattern matching and entropy metrics) to flag potential security threats during an active conversation. Some false positives are expected as part of standard operations.

| Detector Category | Expected False Positive Rate | Common Causes of False Positives | Triage Instructions / Recommendation |
|---|---|---|---|
| **PII Detection** | **Low to Medium** | Formatted street addresses, personal names, generic email domains in examples. | Lower severity thresholds or disable specific checkers if operating in public/tutorial contexts. |
| **Secrets & Keys** | **Medium** | High-entropy strings (hashes, Base64 chunks, git SHAs, build artifacts) in technical texts. | Use explicit secret matching or adjust the entropy threshold when working with highly technical domains. |
| **SQL / Cmd Injection** | **Low** | Code snippets, SQL tutorials, or terminal command examples. | Mark as Warning/Review instead of Block for trusted developer workflows. |
| **LDAP Injection** | **Extremely Low** | The LDAP detector is heavily refined to target specific nested LDAP query structures instead of single special characters like `!` or `*`. | Safely allow single occurrences of special characters. |
| **Prompt Injection** | **Medium** | Documentation explaining prompt injection, or tutorials containing typical jailbreak instruction phrasing. | Review flagged inputs manually or bypass screening for administrative prompts. |

## License

MIT

## Status & roadmap

- [Assessment & gaps](docs/ASSESSMENT.md)
- [Product roadmap & API plans](docs/ROADMAP.md)
