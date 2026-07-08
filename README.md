# security-mcp

MCP server for security screening: prompt-injection defense, PII detection, and secrets scanning
**in text content passed through an MCP conversation** (tool calls, model input/output).

This crate is intended to sit “in front of” other tools/servers, so inputs and outputs can be screened consistently.

## What This Is NOT

**This is a content/text screener, not a repository, dependency, or supply-chain scanner.** It does
not clone or walk a filesystem or git tree, does not resolve a dependency graph, and does not shell
out to (or replace) tools like `cargo audit`, `gitleaks`, `trivy`, or `semgrep`. If you need CVE/SBOM
scanning, git-history secret scanning, or static analysis of a codebase, use those tools — this one is
for screening the *text* flowing through an MCP session at request/response time.

## Status

Alpha / under active development. Rules and thresholds will evolve.

## What It Does Today (Code-Backed)

- Runs an MCP-compatible JSON-RPC server over HTTP/WebSocket.
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
cargo run -p security-mcp -- --help
```

## Usage with VS Code / GitHub Copilot

Install the binary:

```bash
cargo install security-mcp
```

Add to your VS Code MCP configuration (typically `~/.config/Code/User/profiles/<profile>/mcp.json` or `.vscode/mcp.json`):

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

> **Important**: The `--stdio` flag is required for VS Code integration. Without it, the server defaults to HTTP mode on port 3001.

## Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

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

## License

MIT
