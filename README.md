# security-mcp

MCP server for security screening: prompt-injection defense, PII detection, and secrets scanning.

This crate is intended to sit “in front of” other tools/servers, so inputs and outputs can be screened consistently.

## Status

Alpha / under active development. Rules and thresholds will evolve.

## What It Does Today (Code-Backed)

- Runs an MCP-compatible JSON-RPC server over HTTP/WebSocket.
- Screens text in two directions:
  - **Input screening** (prompt-injection patterns, suspicious encodings)
  - **Output screening** (PII/secrets patterns, high-entropy tokens)
- Supports batch scanning with CPU-parallelism (`rayon`).

## What It Does Not Do Yet

- Full DLP-grade PII detection (this is heuristic/pattern-based today).
- Policy-driven redaction across structured formats beyond plain text.

## Running

```bash
cargo run -p security-mcp -- --help
```

## License

MIT
