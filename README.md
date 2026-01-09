# embeddenator-security-mcp

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
- **Security Proxy Mode**: Acts as a passthru proxy for webpuppet-rs-mcp with integrated security screening.
- **WebSocket Transport**: Supports WebSocket connections for real-time MCP communication.
- **SSE Audit Logging**: Server-Sent Events for real-time audit log streaming.
- **Advanced Detection**: Context-aware PII detection and entropy-based secret scanning.

## What It Does Not Do Yet

- Full DLP-grade PII detection (this is heuristic/pattern-based today).
- Policy-driven redaction across structured formats beyond plain text.

## Security Proxy Mode

The security-mcp can now act as a proxy for webpuppet-rs-mcp with integrated security screening:

```bash
cargo run -- --webpuppet-path ./webpuppet-rs-mcp --websocket --sse
```

### Endpoints

- `POST /mcp` - HTTP MCP transport
- `GET /mcp/ws` - WebSocket MCP transport  
- `GET /audit/sse` - Server-Sent Events for audit logs

## Running

```bash
cargo run -p embeddenator-security-mcp -- --help
```

## License

MIT
