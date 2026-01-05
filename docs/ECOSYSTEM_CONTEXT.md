# Embeddenator Security MCP - Ecosystem Context Report

**Generated**: 2026-01-04  
**Purpose**: Cross-project context for AI-assisted development

## Project Identity

| Field | Value |
|-------|-------|
| **Name** | embeddenator-security-mcp |
| **Type** | Native MCP Server (Rust binary) |
| **Transport** | stdio / HTTP |
| **Role** | Security screening for inputs/outputs (PII, secrets, injection) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Client / Other MCP Servers               │
└───────────────────────────┬─────────────────────────────────────┘
                            │ MCP Protocol
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   embeddenator-security-mcp                      │
│  ┌────────────────────────────────────────────────────────┐    │
│  │                  Screening Pipeline                     │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐     │    │
│  │  │   PII    │  │ Secrets  │  │    Injection     │     │    │
│  │  │ Detector │  │ Scanner  │  │    Detector      │     │    │
│  │  └──────────┘  └──────────┘  └──────────────────┘     │    │
│  └────────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────────┐    │
│  │                  Screening Policy                       │    │
│  │  - Block on high severity                               │    │
│  │  - Allow warnings / redacted content                    │    │
│  │  - Configurable actions per finding type                │    │
│  └────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Screening Capabilities

| Category | Detects |
|----------|---------|
| **PII** | Email, phone, SSN, credit cards, addresses |
| **Secrets** | API keys, tokens, passwords, private keys |
| **Injection** | SQL injection, command injection, prompt injection |

## Sister Projects

### Same Ecosystem (Native MCP Servers)

| Project | Relationship | Integration Point |
|---------|--------------|-------------------|
| **embeddenator-agent-mcp** | Consumer | Pre-screens prompts before provider dispatch |
| **embeddenator-webpuppet-mcp** | Consumer | Screens browser automation inputs |
| **embeddenator-context-mcp** | Consumer | Tags stored content with screening status |

### WASM Counterpart (homelab-ci-stack)

| Project | Comparison | Notes |
|---------|------------|-------|
| **homelab-ci-stack/security-mcp** | Lightweight alternative | WASM-based, ~150KB, sandboxed |

#### Feature Comparison

| Feature | embeddenator-security-mcp | homelab-ci-stack/security-mcp |
|---------|---------------------------|-------------------------------|
| **Execution** | Native binary | WASM (wasmtime) |
| **PII Detection** | Yes (comprehensive) | No |
| **Secrets Scanning** | Yes | No |
| **Injection Detection** | Yes | Yes (SQL, XSS, command, path) |
| **Input Sanitization** | Via redaction | Yes (HTML/SQL escaping) |
| **Validation Rules** | No | Yes (email, URL, length, etc.) |
| **Policy Engine** | Yes (configurable) | No |
| **Startup Time** | ~50ms | ~14ms |
| **Use Case** | Full security pipeline | Quick input validation |

## Integration Patterns

### 1. Pre-Flight Security Check

```
user_input
    │
    ├─► security-mcp.screen_input(input)
    │       │
    │       ├─► severity=high → BLOCK
    │       │
    │       └─► severity=low → WARN + continue
    │
    └─► agent-mcp.prompt(screened_input)
```

### 2. Output Screening

```
provider_response
    │
    └─► security-mcp.screen_output(response)
            │
            ├─► PII found → REDACT
            │
            ├─► Secrets found → BLOCK
            │
            └─► Clean → pass through
```

### 3. Hybrid WASM + Native

```
# Fast path (WASM) - quick validation
echo '{"method":"detect_injection","params":{"input":"..."}}' | wasmtime security-mcp.wasm
# Returns in ~14ms

# Full path (Native) - comprehensive screening  
security-mcp.screen(input, {pii: true, secrets: true, injection: true})
# Returns in ~50ms with full analysis
```

### 4. Context-Aware Storage

```
security-mcp.screen(input)
    │
    └─► result = {severity, findings, redacted}
            │
            └─► context-mcp.store(input, metadata={
                    screening_status: result.severity,
                    redacted: result.redacted,
                    findings_count: result.findings.length
                })
```

## Configuration

```bash
# Full screening (HTTP server)
security-mcp --host 127.0.0.1 --port 3001 --pii --secrets --injection

# Lightweight (stdio, injection only)
security-mcp --stdio --no-pii --no-secrets --injection

# Permissive (allow warnings through)
security-mcp --stdio --allow-warnings --allow-redacted
```

## Key Dependencies

```toml
[dependencies]
tokio = { version = "1.35", features = ["full"] }
regex = "1.10"          # Pattern matching
serde = { version = "1.0", features = ["derive"] }
lazy_static = "1.4"     # Compiled regex patterns
```

## Source Structure

```
src/
├── main.rs       # CLI entry point
├── lib.rs        # Public API exports
├── server.rs     # MCP server + StdioTransport
├── pipeline.rs   # ScreeningConfig, orchestration
├── screeners/    # Detection modules
│   ├── mod.rs
│   ├── pii.rs       # PII patterns
│   ├── secrets.rs   # Secret detection
│   └── injection.rs # Injection patterns
└── policy.rs     # ScreeningPolicy, actions
```

## Testing & Validation

### Local Testing

```bash
# Test injection detection
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"screen","arguments":{"input":"SELECT * FROM users WHERE id=1 OR 1=1--"}}}' | cargo run -- --stdio
```

### Integration with homelab-ci-stack

The WASM version provides complementary capabilities:

```bash
# Pull from GHCR
oras pull ghcr.io/tzervas/security-mcp:dev -o ./wasm/

# Test injection detection (WASM) - 14ms
echo '{"method":"detect_injection","params":{"input":"OR 1=1--"}}' | wasmtime run ./wasm/security-mcp.wasm

# Test sanitization (WASM) - not available in native version
echo '{"method":"sanitize","params":{"input":"<script>alert(1)</script>"}}' | wasmtime run ./wasm/security-mcp.wasm
```

## homelab-ci-stack Interop Data

Test results captured at:
```
logs/wasm-test-runs/<timestamp>/
├── interop/security-mcp-sanitize.json
├── interop/security-mcp-detect_injection.json
├── interop/security-mcp-validate.json
└── artifacts/security-mcp/security-mcp.wasm
```

### Sample WASM Test Results

```json
{
  "method": "detect_injection",
  "input": {"input": "SELECT * FROM users WHERE id = 1 OR 1=1--"},
  "output": {
    "success": true,
    "result": {
      "is_safe": false,
      "threat_count": 2,
      "threats": [
        {"threat_type": "sql_injection", "pattern": "1=1--", "severity": "high"},
        {"threat_type": "sql_injection", "pattern": "or 1=1", "severity": "high"}
      ]
    }
  },
  "execution_ms": 14
}
```

## Development Notes

### When to Use Which Version

| Scenario | Recommended |
|----------|-------------|
| Full security audit | Native (this repo) |
| Quick input validation | WASM (homelab-ci-stack) |
| PII/secrets detection | Native only |
| Sandboxed tool execution | WASM (wasmtime) |
| Pre-flight checks in agent | Either (based on latency needs) |

### Severity Levels

```rust
pub enum Severity {
    Low,      // Informational, allow through
    Medium,   // Warning, log + allow
    High,     // Block by default
    Critical, // Always block
}
```

### Policy Actions

```rust
pub struct ScreeningPolicy {
    pub allow_warnings: bool,     // Let Low/Medium through
    pub allow_redacted: bool,     // Pass redacted content
    pub log_all: bool,            // Audit logging
    pub blocked_message: String,  // Custom block message
}
```

### Complementary Capabilities

The WASM version in homelab-ci-stack provides features not in this server:

| WASM Feature | Description |
|--------------|-------------|
| `sanitize` | HTML/SQL escaping for safe output |
| `validate` | Rule-based validation (email, URL, length) |

Consider adding these to this server or keeping the division of labor:
- **Native**: Detection + Policy (what's dangerous?)
- **WASM**: Sanitization + Validation (make it safe)

---

*This report was generated to provide cross-project context for AI-assisted development across the embeddenator ecosystem.*
