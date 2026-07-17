# security-mcp — Product Roadmap

**Status:** Living (2026-07-08)  
**North star:** Load-bearing **local** content-screening MCP that agents can put in front of risky tools — honest heuristics, optional strict modes, real proxy path when needed.

Companion: [ASSESSMENT.md](ASSESSMENT.md).

---

## Waves

### Wave A — Harden what exists

| ID | Work | Exit | Status |
|----|------|------|--------|
| S-A1 | Token auth for HTTP (`SECURITY_MCP_TOKENS` or bearer) | Unauthenticated remote bind rejected | **Completed** |
| S-A2 | MCP stdio e2e tests | CI covers tools/call | **Completed** |
| S-A3 | Fix WebSocket claim (implement or delete from README) | Docs = code | **Completed** (Claims cleaned up) |
| S-A4 | Config: enforce timeout_ms + simple rate limit | No dead knobs | **Completed** |
| S-A5 | FP triage pass on noisiest patterns | Document expected FP rate | **Completed** |

### Wave B — Proxy / wrap path (from paused branch)

Triage `origin/security-proxy-integration`:

| ID | Work | Status |
|----|------|--------|
| S-B1 | Diff branch vs main; cherry-pick viable subprocess/proxy | **Completed** |
| S-B2 | **API:** `wrap_command` or sidecar mode that screens child MCP stdio | **Completed** (`--wrap` and `--wrap-args`) |
| S-B3 | Integration tests with mock child server | **Completed** (via `tests/proxy_integration.rs`) |
| S-B4 | Document pairing with webpuppet-rs-mcp | **Completed** (documented below) |

#### Pairing with webpuppet-rs-mcp or other MCP servers

To run `security-mcp` as a transparent, screening sidecar proxy in front of `webpuppet-rs-mcp` (or any other stdio-based MCP server), run `security-mcp` using `--wrap` and `--wrap-args`:

```bash
security-mcp --wrap webpuppet-rs-mcp --wrap-args --stdio --some-other-arg
```

This starts `webpuppet-rs-mcp` in the background, intercepting and screening all `tools/call` inputs and outputs dynamically.

### Wave C — Product quality

| ID | Work |
|----|------|
| S-C1 | Labeled mini-corpus + precision/recall smoke metrics |
| S-C2 | Redaction policies (structured JSON paths) |
| S-C3 | Stable 0.2.0 non-alpha after A+B |

---

## API plan

### MCP tools (current — keep stable)

| Tool | Purpose | Key args |
|------|---------|----------|
| `screen_input` | Inbound / prompt-side screen | `content`, options |
| `screen_output` | Outbound / tool-result screen | `content` |
| `screen_content` | Generic | `content`, `direction?` |
| `check_safe` | Boolean-ish safety summary | `content` |
| `redact_content` | Return redacted text | `content`, policy? |
| `get_config` | Active thresholds (no secrets) | — |

**Envelope:** JSON-RPC MCP; result includes findings list, severity, `safe: bool`, optional redacted text.

### Planned MCP tools (Wave B)

| Tool | Purpose |
|------|---------|
| `proxy_status` | Child process health |
| `proxy_configure` | Allowlisted child command + env (admin token) |

### HTTP (planned auth)

```http
POST /v1/screen
Authorization: Bearer <token>
{ "direction": "input"|"output", "content": "..." }
→ { "safe": true, "findings": [...], "redacted": "..." }
```

Default bind: `127.0.0.1`. Refuse `0.0.0.0` without `ALLOW_INSECURE_BIND=1` + token.

### Rust library (stable intent)

```rust
// Conceptual — keep ScreeningPipeline public
let report = pipeline.screen_input(&text)?;
let report = pipeline.screen_output(&text)?;
```

---

## PR plan

1. Docs assessment + roadmap (this)  
2. Auth + bind safety  
3. MCP e2e + CI  
4. Proxy branch triage PR  
5. Eval harness + 0.2.0  

---

## Non-goals

- Replacing gitleaks / cargo-audit / trivy  
- Guaranteeing zero false negatives  
- Shipping as cabal’s only security control  
