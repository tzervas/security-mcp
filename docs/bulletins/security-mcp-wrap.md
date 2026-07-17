# Interface Bulletin: `security-mcp/wrap`

**Status:** DRAFT  
**Bulletin ID:** `security-mcp/wrap`  
**Branch:** `feat/security-proxy-wrap` (not merged to `main`)  
**Date:** 2026-07-16  
**Source branch triage:** `origin/security-proxy-integration` (cherry-picked concepts, not a blind merge)

## Summary

Optional **wrap mode** forwards MCP JSON-RPC to a **child MCP server** over newline-delimited stdio, while keeping local screening tools and Wave A HTTP hardening (token auth, bind safety, rate limits).

## Consumer contract (DRAFT)

### Modes

| Mode | Behavior |
|------|----------|
| Default (no wrap) | Same as `main`: screening tools only; no child process |
| Wrap enabled | Non-local MCP methods forward to child; `tools/call` arguments screened before forward |

### CLI / env

| Flag / env | Purpose |
|------------|---------|
| `--wrap` / `SECURITY_MCP_WRAP=1` | Enable wrap mode |
| `--wrap-command` / `SECURITY_MCP_WRAP_COMMAND` | Child binary (required when wrap on) |
| `--wrap-arg` / `SECURITY_MCP_WRAP_ARGS` | Repeatable child argv (default `["--stdio"]`) |
| `--websocket` | HTTP route `GET /mcp/ws` |
| `--sse` | HTTP route `GET /audit/sse` (audit events) |

### MCP tools (Wave B)

| Tool | Purpose |
|------|---------|
| `proxy_status` | Child health + configured command |
| `proxy_configure` | Set allowlisted child command (`admin_token` required) |

**Admin token:** `SECURITY_MCP_ADMIN_TOKEN`, or first entry of `SECURITY_MCP_TOKENS`.

### Local tools (never forwarded)

`screen_input`, `screen_output`, `screen_content`, `check_safe`, `redact_content`, `get_config`, `proxy_status`, `proxy_configure`

## Non-goals (this bulletin)

- No dependency on webpuppet or agent-mcp trees in this repo
- No claim of STABLE until integration tests cover a real child MCP and human promote gate passes
- No merge to `main` via this draft alone

## Verification

```bash
./scripts/check.sh
```

## Promotion gate (human)

1. Review PR `feat/security-proxy-wrap` → `main`
2. Run `./scripts/check.sh` on reviewer machine
3. Bump bulletin **Status** from DRAFT → STABLE-candidate after sign-off