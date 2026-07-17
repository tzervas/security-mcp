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

## STABLE-candidate (branch evidence only)

Use when feat branch + local-ci are green and human review is in progress. **Not STABLE** — consumers must not treat this as a pinned contract on `main`.

- [ ] PR open: `feat/security-proxy-wrap` → `main` (draft OK until review complete)
- [ ] `./scripts/check.sh` green on PR head SHA
- [ ] DRAFT bulletin committed on the same branch as the PR
- [ ] Evidence log under workspace `plans/evidence/48h/` (e.g. `S2-security-wrap-candidate.md`)
- [ ] Optional: set bulletin note **STABLE-candidate** in evidence only; **Status** field stays **DRAFT** until main merge

## Promotion to STABLE

All items required before changing **Status** from **DRAFT** → **STABLE**:

- [ ] Human promote: PR merged to `main` (no autonomous merge)
- [ ] `./scripts/check.sh` green on `main` at the merge commit
- [ ] Wrap integration tests exercise a **real** child MCP process (not router/scaffold-only)
- [ ] Semver / CHANGELOG updated if wire or CLI contract changed since last tag
- [ ] **Consumer acknowledgment:** downstream owners (at minimum **webpuppet-rs**, **webpuppet-rs-mcp**, **agent-mcp** per fleet graph) record acceptance of `security-mcp/wrap` in their repos (separate PRs; producers do not edit consumer trees)
- [ ] Evidence path updated with post-merge SHA and consumer-ack links or issue refs
- [ ] Reviewer sign-off on bulletin **Status** → **STABLE**