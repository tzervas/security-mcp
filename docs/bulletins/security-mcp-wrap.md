# Interface Bulletin: `security-mcp/wrap`

**Status:** DRAFT  
**Bulletin ID:** `security-mcp/wrap`  
**Merged to `main`:** PR [#28](https://github.com/tzervas/security-mcp/pull/28) (`fd24164`); bulletin honesty PR [#29](https://github.com/tzervas/security-mcp/pull/29) on `main` (`ce60fc7` at P17 evidence time)  
**Date:** 2026-07-16  
**Post-merge note:** Code ships on `main`; **Status stays DRAFT** until STABLE promotion checklist below is complete (real child MCP integration tests, remaining consumer acks, human STABLE sign-off).
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

## STABLE promotion checklist (DRAFT → STABLE)

**Status field remains DRAFT** until every **open** item below is satisfied and a human sets **STABLE**.

### Completed (main evidence)

- [x] Wrap feature merged to `main` via PR [#28](https://github.com/tzervas/security-mcp/pull/28) (human promote)
- [x] DRAFT bulletin on `main`; post-merge honesty in PR [#29](https://github.com/tzervas/security-mcp/pull/29)
- [x] `./scripts/check.sh` green on `main` at merge lineage (`ce60fc7` — re-run before STABLE sign-off if `main` advances)
- [x] **Consumer acknowledgment (webpuppet family):** [webpuppet-rs PR #34](https://github.com/tzervas/webpuppet-rs/pull/34) (SECURITY.md / readiness hooks); [webpuppet-rs-mcp PR #26](https://github.com/tzervas/webpuppet-rs-mcp/pull/26) (Depends-on `security-mcp/wrap`@DRAFT). Producer does not edit consumer trees; acks recorded in consumer PRs per P10 evidence.

### Open (block STABLE)

- [ ] Wrap integration tests exercise a **real** child MCP process (not router/scaffold-only); see `tests/proxy_integration.rs` stub `real_child_mcp_stdio_roundtrip` (ignored until fixture binary lands)
- [ ] **Consumer acknowledgment:** **agent-mcp** (and any other fleet consumers not yet acked) record acceptance in their repos
- [ ] Semver / CHANGELOG updated if wire or CLI contract changed since last tag
- [ ] Evidence path updated with post-merge SHA and any new consumer-ack links
- [ ] Reviewer sign-off on bulletin **Status** → **STABLE**