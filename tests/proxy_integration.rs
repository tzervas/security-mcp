//! Integration tests for wrap/proxy scaffolding (Wave B).

use security_mcp::pipeline::ScreeningConfig;
use security_mcp::screeners::ScreeningPolicy;
use security_mcp::server::{SecurityServer, ServerConfig};
use security_mcp::wrap::{WrapConfig, WrapController};

#[tokio::test]
async fn wrap_controller_status_when_disabled() {
    let wrap = WrapController::new(None);
    let status = wrap.status().await;
    assert_eq!(status["wrap_enabled"], false);
}

#[tokio::test]
async fn server_router_includes_optional_wrap_routes() {
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        screening: ScreeningConfig::default(),
        policy: ScreeningPolicy::default(),
        wrap: Some(WrapConfig {
            command: "echo".to_string(),
            args: vec!["wrap-test".to_string()],
        }),
        enable_websocket: true,
        enable_sse: true,
        ..Default::default()
    };
    let server = SecurityServer::new(config);
    let _router = server.router();
}

/// STABLE gate: spawn a real MCP child over stdio and assert a forwarded `tools/list` (or ping) succeeds.
/// Enable when a minimal stdio MCP test fixture is checked in or built by `check.sh`.
#[tokio::test]
#[ignore = "requires real child MCP binary; router/scaffold tests are not sufficient for STABLE"]
async fn real_child_mcp_stdio_roundtrip() {
    // Placeholder: set SECURITY_MCP_WRAP_COMMAND to fixture, send JSON-RPC newline frame, assert response.
    // Bulletin: docs/bulletins/security-mcp-wrap.md — Promotion checklist.
    let _ = WrapController::new(None);
}
