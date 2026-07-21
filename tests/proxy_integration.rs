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
async fn real_child_mcp_stdio_roundtrip() {
    let wrap = WrapController::new(Some(WrapConfig {
        command: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "read -r line; printf '%s\\n' \"{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":1,\\\"result\\\":{\\\"ok\\\":true}}\"".to_string(),
        ],
    }));

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping"
    });

    let response = wrap
        .forward_request(&request)
        .await
        .expect("forward request succeeds");

    assert_eq!(response["result"]["ok"], true);
}
