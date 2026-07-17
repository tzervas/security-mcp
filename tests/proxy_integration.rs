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
