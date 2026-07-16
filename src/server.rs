//! MCP server implementation for security screening

use axum::{
    extract::{Json, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Thread-safe sliding-window rate limiter
pub struct RateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    limit_per_second: usize,
}

impl RateLimiter {
    /// Create a new RateLimiter
    pub fn new(limit_per_second: usize) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            limit_per_second,
        }
    }

    /// Check if the key has exceeded the rate limit
    pub fn check(&self, key: &str) -> bool {
        if self.limit_per_second == 0 {
            return true; // 0 means unlimited
        }

        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        let window_start = now - Duration::from_secs(1);

        let timestamps = requests.entry(key.to_string()).or_default();

        // Retain only timestamps within the last second
        timestamps.retain(|&t| t > window_start);

        if timestamps.len() >= self.limit_per_second {
            false
        } else {
            timestamps.push(now);
            true
        }
    }
}

use crate::error::SecurityResult;
use crate::pipeline::ScreeningConfig;
use crate::protocol::{
    CallToolRequest, InitializeResult, JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId,
    ServerCapabilities, ServerInfo, ToolsCapability, MCP_VERSION,
};
use crate::screeners::ScreeningPolicy;
use crate::tools::ToolRegistry;

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub screening: ScreeningConfig,
    pub policy: ScreeningPolicy,
    pub rate_limit: usize,
    pub tokens: Option<Vec<String>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3001,
            screening: ScreeningConfig::default(),
            policy: ScreeningPolicy::default(),
            rate_limit: 100,
            tokens: None,
        }
    }
}

/// Server state
pub struct ServerState {
    tools: Arc<ToolRegistry>,
    pub rate_limiter: RateLimiter,
    pub tokens: Option<Vec<String>>,
}

impl ServerState {
    pub fn new(config: &ServerConfig) -> Self {
        Self {
            tools: Arc::new(ToolRegistry::with_config(
                config.screening.clone(),
                config.policy.clone(),
            )),
            rate_limiter: RateLimiter::new(config.rate_limit),
            tokens: config.tokens.clone(),
        }
    }
}

/// Security screening MCP server
pub struct SecurityServer {
    config: ServerConfig,
    state: Arc<ServerState>,
}

impl SecurityServer {
    /// Create a new security server
    pub fn new(config: ServerConfig) -> Self {
        let state = Arc::new(ServerState::new(&config));
        Self { config, state }
    }

    /// Create with defaults
    pub fn with_defaults() -> Self {
        Self::new(ServerConfig::default())
    }

    /// Build the router
    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(health))
            .route("/health", get(health))
            .route("/mcp", post(handle_mcp_request))
            .with_state(self.state.clone())
    }

    /// Check if binding to non-loopback address is secure
    fn check_bind_safety(&self) -> SecurityResult<()> {
        let is_loopback = self.config.host == "127.0.0.1"
            || self.config.host == "localhost"
            || self.config.host == "::1";

        if !is_loopback {
            let has_tokens = self
                .config
                .tokens
                .as_ref()
                .map(|t| !t.is_empty())
                .unwrap_or(false);
            let allow_insecure = std::env::var("ALLOW_INSECURE_BIND").unwrap_or_default() == "1";

            if !has_tokens && !allow_insecure {
                return Err(crate::error::SecurityError::ConfigError(
                    "Refusing to bind to non-loopback address without SECURITY_MCP_TOKENS or ALLOW_INSECURE_BIND=1".to_string()
                ));
            }
        }
        Ok(())
    }

    /// Run the server
    pub async fn run(&self) -> SecurityResult<()> {
        self.check_bind_safety()?;

        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(crate::error::SecurityError::Io)?;

        tracing::info!("Security MCP Server listening on {}", addr);

        axum::serve(listener, self.router())
            .await
            .map_err(|e| crate::error::SecurityError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Get server address
    pub fn address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }
}

/// Health check
async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "server": "security-mcp",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Handle MCP request
async fn handle_mcp_request(
    State(state): State<Arc<ServerState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    // Check token authentication if configured
    if let Some(ref allowed_tokens) = state.tokens {
        let mut authenticated = false;
        if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    let token = token.trim();
                    if allowed_tokens.iter().any(|t| t == token) {
                        authenticated = true;
                    }
                }
            }
        }
        if !authenticated {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Unauthorized. Please provide a valid Bearer token in the Authorization header."
                })),
            ).into_response();
        }
    }

    if !state.rate_limiter.check("global") {
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "Rate limit exceeded. Please try again later."
            })),
        )
            .into_response();
    }

    let response = process_request(&state, request).await;
    Json(response).into_response()
}

/// Process MCP request
async fn process_request(state: &ServerState, request: JsonRpcRequest) -> JsonRpcResponse {
    match request.method.as_str() {
        "initialize" => handle_initialize(request.id),
        "initialized" => handle_initialized(request.id),
        "tools/list" => handle_list_tools(request.id, state),
        "tools/call" => handle_call_tool(request.id, state, request.params).await,
        "ping" => handle_ping(request.id),
        method => JsonRpcResponse::error(request.id, JsonRpcError::method_not_found(method)),
    }
}

fn handle_initialize(id: RequestId) -> JsonRpcResponse {
    let result = InitializeResult {
        protocol_version: MCP_VERSION.to_string(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
        },
        server_info: ServerInfo {
            name: "security-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

fn handle_initialized(id: RequestId) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!({}))
}

fn handle_list_tools(id: RequestId, state: &ServerState) -> JsonRpcResponse {
    let tools = state.tools.list_tools();
    JsonRpcResponse::success(id, json!({ "tools": tools }))
}

async fn handle_call_tool(
    id: RequestId,
    state: &ServerState,
    params: Option<Value>,
) -> JsonRpcResponse {
    let params = match params {
        Some(p) => p,
        None => return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params")),
    };

    let call_request: CallToolRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Invalid params: {}", e)),
            )
        }
    };

    let result = state
        .tools
        .execute(&call_request.name, call_request.arguments)
        .await;
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

fn handle_ping(id: RequestId) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!({}))
}

/// Stdio transport for MCP
pub struct StdioTransport {
    state: Arc<ServerState>,
}

impl StdioTransport {
    pub fn new(config: ServerConfig) -> Self {
        let state = Arc::new(ServerState::new(&config));
        Self { state }
    }

    pub async fn run(&self) -> SecurityResult<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    match serde_json::from_str::<JsonRpcRequest>(line) {
                        Ok(request) => {
                            let response = process_request(&self.state, request).await;
                            let response_str = serde_json::to_string(&response).unwrap();
                            stdout.write_all(response_str.as_bytes()).await.ok();
                            stdout.write_all(b"\n").await.ok();
                            stdout.flush().await.ok();
                        }
                        Err(_) => {
                            let error = JsonRpcResponse::error(
                                RequestId::Number(0),
                                JsonRpcError::parse_error(),
                            );
                            let error_str = serde_json::to_string(&error).unwrap();
                            stdout.write_all(error_str.as_bytes()).await.ok();
                            stdout.write_all(b"\n").await.ok();
                            stdout.flush().await.ok();
                        }
                    }
                }
                Err(_) => break,
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(2);
        // First request: ok
        assert!(limiter.check("client_1"));
        // Second request: ok
        assert!(limiter.check("client_1"));
        // Third request: rate limited!
        assert!(!limiter.check("client_1"));

        // Different client should not be affected
        assert!(limiter.check("client_2"));
    }

    #[test]
    fn test_bind_safety_all_cases() {
        // Since std::env is global, we test all cases sequentially in one test to avoid race conditions.

        // 1. Loopback should always succeed
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let server = SecurityServer::new(config);
        assert!(server.check_bind_safety().is_ok());

        // 2. Remote should fail without tokens/env
        std::env::remove_var("ALLOW_INSECURE_BIND");
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            tokens: None,
            ..Default::default()
        };
        let server = SecurityServer::new(config);
        assert!(server.check_bind_safety().is_err());

        // 3. Remote should succeed with tokens
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            tokens: Some(vec!["my-token".to_string()]),
            ..Default::default()
        };
        let server = SecurityServer::new(config);
        assert!(server.check_bind_safety().is_ok());

        // 4. Remote should succeed with ALLOW_INSECURE_BIND=1
        std::env::set_var("ALLOW_INSECURE_BIND", "1");
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            tokens: None,
            ..Default::default()
        };
        let server = SecurityServer::new(config);
        assert!(server.check_bind_safety().is_ok());

        // Cleanup
        std::env::remove_var("ALLOW_INSECURE_BIND");
    }
}
