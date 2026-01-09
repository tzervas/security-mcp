//! MCP server implementation for security screening

use axum::{
    extract::{Json, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::audit::AuditLogger;
use crate::error::SecurityResult;
use crate::pipeline::ScreeningConfig;
use crate::protocol::{
    CallToolRequest, JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId,
};
use crate::screeners::ScreeningPolicy;
use crate::subprocess::WebpuppetSubprocess;
use crate::tools::ToolRegistry;

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub screening: ScreeningConfig,
    pub policy: ScreeningPolicy,
    pub webpuppet_path: String,
    pub webpuppet_args: Vec<String>,
    pub enable_websocket: bool,
    pub enable_sse: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3001,
            screening: ScreeningConfig::default(),
            policy: ScreeningPolicy::default(),
            webpuppet_path: "webpuppet-rs-mcp".to_string(),
            webpuppet_args: vec!["--stdio".to_string()],
            enable_websocket: true,
            enable_sse: true,
        }
    }
}

/// Server state
pub struct ServerState {
    tools: Arc<ToolRegistry>,
    webpuppet: Arc<RwLock<Option<WebpuppetSubprocess>>>,
    pub audit: Arc<AuditLogger>,
    config: ServerConfig,
}

impl ServerState {
    pub fn new(config: &ServerConfig) -> Self {
        Self {
            tools: Arc::new(ToolRegistry::with_config(
                config.screening.clone(),
                config.policy.clone(),
            )),
            webpuppet: Arc::new(RwLock::new(None)),
            audit: Arc::new(AuditLogger::new()),
            config: config.clone(),
        }
    }

    pub async fn ensure_webpuppet_running(&self) -> SecurityResult<()> {
        let mut webpuppet = self.webpuppet.write().await;
        if webpuppet.is_none() || !webpuppet.as_mut().unwrap().is_alive().await {
            let args: Vec<&str> = self.config.webpuppet_args.iter().map(|s| s.as_str()).collect();
            *webpuppet = Some(WebpuppetSubprocess::spawn(
                &self.config.webpuppet_path,
                &args,
            ).await.map_err(|e| crate::error::SecurityError::Internal(format!("Failed to spawn webpuppet: {}", e)))?);
        }
        Ok(())
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
            .route("/mcp/ws", get(handle_websocket))
            .route("/audit/sse", get(crate::audit::handle_sse))
            .with_state(self.state.clone())
    }

    /// Run the server
    pub async fn run(&self) -> SecurityResult<()> {
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
        "server": "embeddenator-security-mcp",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Handle MCP request
async fn handle_mcp_request(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let response = process_request(&state, request).await;
    Json(response)
}

/// Handle WebSocket upgrade
async fn handle_websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ServerState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_websocket_connection(socket, state))
}

/// Handle WebSocket connection
async fn handle_websocket_connection(mut socket: WebSocket, state: Arc<ServerState>) {
    while let Some(msg) = socket.recv().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(request) = serde_json::from_str::<JsonRpcRequest>(&text) {
                    let response = process_request_ws(&state, request).await;
                    if socket.send(Message::Text(serde_json::to_string(&response).unwrap().into())).await.is_err() {
                        break;
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            _ => {}
        }
    }
}

/// Process MCP request for WebSocket
async fn process_request_ws(state: &ServerState, request: JsonRpcRequest) -> JsonRpcResponse {
    // Apply security screening first
    match request.method.as_str() {
        "tools/call" => {
            // Screen the tool call arguments as input
            if let Some(params) = &request.params {
                if let Ok(call_request) = serde_json::from_value::<CallToolRequest>(params.clone()) {
                    let args_str = serde_json::to_string(&call_request.arguments).unwrap_or_default();
                    if let Err(_) = state.tools.screen_input_sync(&args_str) {
                        return JsonRpcResponse::error(request.id, JsonRpcError::invalid_params("Security policy violation"));
                    }
                }
            }
        }
        _ => {}
    }

    // Proxy to webpuppet subprocess
    state.ensure_webpuppet_running().await.unwrap();
    let mut webpuppet = state.webpuppet.write().await;
    if let Some(ref mut wp) = *webpuppet {
        wp.send_request(&serde_json::to_value(&request).unwrap()).await.unwrap();
        if let Some(response_str) = wp.receive_response().await {
            if let Ok(response) = serde_json::from_str(&response_str) {
                return response;
            }
        }
    }

    JsonRpcResponse::error(request.id, JsonRpcError::internal_error("Webpuppet communication failed"))
}

/// Process MCP request
async fn process_request(state: &ServerState, request: JsonRpcRequest) -> JsonRpcResponse {
    // Apply security screening first
    match request.method.as_str() {
        "tools/call" => {
            // Screen the tool call arguments as input
            if let Some(params) = &request.params {
                if let Ok(call_request) = serde_json::from_value::<CallToolRequest>(params.clone()) {
                    let args_str = serde_json::to_string(&call_request.arguments).unwrap_or_default();
                    if let Err(_) = state.tools.screen_input_sync(&args_str) {
                        return JsonRpcResponse::error(request.id, JsonRpcError::invalid_params("Security policy violation"));
                    }
                }
            }
        }
        _ => {}
    }

    // Proxy to webpuppet subprocess
    state.ensure_webpuppet_running().await.unwrap();
    let mut webpuppet = state.webpuppet.write().await;
    if let Some(ref mut wp) = *webpuppet {
        wp.send_request(&serde_json::to_value(&request).unwrap()).await.unwrap();
        if let Some(response_str) = wp.receive_response().await {
            if let Ok(response) = serde_json::from_str(&response_str) {
                return response;
            }
        }
    }

    JsonRpcResponse::error(request.id, JsonRpcError::internal_error("Webpuppet communication failed"))
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
