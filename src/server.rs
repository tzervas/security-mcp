//! MCP server implementation for security screening

use axum::{
    extract::{Json, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;

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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3001,
            screening: ScreeningConfig::default(),
            policy: ScreeningPolicy::default(),
        }
    }
}

/// Server state
pub struct ServerState {
    tools: Arc<ToolRegistry>,
}

impl ServerState {
    pub fn new(config: &ServerConfig) -> Self {
        Self {
            tools: Arc::new(ToolRegistry::with_config(
                config.screening.clone(),
                config.policy.clone(),
            )),
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
            name: "embeddenator-security-mcp".to_string(),
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
