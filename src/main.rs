//! security-mcp
//!
//! MCP server for security screening of inputs and outputs.
//!
//! Provides:
//! - Input screening: Injection detection (SQL, command, prompt injection)
//! - Output screening: PII detection, secrets scanning
//!
//! # Usage
//!
//! Run as HTTP server:
//! ```bash
//! security-mcp --host 127.0.0.1 --port 3001
//! ```
//!
//! Run as stdio transport:
//! ```bash
//! security-mcp --stdio
//! ```

use clap::Parser;

use security_mcp::{
    pipeline::ScreeningConfig,
    screeners::ScreeningPolicy,
    server::{SecurityServer, ServerConfig, StdioTransport},
    wrap::WrapConfig,
    Severity,
};

/// Security Screening MCP Server
#[derive(Parser, Debug)]
#[command(name = "security-mcp")]
#[command(about = "Security screening MCP server for PII, secrets, and injection detection")]
#[command(version)]
struct Args {
    /// Use stdio transport instead of HTTP
    #[arg(long)]
    stdio: bool,

    /// Server host (HTTP mode only)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Server port (HTTP mode only)
    #[arg(long, default_value = "3001")]
    port: u16,

    /// Enable PII detection
    #[arg(long, default_value = "true")]
    pii: bool,

    /// Enable secrets detection
    #[arg(long, default_value = "true")]
    secrets: bool,

    /// Enable injection detection
    #[arg(long, default_value = "true")]
    injection: bool,

    /// Block on high severity findings
    #[arg(long, default_value = "true")]
    block_high: bool,

    /// Allow warnings through
    #[arg(long, default_value = "true")]
    allow_warnings: bool,

    /// Allow redacted content through
    #[arg(long, default_value = "true")]
    allow_redacted: bool,

    /// Rate limit in requests per second (0 for unlimited, HTTP mode only)
    #[arg(long, default_value = "100", env = "SECURITY_MCP_RATE_LIMIT")]
    rate_limit: usize,

    /// Comma-separated list of valid security tokens for HTTP mode (env: SECURITY_MCP_TOKENS)
    #[arg(long, env = "SECURITY_MCP_TOKENS")]
    tokens: Option<String>,

    /// Enable wrap mode: forward non-local MCP traffic to a child server (stdio/HTTP)
    #[arg(long, env = "SECURITY_MCP_WRAP")]
    wrap: bool,

    /// Child MCP command when wrap mode is enabled
    #[arg(long, env = "SECURITY_MCP_WRAP_COMMAND")]
    wrap_command: Option<String>,

    /// Child MCP argv when wrap mode is enabled (repeatable)
    #[arg(long = "wrap-arg", env = "SECURITY_MCP_WRAP_ARGS", num_args = 0..)]
    wrap_args: Vec<String>,

    /// Enable WebSocket MCP transport (HTTP mode)
    #[arg(long, default_value = "false")]
    websocket: bool,

    /// Enable SSE audit stream at /audit/sse (HTTP mode)
    #[arg(long, default_value = "false")]
    sse: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing, sending logs to stderr so stdout is clean for the MCP stdio protocol
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();

    // Build configuration
    let screening_config = ScreeningConfig {
        enable_pii: args.pii,
        enable_secrets: args.secrets,
        enable_injection: args.injection,
        min_severity: Severity::Low,
        block_on_high: args.block_high,
        ..Default::default()
    };

    let policy = ScreeningPolicy {
        allow_warnings: args.allow_warnings,
        allow_redacted: args.allow_redacted,
        log_all: false,
        blocked_message: "Content blocked due to security policy".to_string(),
    };

    let parsed_tokens = args.tokens.map(|s| {
        s.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect::<Vec<String>>()
    });

    let wrap_config = if args.wrap {
        let command = args.wrap_command.ok_or_else(|| {
            anyhow::anyhow!("--wrap requires --wrap-command or SECURITY_MCP_WRAP_COMMAND")
        })?;
        Some(WrapConfig {
            command,
            args: if args.wrap_args.is_empty() {
                vec!["--stdio".to_string()]
            } else {
                args.wrap_args
            },
        })
    } else {
        None
    };

    let server_config = ServerConfig {
        host: args.host,
        port: args.port,
        screening: screening_config,
        policy,
        rate_limit: args.rate_limit,
        tokens: parsed_tokens,
        wrap: wrap_config,
        enable_websocket: args.websocket,
        enable_sse: args.sse,
    };

    if args.stdio {
        tracing::info!("Starting Security MCP Server in stdio mode");
        let transport = StdioTransport::new(server_config);
        transport.run().await?;
    } else {
        tracing::info!(
            "Starting Security MCP Server on {}:{}",
            server_config.host,
            server_config.port
        );
        let server = SecurityServer::new(server_config);
        server.run().await?;
    }

    Ok(())
}
