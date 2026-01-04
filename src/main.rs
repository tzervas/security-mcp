//! embeddenator-security-mcp
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
//! embeddenator-security-mcp --host 127.0.0.1 --port 3001
//! ```
//!
//! Run as stdio transport:
//! ```bash
//! embeddenator-security-mcp --stdio
//! ```

use clap::Parser;

use embeddenator_security_mcp::{
    pipeline::ScreeningConfig,
    screeners::ScreeningPolicy,
    server::{SecurityServer, ServerConfig, StdioTransport},
    Severity,
};

/// Security Screening MCP Server
#[derive(Parser, Debug)]
#[command(name = "embeddenator-security-mcp")]
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
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

    let server_config = ServerConfig {
        host: args.host,
        port: args.port,
        screening: screening_config,
        policy,
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
