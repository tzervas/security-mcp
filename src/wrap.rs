//! Optional wrap/proxy configuration for forwarding MCP to a child process.

use std::sync::Arc;

use tokio::sync::RwLock;

use crate::error::{SecurityError, SecurityResult};
use crate::subprocess::McpChildProcess;

/// Configuration for wrapping another MCP server behind screening.
#[derive(Debug, Clone)]
pub struct WrapConfig {
    pub command: String,
    pub args: Vec<String>,
}

impl WrapConfig {
    pub fn argv(&self) -> Vec<&str> {
        self.args.iter().map(String::as_str).collect()
    }
}

/// Runtime controller for the wrapped child MCP process.
pub struct WrapController {
    config: RwLock<Option<WrapConfig>>,
    child: RwLock<Option<McpChildProcess>>,
}

impl WrapController {
    pub fn new(initial: Option<WrapConfig>) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(initial),
            child: RwLock::new(None),
        })
    }

    pub async fn is_enabled(&self) -> bool {
        self.config.read().await.is_some()
    }

    pub async fn status(&self) -> serde_json::Value {
        let config = self.config.read().await;
        let mut child = self.child.write().await;
        let alive = if let Some(ref mut c) = *child {
            c.is_alive().await
        } else {
            false
        };

        serde_json::json!({
            "wrap_enabled": config.is_some(),
            "child_running": alive,
            "command": config.as_ref().map(|c| &c.command),
            "args": config.as_ref().map(|c| &c.args),
        })
    }

    pub async fn configure(&self, command: String, args: Vec<String>) -> SecurityResult<()> {
        if command.trim().is_empty() {
            return Err(SecurityError::ConfigError(
                "wrap command must not be empty".to_string(),
            ));
        }
        {
            let mut cfg = self.config.write().await;
            *cfg = Some(WrapConfig { command, args });
        }
        self.restart_child().await
    }

    pub async fn disable(&self) -> SecurityResult<()> {
        let mut child = self.child.write().await;
        if let Some(ref mut c) = *child {
            let _ = c.kill().await;
        }
        *child = None;
        *self.config.write().await = None;
        Ok(())
    }

    pub async fn ensure_child(&self) -> SecurityResult<()> {
        if !self.is_enabled().await {
            return Err(SecurityError::ConfigError(
                "wrap mode is not configured".to_string(),
            ));
        }
        let mut child_guard = self.child.write().await;
        let needs_spawn = match child_guard.as_mut() {
            Some(c) => !c.is_alive().await,
            None => true,
        };
        if needs_spawn {
            let cfg = self.config.read().await;
            let cfg = cfg
                .as_ref()
                .ok_or_else(|| SecurityError::ConfigError("wrap config missing".to_string()))?;
            let argv = cfg.argv();
            let spawned = McpChildProcess::spawn(&cfg.command, &argv)
                .await
                .map_err(|e| SecurityError::Internal(format!("failed to spawn wrap child: {e}")))?;
            *child_guard = Some(spawned);
        }
        Ok(())
    }

    pub async fn forward_request(
        &self,
        request: &serde_json::Value,
    ) -> SecurityResult<serde_json::Value> {
        self.ensure_child().await?;
        let mut child = self.child.write().await;
        let child = child
            .as_mut()
            .ok_or_else(|| SecurityError::Internal("wrap child not available".to_string()))?;
        child
            .send_request(request)
            .await
            .map_err(|e| SecurityError::Internal(format!("wrap send failed: {e}")))?;
        let line = child.receive_response().await.ok_or_else(|| {
            SecurityError::Internal("wrap child returned no response".to_string())
        })?;
        serde_json::from_str(&line).map_err(SecurityError::Serialization)
    }

    async fn restart_child(&self) -> SecurityResult<()> {
        let mut child = self.child.write().await;
        if let Some(ref mut c) = *child {
            let _ = c.kill().await;
        }
        *child = None;
        drop(child);
        self.ensure_child().await
    }
}

/// Names handled locally even when wrap mode is active.
pub fn is_local_tool(name: &str) -> bool {
    matches!(
        name,
        "screen_input"
            | "screen_output"
            | "screen_content"
            | "check_safe"
            | "redact_content"
            | "get_config"
            | "proxy_status"
            | "proxy_configure"
    )
}
