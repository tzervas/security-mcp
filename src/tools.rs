//! MCP tool implementations for security screening

use serde_json::{json, Value};
use std::collections::HashMap;

use std::sync::Arc;

use crate::pipeline::{ScreeningConfig, ScreeningDirection, ScreeningPipeline};
use crate::protocol::{CallToolResult, InputSchema, PropertySchema, Tool};
use crate::screeners::{InputScreener, OutputScreener, ScreeningPolicy};
use crate::wrap::WrapController;

/// Tool registry for security screening
pub struct ToolRegistry {
    input_screener: InputScreener,
    output_screener: OutputScreener,
    pipeline: ScreeningPipeline,
    wrap: Option<Arc<WrapController>>,
}

impl ToolRegistry {
    /// Create a new tool registry
    pub fn new() -> Self {
        Self {
            input_screener: InputScreener::new(),
            output_screener: OutputScreener::new(),
            pipeline: ScreeningPipeline::with_defaults(),
            wrap: None,
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: ScreeningConfig, policy: ScreeningPolicy) -> Self {
        Self::with_config_and_wrap(config, policy, WrapController::new(None))
    }

    /// Create with screening configuration and optional wrap controller.
    pub fn with_config_and_wrap(
        config: ScreeningConfig,
        policy: ScreeningPolicy,
        wrap: Arc<WrapController>,
    ) -> Self {
        Self {
            input_screener: InputScreener::with_config(config.clone(), policy.clone()),
            output_screener: OutputScreener::with_config(config.clone(), policy),
            pipeline: ScreeningPipeline::new(config),
            wrap: Some(wrap),
        }
    }

    /// Screen tool-call arguments synchronously (wrap/proxy path).
    pub fn screen_input_sync(
        &self,
        content: &str,
    ) -> crate::error::SecurityResult<crate::screeners::ScreenedContent> {
        self.input_screener.screen(content)
    }

    /// Get all available tools
    pub fn list_tools(&self) -> Vec<Tool> {
        vec![
            self.screen_input_tool(),
            self.screen_output_tool(),
            self.screen_content_tool(),
            self.check_safe_tool(),
            self.redact_content_tool(),
            self.get_config_tool(),
            self.proxy_status_tool(),
            self.proxy_configure_tool(),
        ]
    }

    /// Execute a tool by name
    pub async fn execute(&self, name: &str, args: HashMap<String, Value>) -> CallToolResult {
        match name {
            "screen_input" => self.screen_input(args).await,
            "screen_output" => self.screen_output(args).await,
            "screen_content" => self.screen_content(args).await,
            "check_safe" => self.check_safe(args).await,
            "redact_content" => self.redact_content(args).await,
            "get_config" => self.get_config(args).await,
            "proxy_status" => self.proxy_status(args).await,
            "proxy_configure" => self.proxy_configure(args).await,
            _ => CallToolResult::error(format!("Unknown tool: {}", name)),
        }
    }

    // Tool definitions

    fn screen_input_tool(&self) -> Tool {
        Tool {
            name: "screen_input".to_string(),
            description: Some(
                "Screen input content for injection attacks (SQL, command, prompt injection)"
                    .to_string(),
            ),
            input_schema: InputSchema::object()
                .with_required("content", PropertySchema::string("Content to screen")),
        }
    }

    fn screen_output_tool(&self) -> Tool {
        Tool {
            name: "screen_output".to_string(),
            description: Some(
                "Screen output content for PII and secrets before sending to user".to_string(),
            ),
            input_schema: InputSchema::object()
                .with_required("content", PropertySchema::string("Content to screen"))
                .with_property(
                    "redact",
                    PropertySchema::boolean("Automatically redact sensitive content"),
                ),
        }
    }

    fn screen_content_tool(&self) -> Tool {
        Tool {
            name: "screen_content".to_string(),
            description: Some("Screen content with full analysis (all detectors)".to_string()),
            input_schema: InputSchema::object()
                .with_required("content", PropertySchema::string("Content to screen"))
                .with_required(
                    "direction",
                    PropertySchema::string("Screening direction")
                        .with_enum(vec!["input", "output"]),
                ),
        }
    }

    fn check_safe_tool(&self) -> Tool {
        Tool {
            name: "check_safe".to_string(),
            description: Some("Quick check if content is safe (returns boolean)".to_string()),
            input_schema: InputSchema::object()
                .with_required("content", PropertySchema::string("Content to check"))
                .with_property(
                    "direction",
                    PropertySchema::string("Check direction (input/output)")
                        .with_enum(vec!["input", "output", "both"]),
                ),
        }
    }

    fn redact_content_tool(&self) -> Tool {
        Tool {
            name: "redact_content".to_string(),
            description: Some(
                "Redact sensitive information from content (PII, secrets)".to_string(),
            ),
            input_schema: InputSchema::object()
                .with_required("content", PropertySchema::string("Content to redact")),
        }
    }

    fn get_config_tool(&self) -> Tool {
        Tool {
            name: "get_config".to_string(),
            description: Some("Get current screening configuration".to_string()),
            input_schema: InputSchema::object(),
        }
    }

    fn proxy_status_tool(&self) -> Tool {
        Tool {
            name: "proxy_status".to_string(),
            description: Some(
                "Report wrap/proxy child process health and configuration".to_string(),
            ),
            input_schema: InputSchema::object(),
        }
    }

    fn proxy_configure_tool(&self) -> Tool {
        Tool {
            name: "proxy_configure".to_string(),
            description: Some(
                "Configure allowlisted wrap child command (requires admin_token)".to_string(),
            ),
            input_schema: InputSchema::object()
                .with_required("admin_token", PropertySchema::string("Admin bearer token"))
                .with_required("command", PropertySchema::string("Child MCP binary path"))
                .with_property(
                    "args",
                    PropertySchema::string("JSON array of argv strings for the child"),
                )
                .with_property(
                    "disable",
                    PropertySchema::boolean("Set true to disable wrap mode"),
                ),
        }
    }

    // Tool implementations

    async fn screen_input(&self, args: HashMap<String, Value>) -> CallToolResult {
        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter: content"),
        };

        match self.input_screener.screen(content) {
            Ok(result) => CallToolResult::json(json!({
                "verdict": format!("{:?}", result.result.verdict),
                "is_safe": result.result.is_allowed(),
                "was_modified": result.was_modified,
                "findings_count": result.result.findings.len(),
                "findings": result.result.findings.iter().map(|f| json!({
                    "type": f.finding_type,
                    "severity": format!("{:?}", f.severity),
                    "description": f.description,
                    "confidence": f.confidence
                })).collect::<Vec<_>>(),
                "risk_score": result.result.risk_score,
                "processing_time_ms": result.result.processing_time_ms
            })),
            Err(e) => CallToolResult::json(json!({
                "verdict": "Blocked",
                "is_safe": false,
                "error": e.to_string(),
                "blocked_reason": format!("{:?}", e)
            })),
        }
    }

    async fn screen_output(&self, args: HashMap<String, Value>) -> CallToolResult {
        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter: content"),
        };

        let redact = args.get("redact").and_then(|v| v.as_bool()).unwrap_or(true);

        match self.output_screener.screen(content) {
            Ok(result) => {
                let mut response = json!({
                    "verdict": format!("{:?}", result.result.verdict),
                    "is_safe": result.result.is_allowed(),
                    "was_modified": result.was_modified,
                    "findings_count": result.result.findings.len(),
                    "findings": result.result.findings.iter().map(|f| json!({
                        "type": f.finding_type,
                        "severity": format!("{:?}", f.severity),
                        "description": f.description,
                        "confidence": f.confidence
                    })).collect::<Vec<_>>(),
                    "risk_score": result.result.risk_score,
                    "processing_time_ms": result.result.processing_time_ms
                });

                if redact && result.was_modified {
                    response["redacted_content"] = json!(result.processed);
                }

                CallToolResult::json(response)
            }
            Err(e) => CallToolResult::json(json!({
                "verdict": "Blocked",
                "is_safe": false,
                "error": e.to_string()
            })),
        }
    }

    async fn screen_content(&self, args: HashMap<String, Value>) -> CallToolResult {
        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter: content"),
        };

        let direction = match args.get("direction").and_then(|v| v.as_str()) {
            Some("input") => ScreeningDirection::Input,
            Some("output") => ScreeningDirection::Output,
            _ => return CallToolResult::error("Invalid direction: must be 'input' or 'output'"),
        };

        match self.pipeline.screen(content, direction) {
            Ok(result) => CallToolResult::json(json!({
                "request_id": result.request_id,
                "direction": format!("{:?}", result.direction),
                "verdict": format!("{:?}", result.verdict),
                "is_allowed": result.is_allowed(),
                "risk_score": result.risk_score,
                "content_size": result.content_size,
                "content_hash": result.content_hash,
                "findings": result.findings.iter().map(|f| json!({
                    "type": f.finding_type,
                    "severity": format!("{:?}", f.severity),
                    "description": f.description,
                    "matched": f.matched,
                    "start": f.start,
                    "end": f.end,
                    "confidence": f.confidence,
                    "action": format!("{:?}", f.action)
                })).collect::<Vec<_>>(),
                "redacted_content": result.redacted_content,
                "processing_time_ms": result.processing_time_ms,
                "timestamp": result.timestamp.to_rfc3339()
            })),
            Err(e) => CallToolResult::error(format!("Screening failed: {}", e)),
        }
    }

    async fn check_safe(&self, args: HashMap<String, Value>) -> CallToolResult {
        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter: content"),
        };

        let direction = args
            .get("direction")
            .and_then(|v| v.as_str())
            .unwrap_or("both");

        let (input_safe, output_safe) = match direction {
            "input" => (self.input_screener.is_safe(content), true),
            "output" => (true, self.output_screener.is_safe(content)),
            _ => (
                self.input_screener.is_safe(content),
                self.output_screener.is_safe(content),
            ),
        };

        CallToolResult::json(json!({
            "is_safe": input_safe && output_safe,
            "input_safe": input_safe,
            "output_safe": output_safe,
            "direction_checked": direction
        }))
    }

    async fn redact_content(&self, args: HashMap<String, Value>) -> CallToolResult {
        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter: content"),
        };

        match self.output_screener.screen_and_redact(content) {
            Ok(redacted) => {
                let was_modified = redacted != content;
                CallToolResult::json(json!({
                    "success": true,
                    "redacted_content": redacted,
                    "was_modified": was_modified,
                    "original_length": content.len(),
                    "redacted_length": redacted.len()
                }))
            }
            Err(e) => CallToolResult::error(format!("Redaction failed: {}", e)),
        }
    }

    async fn get_config(&self, _args: HashMap<String, Value>) -> CallToolResult {
        let config = self.pipeline.config();
        CallToolResult::json(json!({
            "enable_pii": config.enable_pii,
            "enable_secrets": config.enable_secrets,
            "enable_injection": config.enable_injection,
            "min_severity": format!("{:?}", config.min_severity),
            "block_on_high": config.block_on_high,
            "parallel_threshold": config.parallel_threshold,
            "max_content_size": config.max_content_size,
            "timeout_ms": config.timeout_ms
        }))
    }

    async fn proxy_status(&self, _args: HashMap<String, Value>) -> CallToolResult {
        let Some(wrap) = &self.wrap else {
            return CallToolResult::json(json!({ "wrap_enabled": false }));
        };
        CallToolResult::json(wrap.status().await)
    }

    async fn proxy_configure(&self, args: HashMap<String, Value>) -> CallToolResult {
        let Some(wrap) = &self.wrap else {
            return CallToolResult::error("Wrap controller not available");
        };

        let admin_token = match args.get("admin_token").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return CallToolResult::error("Missing admin_token"),
        };
        let expected = std::env::var("SECURITY_MCP_ADMIN_TOKEN").ok().or_else(|| {
            std::env::var("SECURITY_MCP_TOKENS")
                .ok()
                .and_then(|s| s.split(',').next().map(|t| t.trim().to_string()))
        });
        if expected.as_deref() != Some(admin_token) {
            return CallToolResult::error("Invalid admin_token");
        }

        if args.get("disable").and_then(|v| v.as_bool()) == Some(true) {
            match wrap.disable().await {
                Ok(()) => return CallToolResult::json(json!({ "wrap_enabled": false })),
                Err(e) => return CallToolResult::error(e.to_string()),
            }
        }

        let command = match args.get("command").and_then(|v| v.as_str()) {
            Some(c) => c.to_string(),
            None => return CallToolResult::error("Missing command"),
        };
        let child_args = match args.get("args") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>(),
            Some(Value::String(s)) => serde_json::from_str::<Vec<String>>(s).unwrap_or_default(),
            _ => Vec::new(),
        };

        match wrap.configure(command, child_args).await {
            Ok(()) => CallToolResult::json(wrap.status().await),
            Err(e) => CallToolResult::error(e.to_string()),
        }
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_screen_input_tool() {
        let registry = ToolRegistry::new();
        let mut args = HashMap::new();
        args.insert("content".to_string(), json!("Hello, world!"));

        let result = registry.execute("screen_input", args).await;
        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn test_check_safe_tool() {
        let registry = ToolRegistry::new();
        let mut args = HashMap::new();
        args.insert("content".to_string(), json!("Safe content"));
        args.insert("direction".to_string(), json!("both"));

        let result = registry.execute("check_safe", args).await;
        assert!(!result.is_error);
    }
}
