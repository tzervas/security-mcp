//! Subprocess and proxy implementation for security screening

use serde_json::Value;
use std::collections::HashSet;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::error::{SecurityError, SecurityResult};
use crate::protocol::{CallToolResult, JsonRpcRequest, JsonRpcResponse, RequestId};
use crate::server::ServerConfig;
use crate::tools::ToolRegistry;

/// Collect strings recursively from a JSON value
fn collect_strings(value: &Value, strings: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            strings.push(s.clone());
        }
        Value::Array(arr) => {
            for v in arr {
                collect_strings(v, strings);
            }
        }
        Value::Object(obj) => {
            for v in obj.values() {
                collect_strings(v, strings);
            }
        }
        _ => {}
    }
}

/// Screen and modify response result
fn screen_and_modify_response_result(
    result: &mut Value,
    registry: &ToolRegistry,
) -> Result<bool, SecurityError> {
    if let Some(content_arr) = result.get_mut("content").and_then(|c| c.as_array_mut()) {
        let mut blocked = false;
        for item in content_arr {
            if let Some(text_val) = item.get_mut("text").and_then(|t| t.as_str()) {
                match registry.screen_output_sync(text_val) {
                    Ok(screened) => {
                        if screened.was_modified {
                            *item.get_mut("text").unwrap() = Value::String(screened.processed);
                        }
                    }
                    Err(e) => {
                        if e.is_blocking() {
                            blocked = true;
                            break;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
        }
        if blocked {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Bidirectional screening proxy over stdio
pub struct McpProxyTransport {
    registry: Arc<ToolRegistry>,
}

impl McpProxyTransport {
    /// Create a new proxy transport
    pub fn new(config: ServerConfig) -> Self {
        Self {
            registry: Arc::new(ToolRegistry::with_config(config.screening, config.policy)),
        }
    }

    /// Run the proxy transport by wrapping a child process
    pub async fn run(&self, command: &str, args: &[String]) -> SecurityResult<()> {
        tracing::info!(
            "Spawning child MCP process: {} with args {:?}",
            command,
            args
        );

        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(SecurityError::Io)?;

        let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
        let child_stdout = child.stdout.take().expect("Failed to open child stdout");

        let outstanding_tool_calls = Arc::new(Mutex::new(HashSet::<RequestId>::new()));

        // Channel to serialize all writes to parent stdout
        let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::channel::<String>(100);

        // Parent stdout writer task
        let parent_stdout_writer = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            while let Some(line) = stdout_rx.recv().await {
                if stdout.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                if stdout.write_all(b"\n").await.is_err() {
                    break;
                }
                if stdout.flush().await.is_err() {
                    break;
                }
            }
        });

        // Loop 1: Parent to Child (stdin -> child_stdin)
        let outstanding_tc_stdin = outstanding_tool_calls.clone();
        let registry_stdin = self.registry.clone();
        let stdout_tx_stdin = stdout_tx.clone();
        let parent_reader_task = tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut reader = BufReader::new(stdin);
            let mut line = String::new();

            while let Ok(bytes) = reader.read_line(&mut line).await {
                if bytes == 0 {
                    break;
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    line.clear();
                    continue;
                }

                if let Ok(request) = serde_json::from_str::<JsonRpcRequest>(trimmed) {
                    if request.method == "tools/call" {
                        let mut strings_to_screen = Vec::new();
                        if let Some(params) = &request.params {
                            if let Some(arguments) = params.get("arguments") {
                                collect_strings(arguments, &mut strings_to_screen);
                            }
                        }

                        let mut is_blocked = false;
                        let mut block_reason = String::new();
                        for s in strings_to_screen {
                            if let Err(e) = registry_stdin.screen_input_sync(&s) {
                                is_blocked = true;
                                block_reason = e.to_string();
                                break;
                            }
                        }

                        if is_blocked {
                            tracing::warn!("Blocked tool call request due to: {}", block_reason);
                            let response = JsonRpcResponse::success(
                                request.id.clone(),
                                serde_json::to_value(CallToolResult::error(format!(
                                    "Content blocked: {}",
                                    block_reason
                                )))
                                .unwrap(),
                            );
                            let _ = stdout_tx_stdin
                                .send(serde_json::to_string(&response).unwrap())
                                .await;
                            line.clear();
                            continue;
                        }

                        // Allowed: record outstanding tool call
                        let mut otc = outstanding_tc_stdin.lock().unwrap();
                        otc.insert(request.id.clone());
                    }
                }

                // Forward original request line to child
                if child_stdin.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                if child_stdin.flush().await.is_err() {
                    break;
                }
                line.clear();
            }
        });

        // Loop 2: Child to Parent (child_stdout -> stdout)
        let outstanding_tc_stdout = outstanding_tool_calls.clone();
        let registry_stdout = self.registry.clone();
        let stdout_tx_stdout = stdout_tx.clone();
        let child_reader_task = tokio::spawn(async move {
            let mut reader = BufReader::new(child_stdout);
            let mut line = String::new();

            while let Ok(bytes) = reader.read_line(&mut line).await {
                if bytes == 0 {
                    break;
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    line.clear();
                    continue;
                }

                let mut processed_line = None;

                if let Ok(mut response) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
                    let is_outstanding = {
                        let mut otc = outstanding_tc_stdout.lock().unwrap();
                        otc.remove(&response.id)
                    };

                    if is_outstanding {
                        if let Some(ref mut result) = response.result {
                            match screen_and_modify_response_result(result, &registry_stdout) {
                                Ok(true) => {
                                    // Successfully allowed and/or redacted
                                    processed_line =
                                        Some(serde_json::to_string(&response).unwrap());
                                }
                                Ok(false) => {
                                    // Blocked
                                    tracing::warn!("Blocked tool call response payload");
                                    let blocked_response = JsonRpcResponse::success(
                                        response.id.clone(),
                                        serde_json::to_value(CallToolResult::error(
                                            "Content blocked due to security policy",
                                        ))
                                        .unwrap(),
                                    );
                                    processed_line =
                                        Some(serde_json::to_string(&blocked_response).unwrap());
                                }
                                Err(e) => {
                                    // Error
                                    let error_response = JsonRpcResponse::success(
                                        response.id.clone(),
                                        serde_json::to_value(CallToolResult::error(format!(
                                            "Screening error: {}",
                                            e
                                        )))
                                        .unwrap(),
                                    );
                                    processed_line =
                                        Some(serde_json::to_string(&error_response).unwrap());
                                }
                            }
                        }
                    }
                }

                let final_line = processed_line.unwrap_or_else(|| trimmed.to_string());
                if stdout_tx_stdout.send(final_line).await.is_err() {
                    break;
                }
                line.clear();
            }
        });

        let parent_abort_handle = parent_reader_task.abort_handle();
        let child_abort_handle = child_reader_task.abort_handle();

        // Drop original sender so that the rx channel can close on exit
        drop(stdout_tx);

        // Wait for tasks or child process to finish
        tokio::select! {
            _ = parent_reader_task => {
                tracing::info!("Parent reader task finished (EOF on stdin)");
            }
            _ = child_reader_task => {
                tracing::info!("Child reader task finished (EOF on child stdout)");
            }
            status = child.wait() => {
                tracing::info!("Child process exited with status: {:?}", status);
            }
        }

        // Cleanup: abort reading tasks to ensure all stdout_tx clones are dropped
        parent_abort_handle.abort();
        child_abort_handle.abort();

        let _ = child.kill().await;
        let _ = parent_stdout_writer.await;

        Ok(())
    }
}
