//! Black-box smoke tests for the public screening API.
//!
//! These exercise `security_mcp` the way an external consumer would (via the
//! crate's public `lib.rs` surface, not `#[cfg(test)]` internals) to confirm
//! the two properties this tool exists to guarantee at a minimum:
//! a known secret/PII string is flagged, and an unremarkable benign string is
//! not. Detector-internal edge cases live in each module's own `mod tests`.

use security_mcp::pipeline::ScreeningDirection;
use security_mcp::{ScreeningConfig, ScreeningPipeline};

#[test]
fn known_secret_is_flagged() {
    let pipeline = ScreeningPipeline::with_defaults();
    let content = "aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    let result = pipeline
        .screen(content, ScreeningDirection::Output)
        .expect("screening should succeed");

    assert!(
        !result.findings.is_empty(),
        "expected a known-secret-shaped string to produce at least one finding"
    );
}

#[test]
fn benign_string_is_not_flagged() {
    let pipeline = ScreeningPipeline::with_defaults();
    let content = "The quick brown fox jumps over the lazy dog near the riverbank.";

    let result = pipeline
        .screen(content, ScreeningDirection::Output)
        .expect("screening should succeed");

    assert!(
        result.findings.is_empty(),
        "expected an unremarkable benign string to produce no findings, got: {:?}",
        result.findings
    );
}

#[test]
fn screening_config_defaults_enable_all_detectors() {
    // Guards against a silent regression that would quietly disable a
    // detector class by default (this tool's core promise is never-silent
    // screening, not a specific tuning).
    let config = ScreeningConfig::default();
    assert!(config.enable_pii);
    assert!(config.enable_secrets);
    assert!(config.enable_injection);
}

#[tokio::test]
async fn test_mcp_stdio_e2e() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    // Start security-mcp as a subprocess in stdio mode
    let mut child = Command::new("cargo")
        .args(["run", "-q", "-p", "security-mcp", "--", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start security-mcp via cargo run");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout);

    // 1. Send tools/list request
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let req_str = list_req.to_string() + "\n";
    stdin.write_all(req_str.as_bytes()).await.unwrap();
    stdin.flush().await.unwrap();

    // Read response
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(!line.is_empty(), "Response should not be empty");

    let list_resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(list_resp["id"].as_i64(), Some(1));
    assert!(
        list_resp["result"]["tools"].is_array(),
        "Expected list of tools"
    );

    // 2. Send tools/call request for screen_input with safe content
    let call_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "screen_input",
            "arguments": {
                "content": "This is benign safe content"
            }
        }
    });
    let req_str = call_req.to_string() + "\n";
    stdin.write_all(req_str.as_bytes()).await.unwrap();
    stdin.flush().await.unwrap();

    line.clear();
    reader.read_line(&mut line).await.unwrap();
    let call_resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(call_resp["id"].as_i64(), Some(2));

    // Parse the inner text from tool result content
    let content_text = call_resp["result"]["content"][0]["text"].as_str().unwrap();
    let content_json: serde_json::Value = serde_json::from_str(content_text).unwrap();
    assert_eq!(content_json["is_safe"].as_bool(), Some(true));

    // Kill the subprocess
    let _ = child.kill().await;
}
