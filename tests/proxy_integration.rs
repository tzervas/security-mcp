//! Integration tests for wrap/proxy mode of security-mcp.

use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[tokio::test]
async fn test_mcp_proxy_stdio_wrap() {
    // Dynamically locate the security-mcp executable relative to current_exe
    let mut exe_path = std::env::current_exe().unwrap();
    exe_path.pop(); // Remove test filename
    if exe_path.ends_with("deps") {
        exe_path.pop(); // Remove deps/
    }
    exe_path.push("security-mcp");

    // Start security-mcp wrapping itself running in stdio mode
    let mut child = Command::new(&exe_path)
        .args([
            "--wrap",
            exe_path.to_str().unwrap(),
            "--wrap-args",
            "--stdio",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start security-mcp in wrap/proxy mode");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout);

    // 1. Send tools/list request to the proxy
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let req_str = list_req.to_string() + "\n";
    stdin.write_all(req_str.as_bytes()).await.unwrap();
    stdin.flush().await.unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(!line.is_empty(), "Response should not be empty");

    let list_resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(list_resp["id"].as_i64(), Some(1));
    assert!(
        list_resp["result"]["tools"].is_array(),
        "Expected list of tools from wrapped server"
    );

    // 2. Send tools/call request with SAFE content (should succeed)
    let call_req_safe = serde_json::json!({
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
    let req_str = call_req_safe.to_string() + "\n";
    stdin.write_all(req_str.as_bytes()).await.unwrap();
    stdin.flush().await.unwrap();

    line.clear();
    reader.read_line(&mut line).await.unwrap();
    let call_resp_safe: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(call_resp_safe["id"].as_i64(), Some(2));
    let content_text = call_resp_safe["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let content_json: serde_json::Value = serde_json::from_str(content_text).unwrap();
    assert_eq!(content_json["is_safe"].as_bool(), Some(true));

    // 3. Send tools/call request with INJECTION content (should be blocked at request stage by proxy)
    let call_req_malicious = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "screen_input",
            "arguments": {
                "content": "'; DROP TABLE users;--"
            }
        }
    });
    let req_str = call_req_malicious.to_string() + "\n";
    stdin.write_all(req_str.as_bytes()).await.unwrap();
    stdin.flush().await.unwrap();

    line.clear();
    reader.read_line(&mut line).await.unwrap();
    let call_resp_malicious: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(call_resp_malicious["id"].as_i64(), Some(3));
    assert_eq!(
        call_resp_malicious["result"]["is_error"].as_bool(),
        Some(true)
    );
    let err_text = call_resp_malicious["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(
        err_text.contains("Content blocked"),
        "Expected a blocked message, got: {}",
        err_text
    );

    // Kill the subprocess
    let _ = child.kill().await;
}
