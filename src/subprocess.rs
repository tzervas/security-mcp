//! Line-oriented JSON-RPC subprocess transport for wrapped MCP children.

use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc::{self, Receiver, Sender};

/// Managed stdio child that speaks newline-delimited JSON-RPC.
pub struct McpChildProcess {
    child: Child,
    stdin: ChildStdin,
    stdout_rx: Receiver<String>,
    _stdout_tx: Sender<String>,
}

impl McpChildProcess {
    /// Spawn a child MCP server process.
    pub async fn spawn(command: &str, args: &[&str]) -> Result<Self, std::io::Error> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");

        let (tx, rx) = mpsc::channel(100);
        let stdout_tx = tx.clone();

        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            while let Ok(bytes) = reader.read_line(&mut line).await {
                if bytes == 0 {
                    break;
                }
                if !line.trim().is_empty() {
                    let _ = stdout_tx.send(line.clone()).await;
                }
                line.clear();
            }
        });

        Ok(Self {
            child,
            stdin,
            stdout_rx: rx,
            _stdout_tx: tx,
        })
    }

    /// Send one JSON-RPC request line to the child.
    pub async fn send_request(&mut self, request: &Value) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(request)? + "\n";
        self.stdin.write_all(json.as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Receive the next response line from the child, if any.
    pub async fn receive_response(&mut self) -> Option<String> {
        self.stdout_rx.recv().await
    }

    /// Whether the child process is still running.
    pub async fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Terminate the child process.
    pub async fn kill(&mut self) -> Result<(), std::io::Error> {
        self.child.kill().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_echo_mock_roundtrip() {
        let mut child = McpChildProcess::spawn(
            "sh",
            &[
                "-c",
                "read -r line; printf '%s\\n' \"{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":1,\\\"result\\\":{\\\"ok\\\":true}}\"",
            ],
        )
        .await
        .expect("spawn mock child");

        child
            .send_request(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "ping"
            }))
            .await
            .expect("send");

        let line = child.receive_response().await.expect("response line");
        let value: Value = serde_json::from_str(&line).expect("json");
        assert_eq!(value["result"]["ok"], true);
    }
}
