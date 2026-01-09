use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc::{self, Receiver, Sender};
use serde_json::Value;
use std::process::Stdio;

pub struct WebpuppetSubprocess {
    child: Child,
    stdin: ChildStdin,
    stdout_rx: Receiver<String>,
    _stdout_tx: Sender<String>,
}

impl WebpuppetSubprocess {
    pub async fn spawn(webpuppet_path: &str, args: &[&str]) -> Result<Self, std::io::Error> {
        let mut child = Command::new(webpuppet_path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

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

    pub async fn send_request(&mut self, request: &Value) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(request)? + "\n";
        self.stdin.write_all(json.as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    pub async fn receive_response(&mut self) -> Option<String> {
        self.stdout_rx.recv().await
    }

    pub async fn is_alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    pub async fn kill(&mut self) -> Result<(), std::io::Error> {
        self.child.kill().await
    }
}