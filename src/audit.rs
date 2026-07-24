//! Optional SSE audit stream for wrap/proxy events.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub severity: String,
    pub description: String,
    pub request_id: Option<String>,
    pub details: serde_json::Value,
}

pub struct AuditLogger {
    tx: broadcast::Sender<AuditEvent>,
}

impl AuditLogger {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self { tx }
    }

    pub fn log(&self, event: AuditEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> BroadcastStream<AuditEvent> {
        BroadcastStream::new(self.tx.subscribe())
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}
