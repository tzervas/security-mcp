use axum::extract::State;
use axum::response::sse::{Event, Sse};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub severity: String,
    pub description: String,
    pub request_id: Option<String>,
    pub user_id: Option<String>,
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

pub async fn handle_sse(
    State(state): State<Arc<super::server::ServerState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = state.audit.subscribe().map(|event| {
        Ok(Event::default().data(serde_json::to_string(&event.unwrap()).unwrap()))
    });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(30))
            .text("keep-alive"),
    )
}