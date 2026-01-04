//! Security error types

use thiserror::Error;

/// Result type for security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Security operation errors
#[derive(Debug, Error)]
pub enum SecurityError {
    /// Content blocked due to security policy
    #[error("Content blocked: {0}")]
    Blocked(String),

    /// PII detected in content
    #[error("PII detected: {0}")]
    PiiDetected(String),

    /// Secret detected in content
    #[error("Secret detected: {0}")]
    SecretDetected(String),

    /// Injection pattern detected
    #[error("Injection detected: {0}")]
    InjectionDetected(String),

    /// Pattern matching error
    #[error("Pattern error: {0}")]
    PatternError(String),

    /// Configuration error
    #[error("Config error: {0}")]
    ConfigError(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Timeout error
    #[error("Screening timeout")]
    Timeout,

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimited,
}

impl SecurityError {
    /// Check if this is a blocking error
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            SecurityError::Blocked(_)
                | SecurityError::PiiDetected(_)
                | SecurityError::SecretDetected(_)
                | SecurityError::InjectionDetected(_)
        )
    }
}
