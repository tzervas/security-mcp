//! High-level screener interfaces
//!
//! Provides InputScreener and OutputScreener for convenient security screening.

use serde::{Deserialize, Serialize};

use crate::error::{SecurityError, SecurityResult};
use crate::pipeline::{ScreeningConfig, ScreeningDirection, ScreeningPipeline, ScreeningResult, Verdict};

/// Security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreeningPolicy {
    /// Allow content with warnings
    pub allow_warnings: bool,
    /// Allow redacted content through
    pub allow_redacted: bool,
    /// Log all screenings
    pub log_all: bool,
    /// Custom blocked message
    pub blocked_message: String,
}

impl Default for ScreeningPolicy {
    fn default() -> Self {
        Self {
            allow_warnings: true,
            allow_redacted: true,
            log_all: false,
            blocked_message: "Content blocked due to security policy".to_string(),
        }
    }
}

/// Screened content result
#[derive(Debug, Clone)]
pub struct ScreenedContent {
    /// Original content
    pub original: String,
    /// Processed content (may be redacted)
    pub processed: String,
    /// Screening result
    pub result: ScreeningResult,
    /// Whether content was modified
    pub was_modified: bool,
}

impl ScreenedContent {
    /// Get the safe content (processed if redacted, original if safe)
    pub fn safe_content(&self) -> &str {
        &self.processed
    }

    /// Check if content was blocked
    pub fn was_blocked(&self) -> bool {
        self.result.verdict == Verdict::Blocked
    }
}

/// Input content screener (injection detection)
pub struct InputScreener {
    pipeline: ScreeningPipeline,
    policy: ScreeningPolicy,
}

impl Default for InputScreener {
    fn default() -> Self {
        Self::new()
    }
}

impl InputScreener {
    /// Create a new input screener
    pub fn new() -> Self {
        Self {
            pipeline: ScreeningPipeline::for_input(),
            policy: ScreeningPolicy::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: ScreeningConfig, policy: ScreeningPolicy) -> Self {
        Self {
            pipeline: ScreeningPipeline::new(config),
            policy,
        }
    }

    /// Screen input content
    pub fn screen(&self, content: &str) -> SecurityResult<ScreenedContent> {
        let result = self.pipeline.screen(content, ScreeningDirection::Input)?;

        match result.verdict {
            Verdict::Blocked => {
                Err(SecurityError::InjectionDetected(self.policy.blocked_message.clone()))
            }
            Verdict::Warning if !self.policy.allow_warnings => {
                Err(SecurityError::Blocked("Content flagged with warnings".to_string()))
            }
            _ => Ok(ScreenedContent {
                original: content.to_string(),
                processed: content.to_string(),
                was_modified: false,
                result,
            }),
        }
    }

    /// Quick check if content is safe
    pub fn is_safe(&self, content: &str) -> bool {
        self.screen(content).is_ok()
    }

    /// Get the policy
    pub fn policy(&self) -> &ScreeningPolicy {
        &self.policy
    }
}

/// Output content screener (PII and secrets detection)
pub struct OutputScreener {
    pipeline: ScreeningPipeline,
    policy: ScreeningPolicy,
}

impl Default for OutputScreener {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputScreener {
    /// Create a new output screener
    pub fn new() -> Self {
        Self {
            pipeline: ScreeningPipeline::for_output(),
            policy: ScreeningPolicy::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: ScreeningConfig, policy: ScreeningPolicy) -> Self {
        Self {
            pipeline: ScreeningPipeline::new(config),
            policy,
        }
    }

    /// Screen output content
    pub fn screen(&self, content: &str) -> SecurityResult<ScreenedContent> {
        let result = self.pipeline.screen(content, ScreeningDirection::Output)?;

        match result.verdict {
            Verdict::Blocked => {
                Err(SecurityError::Blocked(self.policy.blocked_message.clone()))
            }
            Verdict::Redact => {
                if self.policy.allow_redacted {
                    let processed = result.redacted_content.clone().unwrap_or_else(|| content.to_string());
                    Ok(ScreenedContent {
                        original: content.to_string(),
                        processed,
                        was_modified: true,
                        result,
                    })
                } else {
                    Err(SecurityError::PiiDetected("Content requires redaction but redaction is disabled".to_string()))
                }
            }
            Verdict::Warning if !self.policy.allow_warnings => {
                Err(SecurityError::Blocked("Content flagged with warnings".to_string()))
            }
            _ => Ok(ScreenedContent {
                original: content.to_string(),
                processed: content.to_string(),
                was_modified: false,
                result,
            }),
        }
    }

    /// Screen and automatically redact sensitive content
    pub fn screen_and_redact(&self, content: &str) -> SecurityResult<String> {
        let result = self.screen(content)?;
        Ok(result.processed)
    }

    /// Quick check if content is safe for output
    pub fn is_safe(&self, content: &str) -> bool {
        self.screen(content).map(|r| !r.was_modified).unwrap_or(false)
    }

    /// Get the policy
    pub fn policy(&self) -> &ScreeningPolicy {
        &self.policy
    }
}

/// Combined screener for bidirectional content filtering
pub struct BidirectionalScreener {
    input: InputScreener,
    output: OutputScreener,
}

impl Default for BidirectionalScreener {
    fn default() -> Self {
        Self::new()
    }
}

impl BidirectionalScreener {
    /// Create a new bidirectional screener
    pub fn new() -> Self {
        Self {
            input: InputScreener::new(),
            output: OutputScreener::new(),
        }
    }

    /// Create with custom policies
    pub fn with_policies(input_policy: ScreeningPolicy, output_policy: ScreeningPolicy) -> Self {
        Self {
            input: InputScreener::with_config(ScreeningConfig::default(), input_policy),
            output: OutputScreener::with_config(ScreeningConfig::default(), output_policy),
        }
    }

    /// Screen input
    pub fn screen_input(&self, content: &str) -> SecurityResult<ScreenedContent> {
        self.input.screen(content)
    }

    /// Screen output
    pub fn screen_output(&self, content: &str) -> SecurityResult<ScreenedContent> {
        self.output.screen(content)
    }

    /// Get input screener
    pub fn input(&self) -> &InputScreener {
        &self.input
    }

    /// Get output screener
    pub fn output(&self) -> &OutputScreener {
        &self.output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_screener_safe() {
        let screener = InputScreener::new();
        let result = screener.screen("Hello, how can I help you?").unwrap();
        assert!(!result.was_blocked());
    }

    #[test]
    fn test_input_screener_injection() {
        let screener = InputScreener::new();
        let result = screener.screen("'; DROP TABLE users;--");
        assert!(result.is_err());
    }

    #[test]
    fn test_output_screener_safe() {
        let screener = OutputScreener::new();
        let result = screener.screen("The weather is nice today.").unwrap();
        assert!(!result.was_modified);
    }

    #[test]
    fn test_output_screener_pii() {
        let screener = OutputScreener::new();
        let result = screener.screen("Contact: user@example.com").unwrap();
        // Should be redacted (not blocked)
        assert!(result.was_modified || !result.result.findings.is_empty());
    }

    #[test]
    fn test_bidirectional() {
        let screener = BidirectionalScreener::new();
        
        // Safe input
        assert!(screener.screen_input("normal query").is_ok());
        
        // Safe output
        assert!(screener.screen_output("normal response").is_ok());
    }
}
