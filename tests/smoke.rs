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
