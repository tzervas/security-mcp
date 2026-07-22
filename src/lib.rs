//! security-mcp
//!
//! MCP server for security screening of inputs and outputs.
//!
//! Provides detection and filtering for:
//! - **Output screening**: PII detection, secrets scanning
//! - **Input screening**: Injection detection, malicious content filtering
//!
//! # Architecture
//!
//! The screening pipeline processes content in stages:
//! 1. Quick pattern matching (regex-based)
//! 2. Entropy analysis (for secrets detection)
//! 3. Structural analysis (for injection patterns)
//! 4. Contextual screening (domain-specific rules)

pub mod audit;
pub mod detectors;
pub mod error;
pub mod patterns;
pub mod pipeline;
pub mod protocol;
pub mod screeners;
pub mod server;
pub mod subprocess;
pub mod tools;
pub mod wrap;

pub use detectors::{Detector, DetectorResult, Finding, Severity};
pub use error::{SecurityError, SecurityResult};
pub use pipeline::{ScreeningConfig, ScreeningPipeline, ScreeningResult};
pub use screeners::{InputScreener, OutputScreener, ScreeningPolicy};
