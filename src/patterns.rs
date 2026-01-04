//! Pattern definitions for security screening
//!
//! Contains regex patterns for detecting PII, secrets, and injection attacks.

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // ==========================================================================
    // PII PATTERNS (Output Screening)
    // ==========================================================================
    
    /// Email addresses
    pub static ref EMAIL: Regex = Regex::new(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ).unwrap();
    
    /// US Phone numbers (various formats)
    pub static ref PHONE_US: Regex = Regex::new(
        r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
    ).unwrap();
    
    /// US Social Security Numbers
    pub static ref SSN: Regex = Regex::new(
        r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"
    ).unwrap();
    
    /// Credit card numbers (Visa, MC, Amex, Discover)
    pub static ref CREDIT_CARD: Regex = Regex::new(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
    ).unwrap();
    
    /// IP addresses (IPv4)
    pub static ref IP_ADDRESS: Regex = Regex::new(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ).unwrap();
    
    /// IPv6 addresses
    pub static ref IPV6_ADDRESS: Regex = Regex::new(
        r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}"
    ).unwrap();
    
    /// Physical addresses (US format)
    pub static ref STREET_ADDRESS: Regex = Regex::new(
        r"\b\d{1,5}\s+[\w\s]{1,50}(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|court|ct|circle|cir)\.?\b"
    ).unwrap();
    
    /// Names (common patterns - limited accuracy)
    pub static ref PERSON_NAME: Regex = Regex::new(
        r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b"
    ).unwrap();

    // ==========================================================================
    // SECRET PATTERNS (Output Screening)
    // ==========================================================================
    
    /// AWS Access Key ID
    pub static ref AWS_ACCESS_KEY: Regex = Regex::new(
        r#"(?i)(?:aws|amazon)[_\-\s]?(?:access)[_\-\s]?(?:key)[_\-\s]?(?:id)?[=:\s]+['"]?([A-Z0-9]{20})['"]?"#
    ).unwrap();
    
    /// AWS Secret Access Key
    pub static ref AWS_SECRET_KEY: Regex = Regex::new(
        r#"(?i)(?:aws|amazon)[_\-\s]?(?:secret)[_\-\s]?(?:access)?[_\-\s]?(?:key)?[=:\s]+['"]?([A-Za-z0-9/+=]{40})['"]?"#
    ).unwrap();
    
    /// Generic API Key patterns
    pub static ref API_KEY: Regex = Regex::new(
        r#"(?i)(?:api[_\-\s]?key|apikey|api_secret|api_token)[=:\s]+['"]?([a-zA-Z0-9_\-]{20,})['"]?"#
    ).unwrap();
    
    /// GitHub Token
    pub static ref GITHUB_TOKEN: Regex = Regex::new(
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"
    ).unwrap();
    
    /// Generic Bearer Token
    pub static ref BEARER_TOKEN: Regex = Regex::new(
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+"
    ).unwrap();
    
    /// Private Key headers
    pub static ref PRIVATE_KEY: Regex = Regex::new(
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
    ).unwrap();
    
    /// Password in assignment
    pub static ref PASSWORD_ASSIGN: Regex = Regex::new(
        r#"(?i)(?:password|passwd|pwd|secret)[=:\s]+['"]?([^\s'"]{8,})['"]?"#
    ).unwrap();
    
    /// Database connection strings
    pub static ref DB_CONNECTION: Regex = Regex::new(
        r"(?i)(?:mongodb|postgres|mysql|redis)://[^\s]+"
    ).unwrap();
    
    /// Slack tokens
    pub static ref SLACK_TOKEN: Regex = Regex::new(
        r"xox[baprs]-[0-9a-zA-Z]{10,}"
    ).unwrap();
    
    /// Generic high entropy strings (potential secrets)
    pub static ref HIGH_ENTROPY: Regex = Regex::new(
        r"[a-zA-Z0-9/+=_\-]{32,}"
    ).unwrap();

    // ==========================================================================
    // INJECTION PATTERNS (Input Screening)
    // ==========================================================================
    
    /// SQL Injection patterns
    pub static ref SQL_INJECTION: Regex = Regex::new(
        r#"(?i)(?:'\s*(?:or|and)\s+['\d]|union\s+(?:all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(?:table|database)|;[\s\-]*(?:drop|delete|truncate|alter))"#
    ).unwrap();
    
    /// Command injection patterns
    pub static ref CMD_INJECTION: Regex = Regex::new(
        r"(?:;\s*(?:ls|cat|rm|wget|curl|bash|sh|python|perl|nc|netcat)|`[^`]+`|\$\([^)]+\)|\|\s*(?:bash|sh|python))"
    ).unwrap();
    
    /// Path traversal patterns
    pub static ref PATH_TRAVERSAL: Regex = Regex::new(
        r"(?:\.\.[\\/]|%2e%2e[\\/]|%252e%252e[\\/])"
    ).unwrap();
    
    /// XSS patterns
    pub static ref XSS: Regex = Regex::new(
        r"(?i)(?:<script[^>]*>|javascript:|on(?:load|error|click|mouse|key|focus|blur|change|submit)\s*=|<iframe|<object|<embed)"
    ).unwrap();
    
    /// LDAP injection
    pub static ref LDAP_INJECTION: Regex = Regex::new(
        r"[*)(|&!]"
    ).unwrap();
    
    /// XML/XXE injection
    pub static ref XXE_INJECTION: Regex = Regex::new(
        r#"(?i)(?:<!DOCTYPE[^>]*\[|<!ENTITY|SYSTEM\s+['"](?:file|http|ftp)://)"#
    ).unwrap();
    
    /// Template injection (SSTI)
    pub static ref TEMPLATE_INJECTION: Regex = Regex::new(
        r"(?:\{\{.*\}\}|\{%.*%\}|\$\{.*\}|<%.*%>|#\{.*\})"
    ).unwrap();
    
    /// Prompt injection patterns
    pub static ref PROMPT_INJECTION: Regex = Regex::new(
        r"(?i)(?:ignore\s+(?:previous|above|all)\s+instructions?|disregard\s+(?:previous|above)|forget\s+(?:everything|previous)|new\s+instruction|system\s*:\s*you\s+are|act\s+as|pretend\s+you\s+are|jailbreak|DAN\s+mode)"
    ).unwrap();
    
    /// Control characters
    pub static ref CONTROL_CHARS: Regex = Regex::new(
        r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
    ).unwrap();
}

/// PII pattern collection
pub struct PiiPatterns;

impl PiiPatterns {
    /// Get all PII patterns with their names
    pub fn all() -> Vec<(&'static str, &'static Regex)> {
        vec![
            ("email", &*EMAIL),
            ("phone_us", &*PHONE_US),
            ("ssn", &*SSN),
            ("credit_card", &*CREDIT_CARD),
            ("ip_address", &*IP_ADDRESS),
            ("ipv6_address", &*IPV6_ADDRESS),
            ("street_address", &*STREET_ADDRESS),
            ("person_name", &*PERSON_NAME),
        ]
    }
}

/// Secret pattern collection
pub struct SecretPatterns;

impl SecretPatterns {
    /// Get all secret patterns with their names
    pub fn all() -> Vec<(&'static str, &'static Regex)> {
        vec![
            ("aws_access_key", &*AWS_ACCESS_KEY),
            ("aws_secret_key", &*AWS_SECRET_KEY),
            ("api_key", &*API_KEY),
            ("github_token", &*GITHUB_TOKEN),
            ("bearer_token", &*BEARER_TOKEN),
            ("private_key", &*PRIVATE_KEY),
            ("password", &*PASSWORD_ASSIGN),
            ("db_connection", &*DB_CONNECTION),
            ("slack_token", &*SLACK_TOKEN),
        ]
    }
}

/// Injection pattern collection
pub struct InjectionPatterns;

impl InjectionPatterns {
    /// Get all injection patterns with their names
    pub fn all() -> Vec<(&'static str, &'static Regex)> {
        vec![
            ("sql_injection", &*SQL_INJECTION),
            ("cmd_injection", &*CMD_INJECTION),
            ("path_traversal", &*PATH_TRAVERSAL),
            ("xss", &*XSS),
            ("ldap_injection", &*LDAP_INJECTION),
            ("xxe_injection", &*XXE_INJECTION),
            ("template_injection", &*TEMPLATE_INJECTION),
            ("prompt_injection", &*PROMPT_INJECTION),
            ("control_chars", &*CONTROL_CHARS),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_pattern() {
        assert!(EMAIL.is_match("user@example.com"));
        assert!(EMAIL.is_match("user.name+tag@subdomain.example.co.uk"));
        assert!(!EMAIL.is_match("not an email"));
    }

    #[test]
    fn test_ssn_pattern() {
        assert!(SSN.is_match("123-45-6789"));
        assert!(SSN.is_match("123 45 6789"));
        assert!(SSN.is_match("123456789"));
    }

    #[test]
    fn test_github_token() {
        assert!(GITHUB_TOKEN.is_match("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(GITHUB_TOKEN.is_match("gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    }

    #[test]
    fn test_sql_injection() {
        assert!(SQL_INJECTION.is_match("' OR '1'='1"));
        assert!(SQL_INJECTION.is_match("UNION SELECT * FROM users"));
        assert!(SQL_INJECTION.is_match("; DROP TABLE users;"));
    }

    #[test]
    fn test_prompt_injection() {
        assert!(PROMPT_INJECTION.is_match("Ignore previous instructions"));
        assert!(PROMPT_INJECTION.is_match("Disregard all above"));
        assert!(PROMPT_INJECTION.is_match("Act as a different AI"));
    }
}
