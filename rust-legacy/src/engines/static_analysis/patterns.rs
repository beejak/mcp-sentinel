//! Pattern matching utilities

use regex::Regex;
use once_cell::sync::Lazy;

/// Common dangerous patterns
pub static COMMAND_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"os\.system\("#).unwrap(),
        Regex::new(r#"subprocess\.call\("#).unwrap(),
        Regex::new(r#"child_process\.exec\("#).unwrap(),
        Regex::new(r#"eval\("#).unwrap(),
    ]
});

pub static SENSITIVE_FILE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"\.ssh/id_rsa"#).unwrap(),
        Regex::new(r#"\.ssh/id_ed25519"#).unwrap(),
        Regex::new(r#"\.aws/credentials"#).unwrap(),
        Regex::new(r#"\.env"#).unwrap(),
    ]
});

pub static SECRET_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"AKIA[A-Z0-9]{16}"#).unwrap(), // AWS keys
        Regex::new(r#"sk-[a-zA-Z0-9]{48}"#).unwrap(), // OpenAI keys
        Regex::new(r#"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"#).unwrap(),
    ]
});
