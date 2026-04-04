use crate::rules::{built_in_rules, Rule};

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub matched: String,
    pub start: usize,
    pub end: usize,
}

pub struct Scanner {
    rules: Vec<Rule>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            rules: built_in_rules(),
        }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            for mat in rule.pattern.find_iter(text) {
                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                    matched: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                });
            }
        }
        findings
    }

    pub fn contains_secret(&self, text: &str) -> bool {
        self.rules.iter().any(|rule| rule.pattern.is_match(text))
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        let scanner = Scanner::new();
        assert!(scanner.contains_secret("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn detects_github_token() {
        let scanner = Scanner::new();
        assert!(scanner.contains_secret("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
    }

    #[test]
    fn detects_private_key() {
        let scanner = Scanner::new();
        assert!(scanner.contains_secret("-----BEGIN RSA PRIVATE KEY-----"));
    }

    #[test]
    fn scan_returns_findings() {
        let scanner = Scanner::new();
        let findings = scanner.scan("my key is AKIAIOSFODNN7EXAMPLE ok");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "aws-access-key");
    }

    #[test]
    fn scan_multiple_secrets() {
        let scanner = Scanner::new();
        let text = "aws=AKIAIOSFODNN7EXAMPLE and key=-----BEGIN RSA PRIVATE KEY-----";
        let findings = scanner.scan(text);
        assert!(findings.len() >= 2);
    }

    #[test]
    fn ignores_safe_text() {
        let scanner = Scanner::new();
        assert!(!scanner.contains_secret("hello world"));
        assert!(!scanner.contains_secret("npm install express"));
        assert!(!scanner.contains_secret("PATH=/usr/bin:/usr/local/bin"));
    }
}
