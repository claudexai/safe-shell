use regex::Regex;

pub struct Rule {
    pub id: String,
    pub description: String,
    pub pattern: Regex,
}

pub fn built_in_rules() -> Vec<Rule> {
    let rules_data: Vec<(&str, &str, &str)> = vec![
        // AWS
        ("aws-access-key", "AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
        (
            "aws-secret-key",
            "AWS Secret Access Key",
            r"(?i)aws_secret_access_key\s*=\s*\S+",
        ),
        (
            "aws-session-token",
            "AWS Session Token",
            r"(?i)aws_session_token\s*=\s*\S+",
        ),
        // AI providers
        (
            "anthropic-api-key",
            "Anthropic API Key",
            r"sk-ant-[a-zA-Z0-9_-]{20,}",
        ),
        ("openai-api-key", "OpenAI API Key", r"sk-[a-zA-Z0-9]{20,}"),
        (
            "openai-project-key",
            "OpenAI Project Key",
            r"sk-proj-[a-zA-Z0-9_-]{20,}",
        ),
        // Code hosting
        (
            "github-pat",
            "GitHub Personal Access Token",
            r"ghp_[a-zA-Z0-9]{36}",
        ),
        ("github-oauth", "GitHub OAuth Token", r"gho_[a-zA-Z0-9]{36}"),
        (
            "github-fine-grained",
            "GitHub Fine-Grained Token",
            r"github_pat_[a-zA-Z0-9_]{22,}",
        ),
        (
            "gitlab-pat",
            "GitLab Personal Access Token",
            r"glpat-[a-zA-Z0-9_-]{20,}",
        ),
        // Payment
        (
            "stripe-secret",
            "Stripe Secret Key",
            r"sk_live_[a-zA-Z0-9]{24,}",
        ),
        (
            "stripe-restricted",
            "Stripe Restricted Key",
            r"rk_live_[a-zA-Z0-9]{24,}",
        ),
        // Auth tokens
        (
            "jwt-token",
            "JWT Token",
            r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+",
        ),
        (
            "bearer-token",
            "Bearer Token",
            r"(?i)bearer\s+[a-zA-Z0-9_\-.]{20,}",
        ),
        // Private keys
        (
            "rsa-private-key",
            "RSA Private Key",
            r"-----BEGIN RSA PRIVATE KEY-----",
        ),
        (
            "ec-private-key",
            "EC Private Key",
            r"-----BEGIN EC PRIVATE KEY-----",
        ),
        (
            "pkcs8-private-key",
            "PKCS8 Private Key",
            r"-----BEGIN PRIVATE KEY-----",
        ),
        (
            "openssh-private-key",
            "OpenSSH Private Key",
            r"-----BEGIN OPENSSH PRIVATE KEY-----",
        ),
        // Database connection strings
        (
            "postgres-uri",
            "PostgreSQL Connection String",
            r"postgres(?:ql)?://[^\s]+:[^\s]+@[^\s]+",
        ),
        (
            "mysql-uri",
            "MySQL Connection String",
            r"mysql://[^\s]+:[^\s]+@[^\s]+",
        ),
        (
            "mongodb-uri",
            "MongoDB Connection String",
            r"mongodb(?:\+srv)?://[^\s]+:[^\s]+@[^\s]+",
        ),
        (
            "redis-uri",
            "Redis Connection String",
            r"redis://[^\s]*:[^\s]+@[^\s]+",
        ),
        // Communication
        (
            "slack-token",
            "Slack Token",
            r"xox[baprs]-[a-zA-Z0-9-]{10,}",
        ),
        (
            "slack-webhook",
            "Slack Webhook URL",
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        ),
        (
            "discord-bot-token",
            "Discord Bot Token",
            r"[MN][a-zA-Z0-9_-]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}",
        ),
        // SaaS
        (
            "sendgrid-key",
            "SendGrid API Key",
            r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        ),
        (
            "vault-token",
            "HashiCorp Vault Token",
            r"hvs\.[a-zA-Z0-9_-]{24,}",
        ),
        // Generic
        (
            "generic-password-assign",
            "Password Assignment",
            r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}"#,
        ),
    ];

    rules_data
        .into_iter()
        .map(|(id, desc, pat)| Rule {
            id: id.to_string(),
            description: desc.to_string(),
            pattern: Regex::new(pat).unwrap_or_else(|e| panic!("Bad regex for rule '{id}': {e}")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rules_compile() {
        let rules = built_in_rules();
        assert!(rules.len() >= 27, "Expected 27+ rules, got {}", rules.len());
    }

    #[test]
    fn aws_access_key() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "aws-access-key").unwrap();
        assert!(rule.pattern.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!rule.pattern.is_match("not-an-aws-key"));
    }

    #[test]
    fn anthropic_api_key() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "anthropic-api-key").unwrap();
        assert!(rule.pattern.is_match("sk-ant-api03-abcdefghijklmnopqrst"));
        assert!(!rule.pattern.is_match("sk-ant-short"));
    }

    #[test]
    fn openai_api_key() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "openai-api-key").unwrap();
        assert!(rule.pattern.is_match("sk-abcdefghijklmnopqrstuvwx"));
        assert!(!rule.pattern.is_match("sk-short"));
    }

    #[test]
    fn github_pat() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "github-pat").unwrap();
        assert!(rule
            .pattern
            .is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(!rule.pattern.is_match("ghp_short"));
    }

    #[test]
    fn github_fine_grained() {
        let rules = built_in_rules();
        let rule = rules
            .iter()
            .find(|r| r.id == "github-fine-grained")
            .unwrap();
        assert!(rule.pattern.is_match("github_pat_11ABCDEFGH0123456789AB"));
        assert!(!rule.pattern.is_match("github_pat_short"));
    }

    #[test]
    fn gitlab_pat() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "gitlab-pat").unwrap();
        assert!(rule.pattern.is_match("glpat-ABCDEFghijklmnopqrstu"));
        assert!(!rule.pattern.is_match("glpat-short"));
    }

    #[test]
    fn stripe_secret_key() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "stripe-secret").unwrap();
        assert!(rule.pattern.is_match("sk_live_abcdefghijklmnopqrstuvwx"));
        assert!(!rule.pattern.is_match("sk_test_abcdefghijklmnopqrstuvwx"));
    }

    #[test]
    fn jwt_token() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "jwt-token").unwrap();
        assert!(rule
            .pattern
            .is_match("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"));
        assert!(!rule.pattern.is_match("not.a.jwt"));
    }

    #[test]
    fn rsa_private_key() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "rsa-private-key").unwrap();
        assert!(rule.pattern.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!rule.pattern.is_match("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn postgres_uri() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "postgres-uri").unwrap();
        assert!(rule
            .pattern
            .is_match("postgresql://user:password@localhost:5432/db"));
        assert!(rule
            .pattern
            .is_match("postgres://admin:secret@prod.db.com/mydb"));
        assert!(!rule.pattern.is_match("postgres://localhost/db"));
    }

    #[test]
    fn mongodb_uri() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "mongodb-uri").unwrap();
        assert!(rule
            .pattern
            .is_match("mongodb+srv://user:pass@cluster.mongodb.net/db"));
        assert!(!rule.pattern.is_match("mongodb://localhost/db"));
    }

    #[test]
    fn slack_token() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "slack-token").unwrap();
        assert!(rule.pattern.is_match("xoxb-123456789-abcdefghij"));
        assert!(rule.pattern.is_match("xoxp-123456789-abcdefghij"));
        assert!(!rule.pattern.is_match("xoxb-short"));
    }

    #[test]
    fn sendgrid_key() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "sendgrid-key").unwrap();
        assert!(rule
            .pattern
            .is_match("SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"));
    }

    #[test]
    fn vault_token() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "vault-token").unwrap();
        assert!(rule.pattern.is_match("hvs.ABCDEFghijklmnopqrstuvwx"));
        assert!(!rule.pattern.is_match("hvs.short"));
    }

    #[test]
    fn generic_password() {
        let rules = built_in_rules();
        let rule = rules
            .iter()
            .find(|r| r.id == "generic-password-assign")
            .unwrap();
        assert!(rule.pattern.is_match("password=mysecretpassword"));
        assert!(rule.pattern.is_match("PASSWORD: 'longpassword123'"));
        assert!(!rule.pattern.is_match("password=short"));
    }

    #[test]
    fn bearer_token() {
        let rules = built_in_rules();
        let rule = rules.iter().find(|r| r.id == "bearer-token").unwrap();
        assert!(rule.pattern.is_match("Bearer abcdefghijklmnopqrstuvwx"));
        assert!(rule.pattern.is_match("bearer abcdefghijklmnopqrstuvwx"));
        assert!(!rule.pattern.is_match("Bearer short"));
    }

    #[test]
    fn no_false_positive_on_normal_text() {
        let rules = built_in_rules();
        let normal_texts = [
            "hello world",
            "npm install express",
            "const x = 42;",
            "PATH=/usr/bin",
            "HOME=/Users/dev",
            "NODE_ENV=production",
        ];
        for text in &normal_texts {
            for rule in &rules {
                assert!(
                    !rule.pattern.is_match(text),
                    "Rule '{}' false-positive on: {}",
                    rule.id,
                    text
                );
            }
        }
    }
}
