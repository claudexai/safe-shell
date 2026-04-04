use std::collections::HashMap;

use crate::scanner::Scanner;

/// Scrub secret values from environment variables.
///
/// - `env`: the current environment
/// - `scrub_patterns`: glob patterns for keys to remove (e.g. `*_KEY`, `*_SECRET`)
/// - `pass_patterns`: glob patterns for keys to always keep (e.g. `PATH`, `HOME`)
/// - `scanner`: also scan values for secret content patterns
///
/// Returns the cleaned environment.
pub fn scrub_env(
    env: &HashMap<String, String>,
    scrub_patterns: &[String],
    pass_patterns: &[String],
    scanner: &Scanner,
) -> HashMap<String, String> {
    env.iter()
        .filter(|(key, value)| {
            // Always keep if key matches a pass pattern
            if pass_patterns.iter().any(|p| glob_match(p, key)) {
                return true;
            }

            // Remove if key matches a scrub pattern
            if scrub_patterns.iter().any(|p| glob_match(p, key)) {
                return false;
            }

            // Remove if value looks like a secret
            if scanner.contains_secret(value) {
                return false;
            }

            // Keep everything else
            true
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Simple glob matching for environment variable key patterns.
/// Supports `*` as wildcard prefix/suffix (e.g. `*_KEY`, `NODE_*`, `LC_*`).
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }

    pattern == text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_suffix() {
        assert!(glob_match("*_KEY", "AWS_SECRET_KEY"));
        assert!(glob_match("*_KEY", "STRIPE_KEY"));
        assert!(!glob_match("*_KEY", "PATH"));
        assert!(!glob_match("*_KEY", "KEY_NAME"));
    }

    #[test]
    fn glob_match_prefix() {
        assert!(glob_match("NODE_*", "NODE_ENV"));
        assert!(glob_match("NODE_*", "NODE_PATH"));
        assert!(!glob_match("NODE_*", "PATH"));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("PATH", "PATH"));
        assert!(!glob_match("PATH", "HOME"));
    }

    #[test]
    fn glob_match_wildcard_all() {
        assert!(glob_match("*", "ANYTHING"));
    }

    #[test]
    fn scrubs_secret_keys() {
        let scanner = Scanner::new();
        let mut env = HashMap::new();
        env.insert("AWS_SECRET_KEY".into(), "mysecret".into());
        env.insert("GITHUB_TOKEN".into(), "ghp_fake".into());
        env.insert("PATH".into(), "/usr/bin".into());
        env.insert("HOME".into(), "/home/user".into());

        let scrub = vec!["*_KEY".into(), "*_TOKEN".into()];
        let pass = vec!["PATH".into(), "HOME".into()];

        let result = scrub_env(&env, &scrub, &pass, &scanner);
        assert!(!result.contains_key("AWS_SECRET_KEY"));
        assert!(!result.contains_key("GITHUB_TOKEN"));
        assert!(result.contains_key("PATH"));
        assert!(result.contains_key("HOME"));
    }

    #[test]
    fn pass_overrides_scrub() {
        let scanner = Scanner::new();
        let mut env = HashMap::new();
        // NPM_TOKEN matches *_TOKEN scrub pattern, but also matches NPM_* pass pattern
        env.insert("NPM_TOKEN".into(), "some-token".into());

        let scrub = vec!["*_TOKEN".into()];
        let pass = vec!["NPM_*".into()];

        let result = scrub_env(&env, &scrub, &pass, &scanner);
        assert!(
            result.contains_key("NPM_TOKEN"),
            "pass should override scrub"
        );
    }

    #[test]
    fn scrubs_by_value_content() {
        let scanner = Scanner::new();
        let mut env = HashMap::new();
        // Key doesn't match any scrub pattern, but value contains an AWS key
        env.insert("MY_CUSTOM_VAR".into(), "AKIAIOSFODNN7EXAMPLE".into());
        env.insert("NORMAL_VAR".into(), "hello world".into());

        let scrub: Vec<String> = vec![];
        let pass: Vec<String> = vec![];

        let result = scrub_env(&env, &scrub, &pass, &scanner);
        assert!(
            !result.contains_key("MY_CUSTOM_VAR"),
            "should scrub value with AWS key"
        );
        assert!(result.contains_key("NORMAL_VAR"));
    }

    #[test]
    fn keeps_unmatched_vars() {
        let scanner = Scanner::new();
        let mut env = HashMap::new();
        env.insert("EDITOR".into(), "vim".into());
        env.insert("TERM".into(), "xterm-256color".into());

        let scrub = vec!["*_KEY".into()];
        let pass: Vec<String> = vec![];

        let result = scrub_env(&env, &scrub, &pass, &scanner);
        assert!(result.contains_key("EDITOR"));
        assert!(result.contains_key("TERM"));
    }

    #[test]
    fn empty_env_returns_empty() {
        let scanner = Scanner::new();
        let env = HashMap::new();
        let result = scrub_env(&env, &[], &[], &scanner);
        assert!(result.is_empty());
    }
}
