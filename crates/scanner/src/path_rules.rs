/// A pattern for detecting sensitive file paths.
#[derive(Debug, Clone)]
pub struct PathPattern {
    pub pattern: String,
    pub description: String,
}

/// Returns built-in sensitive path patterns.
pub fn get_sensitive_patterns() -> Vec<PathPattern> {
    vec![
        PathPattern {
            pattern: "~/.ssh".into(),
            description: "SSH keys and config".into(),
        },
        PathPattern {
            pattern: "~/.aws".into(),
            description: "AWS credentials".into(),
        },
        PathPattern {
            pattern: "~/.gnupg".into(),
            description: "GPG keys".into(),
        },
        PathPattern {
            pattern: "~/.config/gcloud".into(),
            description: "Google Cloud credentials".into(),
        },
        PathPattern {
            pattern: "~/.azure".into(),
            description: "Azure credentials".into(),
        },
        PathPattern {
            pattern: "~/.docker".into(),
            description: "Docker config (may contain registry auth)".into(),
        },
        PathPattern {
            pattern: "~/.kube".into(),
            description: "Kubernetes config".into(),
        },
        PathPattern {
            pattern: "~/.npmrc".into(),
            description: "npm auth tokens".into(),
        },
        PathPattern {
            pattern: ".env".into(),
            description: "Environment file".into(),
        },
        PathPattern {
            pattern: ".env.*".into(),
            description: "Environment file variants".into(),
        },
        PathPattern {
            pattern: "*.pem".into(),
            description: "PEM certificate/key".into(),
        },
        PathPattern {
            pattern: "*.key".into(),
            description: "Private key file".into(),
        },
        PathPattern {
            pattern: "*.p12".into(),
            description: "PKCS#12 certificate".into(),
        },
        PathPattern {
            pattern: "*.pfx".into(),
            description: "PFX certificate".into(),
        },
        PathPattern {
            pattern: "*.jks".into(),
            description: "Java keystore".into(),
        },
        PathPattern {
            pattern: "*.keystore".into(),
            description: "Keystore file".into(),
        },
        PathPattern {
            pattern: "*.tfvars".into(),
            description: "Terraform variables (may contain secrets)".into(),
        },
        PathPattern {
            pattern: "*.tfstate".into(),
            description: "Terraform state (contains resource details)".into(),
        },
        PathPattern {
            pattern: "credentials.json".into(),
            description: "Credentials file".into(),
        },
        PathPattern {
            pattern: "secrets.*".into(),
            description: "Secrets file".into(),
        },
        PathPattern {
            pattern: "service-account*.json".into(),
            description: "GCP service account key".into(),
        },
        PathPattern {
            pattern: "*.kdbx".into(),
            description: "KeePass database".into(),
        },
        PathPattern {
            pattern: "*.kdb".into(),
            description: "KeePass database (legacy)".into(),
        },
    ]
}

/// Check if a given path matches any built-in sensitive path pattern.
pub fn is_sensitive_path(path: &str) -> bool {
    let home = dirs::home_dir()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();

    let patterns = get_sensitive_patterns();
    for pat in &patterns {
        // Home directory paths (e.g. ~/.ssh)
        if pat.pattern.starts_with("~/") {
            let resolved = pat.pattern.replacen('~', &home, 1);
            if path == resolved || path.starts_with(&format!("{resolved}/")) {
                return true;
            }
            continue;
        }

        // Extension patterns (e.g. *.pem)
        if let Some(ext) = pat.pattern.strip_prefix("*.") {
            if path.ends_with(&format!(".{ext}")) {
                return true;
            }
            continue;
        }

        // Prefix glob patterns (e.g. .env.*, secrets.*, service-account*.json)
        if pat.pattern.contains('*') {
            let parts: Vec<&str> = pat.pattern.splitn(2, '*').collect();
            if parts.len() == 2 {
                let prefix = parts[0];
                let suffix = parts[1];
                if let Some(filename) = std::path::Path::new(path).file_name() {
                    let name = filename.to_string_lossy();
                    if name.starts_with(prefix)
                        && name.ends_with(suffix)
                        && name.len() >= prefix.len() + suffix.len()
                    {
                        return true;
                    }
                }
            }
            continue;
        }

        // Exact filename match (e.g. .env, credentials.json)
        if let Some(filename) = std::path::Path::new(path).file_name() {
            if filename.to_string_lossy() == pat.pattern {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_enough_patterns() {
        assert!(get_sensitive_patterns().len() >= 23);
    }

    #[test]
    fn detects_ssh_dir() {
        let home = dirs::home_dir().unwrap();
        assert!(is_sensitive_path(&format!(
            "{}/.ssh/id_rsa",
            home.display()
        )));
        assert!(is_sensitive_path(&format!("{}/.ssh", home.display())));
    }

    #[test]
    fn detects_aws_dir() {
        let home = dirs::home_dir().unwrap();
        assert!(is_sensitive_path(&format!(
            "{}/.aws/credentials",
            home.display()
        )));
    }

    #[test]
    fn detects_gnupg() {
        let home = dirs::home_dir().unwrap();
        assert!(is_sensitive_path(&format!(
            "{}/.gnupg/pubring.kbx",
            home.display()
        )));
    }

    #[test]
    fn detects_env_file() {
        assert!(is_sensitive_path(".env"));
        assert!(is_sensitive_path("/project/.env"));
    }

    #[test]
    fn detects_env_variants() {
        assert!(is_sensitive_path(".env.local"));
        assert!(is_sensitive_path(".env.production"));
        assert!(is_sensitive_path("/app/.env.staging"));
    }

    #[test]
    fn detects_pem_file() {
        assert!(is_sensitive_path("server.pem"));
        assert!(is_sensitive_path("/etc/ssl/private/server.pem"));
    }

    #[test]
    fn detects_key_file() {
        assert!(is_sensitive_path("private.key"));
        assert!(is_sensitive_path("/etc/ssl/server.key"));
    }

    #[test]
    fn detects_tfvars() {
        assert!(is_sensitive_path("terraform.tfvars"));
        assert!(is_sensitive_path("prod.tfvars"));
    }

    #[test]
    fn detects_credentials_json() {
        assert!(is_sensitive_path("credentials.json"));
        assert!(is_sensitive_path("/app/credentials.json"));
    }

    #[test]
    fn detects_secrets_file() {
        assert!(is_sensitive_path("secrets.yaml"));
        assert!(is_sensitive_path("secrets.json"));
    }

    #[test]
    fn detects_service_account() {
        assert!(is_sensitive_path("service-account.json"));
        assert!(is_sensitive_path("service-account-prod.json"));
    }

    #[test]
    fn detects_keepass() {
        assert!(is_sensitive_path("passwords.kdbx"));
        assert!(is_sensitive_path("legacy.kdb"));
    }

    #[test]
    fn allows_normal_files() {
        assert!(!is_sensitive_path("/usr/bin/ls"));
        assert!(!is_sensitive_path("src/main.rs"));
        assert!(!is_sensitive_path("package.json"));
        assert!(!is_sensitive_path("README.md"));
        assert!(!is_sensitive_path("Cargo.toml"));
    }
}
