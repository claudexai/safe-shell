use serde::Deserialize;
use std::collections::HashMap;

/// Global config from ~/.config/safe-shell/config.toml
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GlobalConfig {
    pub shield: Option<ShieldConfig>,
    // Global env/filesystem overrides (restrictive merge)
    pub env: Option<EnvConfig>,
    pub filesystem: Option<FilesystemConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ShieldConfig {
    pub aliases: Option<HashMap<String, ShieldAlias>>,
}

/// A shield alias — either a simple string or a detailed config.
/// Simple:   `bun = "npm"`                    → sandbox all subcommands
/// Detailed: `bun = { profile = "npm", subcommands = ["install", "run"] }`
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ShieldAlias {
    Simple(String),
    Detailed(ShieldAliasDetailed),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShieldAliasDetailed {
    pub profile: String,
    pub subcommands: Option<Vec<String>>,
}

impl ShieldAlias {
    pub fn profile(&self) -> &str {
        match self {
            ShieldAlias::Simple(p) => p,
            ShieldAlias::Detailed(d) => &d.profile,
        }
    }

    pub fn subcommands(&self) -> Option<&Vec<String>> {
        match self {
            ShieldAlias::Simple(_) => None, // None = sandbox all
            ShieldAlias::Detailed(d) => d.subcommands.as_ref(),
        }
    }
}

impl GlobalConfig {
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

/// A custom profile entry from profiles.toml (dotted key format).
/// ```toml
/// [my-profile]
/// description = "My custom profile"
/// network.allow = ["example.com"]
/// filesystem.deny_read = ["~/.aws"]
/// env.scrub = ["*_KEY"]
/// env.pass = ["PATH"]
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CustomProfileEntry {
    pub description: Option<String>,
    pub network: Option<NetworkConfig>,
    pub filesystem: Option<FilesystemConfig>,
    pub env: Option<EnvConfig>,
}

impl CustomProfileEntry {
    /// Convert to a standard Profile.
    pub fn into_profile(self, name: &str) -> Profile {
        Profile {
            meta: Some(ProfileMeta {
                name: Some(name.to_string()),
                description: self.description,
                profile: None,
            }),
            network: self.network,
            filesystem: self.filesystem,
            env: self.env,
        }
    }
}

/// Parse a profiles.toml file containing multiple custom profiles.
pub fn parse_custom_profiles(
    text: &str,
) -> Result<HashMap<String, CustomProfileEntry>, toml::de::Error> {
    toml::from_str(text)
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Profile {
    pub meta: Option<ProfileMeta>,
    pub network: Option<NetworkConfig>,
    pub filesystem: Option<FilesystemConfig>,
    pub env: Option<EnvConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProfileMeta {
    pub name: Option<String>,
    pub description: Option<String>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FilesystemConfig {
    #[serde(default)]
    pub allow_write: Vec<String>,
    #[serde(default)]
    pub deny_read: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EnvConfig {
    #[serde(default)]
    pub scrub: Vec<String>,
    #[serde(default)]
    pub pass: Vec<String>,
}

impl Profile {
    /// Parse a profile from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Merge another profile on top of this one (union semantics).
    pub fn merge(&mut self, other: &Profile) {
        if let Some(ref net) = other.network {
            let self_net = self.network.get_or_insert_with(Default::default);
            for domain in &net.allow {
                if !self_net.allow.contains(domain) {
                    self_net.allow.push(domain.clone());
                }
            }
        }

        if let Some(ref fs) = other.filesystem {
            let self_fs = self.filesystem.get_or_insert_with(Default::default);
            for path in &fs.allow_write {
                if !self_fs.allow_write.contains(path) {
                    self_fs.allow_write.push(path.clone());
                }
            }
            for path in &fs.deny_read {
                if !self_fs.deny_read.contains(path) {
                    self_fs.deny_read.push(path.clone());
                }
            }
        }

        if let Some(ref env) = other.env {
            let self_env = self.env.get_or_insert_with(Default::default);
            for pat in &env.scrub {
                if !self_env.scrub.contains(pat) {
                    self_env.scrub.push(pat.clone());
                }
            }
            for pat in &env.pass {
                if !self_env.pass.contains(pat) {
                    self_env.pass.push(pat.clone());
                }
            }
        }
    }

    /// Merge another profile using restrictive-only semantics.
    /// Can only ADD restrictions (more deny_read, more scrub patterns).
    /// Cannot ADD permissions (network.allow, allow_write, env.pass are IGNORED).
    /// Used for project configs (safe-shell.toml) and global configs to prevent
    /// a malicious repo from relaxing the sandbox.
    pub fn merge_restrictive(&mut self, other: &Profile) {
        // network.allow — IGNORED (cannot add allowed domains)
        // filesystem.allow_write — IGNORED (cannot add writable paths)

        // filesystem.deny_read — can ADD more denied paths
        if let Some(ref fs) = other.filesystem {
            let self_fs = self.filesystem.get_or_insert_with(Default::default);
            for path in &fs.deny_read {
                if !self_fs.deny_read.contains(path) {
                    self_fs.deny_read.push(path.clone());
                }
            }
        }

        // env.scrub — can ADD more scrub patterns
        if let Some(ref env) = other.env {
            let self_env = self.env.get_or_insert_with(Default::default);
            for pat in &env.scrub {
                if !self_env.scrub.contains(pat) {
                    self_env.scrub.push(pat.clone());
                }
            }
            // env.pass — IGNORED (cannot add passthrough patterns)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NPM_TOML: &str = r#"
[meta]
name = "npm"
description = "Node.js package manager"

[network]
allow = ["registry.npmjs.org", "*.npmjs.org", "github.com"]

[filesystem]
allow_write = ["./node_modules", "./package-lock.json", "/tmp"]
deny_read = ["~/.aws", "~/.ssh"]

[env]
scrub = ["*_KEY", "*_SECRET", "*_TOKEN"]
pass = ["PATH", "HOME", "NODE_ENV"]
"#;

    #[test]
    fn parse_profile() {
        let profile = Profile::from_toml(NPM_TOML).unwrap();
        let meta = profile.meta.unwrap();
        assert_eq!(meta.name.unwrap(), "npm");

        let net = profile.network.unwrap();
        assert_eq!(net.allow.len(), 3);
        assert!(net.allow.contains(&"registry.npmjs.org".to_string()));

        let fs = profile.filesystem.unwrap();
        assert_eq!(fs.allow_write.len(), 3);
        assert_eq!(fs.deny_read.len(), 2);

        let env = profile.env.unwrap();
        assert_eq!(env.scrub.len(), 3);
        assert_eq!(env.pass.len(), 3);
    }

    #[test]
    fn merge_union_semantics() {
        let mut base = Profile::from_toml(NPM_TOML).unwrap();

        let overlay = Profile::from_toml(
            r#"
[network]
allow = ["custom.registry.com", "github.com"]

[filesystem]
deny_read = ["~/.gnupg"]

[env]
scrub = ["*_PASSWORD"]
pass = ["CI"]
"#,
        )
        .unwrap();

        base.merge(&overlay);

        let net = base.network.unwrap();
        assert_eq!(net.allow.len(), 4); // 3 original + 1 new (github.com deduped)
        assert!(net.allow.contains(&"custom.registry.com".to_string()));
        assert!(net.allow.contains(&"github.com".to_string()));

        let fs = base.filesystem.unwrap();
        assert_eq!(fs.deny_read.len(), 3); // ~/.aws, ~/.ssh, ~/.gnupg

        let env = base.env.unwrap();
        assert_eq!(env.scrub.len(), 4); // 3 + *_PASSWORD
        assert_eq!(env.pass.len(), 4); // 3 + CI
    }

    #[test]
    fn merge_into_empty_profile() {
        let mut base = Profile::default();
        let overlay = Profile::from_toml(NPM_TOML).unwrap();
        base.merge(&overlay);

        let net = base.network.unwrap();
        assert_eq!(net.allow.len(), 3);
    }

    #[test]
    fn merge_with_empty_overlay() {
        let mut base = Profile::from_toml(NPM_TOML).unwrap();
        let overlay = Profile::default();
        base.merge(&overlay);

        let net = base.network.unwrap();
        assert_eq!(net.allow.len(), 3); // unchanged
    }

    #[test]
    fn merge_restrictive_blocks_network_allow() {
        let mut base = Profile::from_toml(NPM_TOML).unwrap();

        // Attacker tries to add evil.com via project config
        let malicious = Profile::from_toml(
            r#"
[network]
allow = ["evil.com"]
"#,
        )
        .unwrap();

        base.merge_restrictive(&malicious);

        let net = base.network.unwrap();
        assert_eq!(net.allow.len(), 3); // unchanged — evil.com NOT added
        assert!(!net.allow.contains(&"evil.com".to_string()));
    }

    #[test]
    fn merge_restrictive_blocks_env_pass() {
        let mut base = Profile::from_toml(NPM_TOML).unwrap();

        // Attacker tries to pass through secrets
        let malicious = Profile::from_toml(
            r#"
[env]
pass = ["*_SECRET", "AWS_*"]
"#,
        )
        .unwrap();

        base.merge_restrictive(&malicious);

        let env = base.env.unwrap();
        assert_eq!(env.pass.len(), 3); // unchanged — no new pass patterns
        assert!(!env.pass.contains(&"*_SECRET".to_string()));
    }

    #[test]
    fn merge_restrictive_blocks_allow_write() {
        let mut base = Profile::from_toml(NPM_TOML).unwrap();

        // Attacker tries to make ~/.ssh writable
        let malicious = Profile::from_toml(
            r#"
[filesystem]
allow_write = ["~/.ssh", "/etc"]
"#,
        )
        .unwrap();

        base.merge_restrictive(&malicious);

        let fs = base.filesystem.unwrap();
        assert_eq!(fs.allow_write.len(), 3); // unchanged
        assert!(!fs.allow_write.contains(&"~/.ssh".to_string()));
    }

    #[test]
    fn merge_restrictive_allows_adding_deny_read() {
        let mut base = Profile::from_toml(NPM_TOML).unwrap();

        // Project adds extra denied paths — this IS allowed (more restrictive)
        let extra_deny = Profile::from_toml(
            r#"
[filesystem]
deny_read = ["~/.config/company-secrets"]
"#,
        )
        .unwrap();

        base.merge_restrictive(&extra_deny);

        let fs = base.filesystem.unwrap();
        assert_eq!(fs.deny_read.len(), 3); // original 2 + 1 new
        assert!(fs
            .deny_read
            .contains(&"~/.config/company-secrets".to_string()));
    }

    #[test]
    fn merge_restrictive_allows_adding_scrub() {
        let mut base = Profile::from_toml(NPM_TOML).unwrap();

        // Project adds extra scrub patterns — this IS allowed (more restrictive)
        let extra_scrub = Profile::from_toml(
            r#"
[env]
scrub = ["COMPANY_*"]
"#,
        )
        .unwrap();

        base.merge_restrictive(&extra_scrub);

        let env = base.env.unwrap();
        assert_eq!(env.scrub.len(), 4); // original 3 + 1 new
        assert!(env.scrub.contains(&"COMPANY_*".to_string()));
    }

    #[test]
    fn parse_minimal_profile() {
        let minimal = r#"
[meta]
name = "minimal"
description = "Maximum isolation"

[network]
allow = []

[filesystem]
allow_write = [".", "/tmp"]
deny_read = ["~/.aws", "~/.ssh", "~/.gnupg"]

[env]
scrub = ["*_KEY", "*_SECRET"]
pass = ["PATH", "HOME"]
"#;
        let profile = Profile::from_toml(minimal).unwrap();
        let net = profile.network.unwrap();
        assert!(net.allow.is_empty());
    }
}
