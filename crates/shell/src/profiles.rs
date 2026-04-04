use safe_shell_scanner::config::{
    parse_custom_profiles, CustomProfileEntry, EnvConfig, FilesystemConfig, GlobalConfig,
    NetworkConfig, Profile,
};
use std::collections::HashMap;

const NPM_TOML: &str = include_str!("../../../profiles/npm.toml");
const PIP_TOML: &str = include_str!("../../../profiles/pip.toml");
const CARGO_TOML: &str = include_str!("../../../profiles/cargo.toml");
const GO_TOML: &str = include_str!("../../../profiles/go.toml");
const DOCKER_TOML: &str = include_str!("../../../profiles/docker.toml");
const TERRAFORM_TOML: &str = include_str!("../../../profiles/terraform.toml");
const MINIMAL_TOML: &str = include_str!("../../../profiles/minimal.toml");

const BUILTIN_NAMES: &[&str] = &[
    "npm",
    "pip",
    "cargo",
    "go",
    "docker",
    "terraform",
    "minimal",
];

/// List all built-in profiles with (name, description).
pub fn list_builtin_profiles() -> Vec<(&'static str, &'static str)> {
    vec![
        ("npm", "Node.js package manager — install, build, test"),
        ("pip", "Python package manager"),
        ("cargo", "Rust package manager and build tool"),
        ("go", "Go modules and build"),
        ("docker", "Docker build and run"),
        ("terraform", "Terraform init and plan (not apply)"),
        (
            "minimal",
            "Maximum isolation — no network, no secrets, project dir only",
        ),
    ]
}

/// List custom profiles from ~/.config/safe-shell/profiles.toml.
pub fn list_custom_profiles() -> Vec<(String, String)> {
    let customs = load_custom_profiles();
    let mut result: Vec<(String, String)> = customs
        .into_iter()
        .filter(|(name, _)| !BUILTIN_NAMES.contains(&name.as_str()))
        .map(|(name, entry)| {
            let desc = entry.description.unwrap_or_default();
            (name, desc)
        })
        .collect();
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// Load a profile by name — checks built-in first, then custom.
pub fn load_profile(name: &str) -> Result<Profile, Box<dyn std::error::Error>> {
    // Built-in profiles take priority and cannot be overridden
    if let Some(toml_str) = builtin_toml(name) {
        return Profile::from_toml(toml_str)
            .map_err(|e| format!("Failed to parse profile '{name}': {e}").into());
    }

    // Check custom profiles
    let customs = load_custom_profiles();
    if let Some(entry) = customs.get(name) {
        return Ok(entry.clone().into_profile(name));
    }

    Err(
        format!("Unknown profile: '{name}'. Run 'safe-shell profiles' to see available profiles.")
            .into(),
    )
}

/// Load a built-in profile by name (for backwards compatibility).
pub fn load_builtin(name: &str) -> Result<Profile, Box<dyn std::error::Error>> {
    load_profile(name)
}

/// Load a merged profile from: profile + global config + project config + CLI flags.
pub fn load_merged_profile(
    profile_name: Option<&str>,
    allow_net: &[String],
    allow_env: &[String],
    allow_read: &[String],
    allow_write: &[String],
    deny_read: &[String],
    scrub_env: &[String],
) -> Result<Profile, Box<dyn std::error::Error>> {
    // Start with profile or empty default
    let mut profile = match profile_name {
        Some(name) => load_profile(name)?,
        None => Profile::default(),
    };

    // Merge global config (~/.config/safe-shell/config.toml)
    // Restrictive only — can add deny_read, scrub patterns, but NOT relax security
    if let Some(global) = load_global_config() {
        profile.merge_restrictive(&global);
    }

    // Merge project config (./safe-shell.toml)
    // Restrictive only — a malicious repo cannot add allowed domains or passthrough envs
    if let Some(project) = load_project_config() {
        profile.merge_restrictive(&project);
    }

    // Apply CLI flags on top (highest priority)
    if !allow_net.is_empty()
        || !allow_env.is_empty()
        || !allow_read.is_empty()
        || !allow_write.is_empty()
        || !deny_read.is_empty()
        || !scrub_env.is_empty()
    {
        let cli_overlay = Profile {
            meta: None,
            network: if allow_net.is_empty() {
                None
            } else {
                Some(NetworkConfig {
                    allow: allow_net.to_vec(),
                })
            },
            filesystem: if allow_write.is_empty() && deny_read.is_empty() && allow_read.is_empty() {
                None
            } else {
                Some(FilesystemConfig {
                    allow_write: allow_write.to_vec(),
                    deny_read: deny_read.to_vec(),
                })
            },
            env: if allow_env.is_empty() && scrub_env.is_empty() {
                None
            } else {
                Some(EnvConfig {
                    pass: allow_env.to_vec(),
                    scrub: scrub_env.to_vec(),
                })
            },
        };
        profile.merge(&cli_overlay);

        // Handle --allow-read: remove matching patterns from deny_read
        if !allow_read.is_empty() {
            if let Some(ref mut fs) = profile.filesystem {
                fs.deny_read.retain(|p| !allow_read.contains(p));
            }
        }
    }

    Ok(profile)
}

fn builtin_toml(name: &str) -> Option<&'static str> {
    match name {
        "npm" => Some(NPM_TOML),
        "pip" => Some(PIP_TOML),
        "cargo" => Some(CARGO_TOML),
        "go" => Some(GO_TOML),
        "docker" => Some(DOCKER_TOML),
        "terraform" => Some(TERRAFORM_TOML),
        "minimal" => Some(MINIMAL_TOML),
        _ => None,
    }
}

/// Get the safe-shell config directory.
/// Checks SAFE_SHELL_CONFIG_DIR env var first (for testing), then
/// ~/.config/safe-shell, then platform config dir.
fn config_dir() -> Option<std::path::PathBuf> {
    // Override for testing — never touches real config
    if let Ok(dir) = std::env::var("SAFE_SHELL_CONFIG_DIR") {
        return Some(std::path::PathBuf::from(dir));
    }

    // Prefer ~/.config/safe-shell (cross-platform, CLI convention)
    if let Some(home) = dirs::home_dir() {
        let dot_config = home.join(".config").join("safe-shell");
        if dot_config.exists() {
            return Some(dot_config);
        }
    }

    // Fall back to platform config dir
    let platform = dirs::config_dir()?.join("safe-shell");
    if platform.exists() {
        return Some(platform);
    }

    // Default to ~/.config/safe-shell even if it doesn't exist yet
    dirs::home_dir().map(|h| h.join(".config").join("safe-shell"))
}

fn load_custom_profiles() -> HashMap<String, CustomProfileEntry> {
    let Some(dir) = config_dir() else {
        return HashMap::new();
    };
    let path = dir.join("profiles.toml");
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    parse_custom_profiles(&content).unwrap_or_default()
}

fn load_global_config_raw() -> Option<GlobalConfig> {
    let dir = config_dir()?;
    let path = dir.join("config.toml");
    let content = std::fs::read_to_string(path).ok()?;
    GlobalConfig::from_toml(&content).ok()
}

fn load_global_config() -> Option<Profile> {
    let dir = config_dir()?;
    let path = dir.join("config.toml");
    let content = std::fs::read_to_string(path).ok()?;
    Profile::from_toml(&content).ok()
}

fn load_project_config() -> Option<Profile> {
    let content = std::fs::read_to_string("safe-shell.toml").ok()?;
    Profile::from_toml(&content).ok()
}

/// A resolved shield mapping: command → profile, with metadata.
pub struct ShieldMapping {
    pub command: String,
    pub profile: String,
    pub subcommands: Option<Vec<String>>, // None = sandbox all
    pub source: ShieldMappingSource,
}

pub enum ShieldMappingSource {
    Builtin,
    Override, // built-in command, custom profile
    Custom,   // custom command from config
}

/// Built-in command → profile mappings with subcommand knowledge.
fn builtin_shield_mappings() -> Vec<(&'static str, &'static str, Option<&'static [&'static str]>)> {
    vec![
        (
            "npm",
            "npm",
            Some(&["install", "ci", "run", "exec", "test"]),
        ),
        ("npx", "npm", None), // None = sandbox all
        ("pip", "pip", Some(&["install"])),
        ("pip3", "pip", Some(&["install"])),
        ("cargo", "cargo", Some(&["build", "run", "test", "install"])),
        (
            "go",
            "go",
            Some(&["build", "run", "test", "install", "get"]),
        ),
        ("docker", "docker", Some(&["build", "run"])),
        ("terraform", "terraform", Some(&["init", "plan", "apply"])),
    ]
}

/// Load shield aliases from config and merge with built-in mappings.
/// Returns resolved mappings and any warnings for invalid profiles.
pub fn load_shield_mappings() -> (Vec<ShieldMapping>, Vec<String>) {
    let mut mappings = Vec::new();
    let mut warnings = Vec::new();

    // Load config aliases
    use safe_shell_scanner::config::ShieldAlias;
    let aliases: HashMap<String, ShieldAlias> = load_global_config_raw()
        .and_then(|c| c.shield)
        .and_then(|s| s.aliases)
        .unwrap_or_default();

    // Process built-in mappings (may be overridden by aliases)
    for (cmd, default_profile, subcommands) in builtin_shield_mappings() {
        let (profile, override_subcmds, source) = if let Some(alias) = aliases.get(cmd) {
            let p = alias.profile().to_string();
            // If alias specifies subcommands, use those; otherwise keep built-in subcommands
            let s = alias
                .subcommands()
                .cloned()
                .or_else(|| subcommands.map(|s| s.iter().map(|x| x.to_string()).collect()));
            (p, s, ShieldMappingSource::Override)
        } else {
            (
                default_profile.to_string(),
                subcommands.map(|s| s.iter().map(|x| x.to_string()).collect()),
                ShieldMappingSource::Builtin,
            )
        };

        // Validate profile exists
        if !profile_exists(&profile) {
            warnings.push(format!(
                "alias '{cmd}' references unknown profile '{profile}' — skipped"
            ));
            mappings.push(ShieldMapping {
                command: cmd.to_string(),
                profile: default_profile.to_string(),
                subcommands: subcommands.map(|s| s.iter().map(|x| x.to_string()).collect()),
                source: ShieldMappingSource::Builtin,
            });
            continue;
        }

        mappings.push(ShieldMapping {
            command: cmd.to_string(),
            profile,
            subcommands: override_subcmds,
            source,
        });
    }

    // Process custom aliases (commands not in built-ins)
    for (cmd, alias) in &aliases {
        // Skip if already handled as a built-in override
        if builtin_shield_mappings().iter().any(|(c, _, _)| c == cmd) {
            continue;
        }

        let profile = alias.profile();
        if !profile_exists(profile) {
            warnings.push(format!(
                "alias '{cmd}' references unknown profile '{profile}' — skipped"
            ));
            continue;
        }

        mappings.push(ShieldMapping {
            command: cmd.clone(),
            profile: profile.to_string(),
            subcommands: alias.subcommands().cloned(),
            source: ShieldMappingSource::Custom,
        });
    }

    // Sort custom aliases alphabetically
    mappings.sort_by(|a, b| a.command.cmp(&b.command));

    (mappings, warnings)
}

/// Check if a profile exists (built-in or custom).
fn profile_exists(name: &str) -> bool {
    if builtin_toml(name).is_some() {
        return true;
    }
    let customs = load_custom_profiles();
    customs.contains_key(name)
}
