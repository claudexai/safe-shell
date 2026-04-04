mod macos;
pub mod proxy;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitStatus;

/// Result from sandbox execution, including stats.
pub struct SandboxResult {
    pub status: ExitStatus,
    pub file_reads_blocked: usize,
    pub network_requests_blocked: usize,
}

/// Configuration for the sandbox, built from the merged profile.
pub struct SandboxConfig {
    pub command: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
    pub allow_write: Vec<String>,
    pub deny_read: Vec<String>,
    pub network_allow: Vec<String>,
    pub quiet: bool,
}

/// Resolve the absolute path to bash for sandbox execution.
///
/// Always uses bash, not the user's SHELL. Reason: zsh with env_clear()
/// reads /etc/zshenv which calls path_helper and can reset PATH, causing
/// "command not found" for basic tools like cat/ls. Bash handles minimal
/// environments reliably. The commands *inside* the sandbox (npm, node, etc.)
/// are unaffected — this only controls the `-c` wrapper.
pub fn resolve_shell() -> Result<String, Box<dyn std::error::Error>> {
    // Find bash via PATH (works before env_clear)
    if let Ok(path) = which::which("bash") {
        return Ok(path.to_string_lossy().to_string());
    }

    // Common locations as fallback
    for path in ["/bin/bash", "/usr/bin/bash", "/opt/homebrew/bin/bash"] {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    // Last resort: sh (POSIX, always available)
    if let Ok(path) = which::which("sh") {
        return Ok(path.to_string_lossy().to_string());
    }

    Err("Could not find bash or sh.".into())
}

/// Ensure the environment has a usable PATH. If the scrubbed env
/// doesn't include PATH, add a minimal one so commands like cat/ls work.
pub fn ensure_path(env: &mut HashMap<String, String>) {
    if !env.contains_key("PATH") {
        env.insert(
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
        );
    }
}

/// Resolve a path pattern: expand `~` to home dir, `.` and relative paths to absolute.
pub fn resolve_path(path: &str, cwd: &std::path::Path) -> String {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = dirs::home_dir() {
            return path.replacen('~', &home.to_string_lossy(), 1);
        }
    }

    if path == "." {
        return cwd.to_string_lossy().to_string();
    }

    if let Some(stripped) = path.strip_prefix("./") {
        return cwd.join(stripped).to_string_lossy().to_string();
    }

    if path.starts_with('/') {
        return path.to_string();
    }

    // Relative path — resolve against cwd
    cwd.join(path).to_string_lossy().to_string()
}

/// Execute a command inside the sandbox.
pub fn execute_sandboxed(
    command: &str,
    env: &HashMap<String, String>,
) -> Result<SandboxResult, Box<dyn std::error::Error>> {
    let config = SandboxConfig {
        command: vec![command.to_string()],
        env: env.clone(),
        cwd: std::env::current_dir()?,
        allow_write: vec![],
        deny_read: vec![],
        network_allow: vec![],
        quiet: false,
    };

    execute_with_config(&config)
}

/// Execute with full sandbox config (used by CLI with profile).
pub fn execute_with_config(
    config: &SandboxConfig,
) -> Result<SandboxResult, Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        macos::execute(config)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err("Unsupported platform. safe-shell currently supports macOS only. Linux support coming soon — see https://github.com/claudexai/safe-shell/issues".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_path_home() {
        let cwd = std::path::Path::new("/project");
        let resolved = resolve_path("~/.aws", cwd);
        let home = dirs::home_dir().unwrap();
        assert_eq!(resolved, format!("{}/.aws", home.display()));
    }

    #[test]
    fn resolve_path_dot() {
        let cwd = std::path::Path::new("/project");
        let resolved = resolve_path("./node_modules", cwd);
        assert_eq!(resolved, "/project/node_modules");
    }

    #[test]
    fn resolve_path_dot_alone() {
        let cwd = std::path::Path::new("/project");
        let resolved = resolve_path(".", cwd);
        assert_eq!(resolved, "/project");
    }

    #[test]
    fn resolve_path_absolute() {
        let cwd = std::path::Path::new("/project");
        let resolved = resolve_path("/tmp", cwd);
        assert_eq!(resolved, "/tmp");
    }

    #[test]
    fn resolve_path_relative() {
        let cwd = std::path::Path::new("/project");
        let resolved = resolve_path("target", cwd);
        assert_eq!(resolved, "/project/target");
    }
}
