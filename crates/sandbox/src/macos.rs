use std::process::Command;

use crate::proxy::DomainFilterProxy;
use crate::{ensure_path, resolve_path, resolve_shell, SandboxConfig, SandboxResult};

/// Execute a command inside a macOS Seatbelt sandbox.
pub fn execute(config: &SandboxConfig) -> Result<SandboxResult, Box<dyn std::error::Error>> {
    let shell = resolve_shell()?;

    let mut env = config.env.clone();
    ensure_path(&mut env);

    // Determine network mode and start proxy if needed
    let has_specific_domains =
        !config.network_allow.is_empty() && !config.network_allow.iter().any(|d| d == "*");

    let proxy = if has_specific_domains {
        // Start domain-filtering proxy
        let proxy = DomainFilterProxy::start(config.network_allow.clone(), config.quiet)
            .map_err(|e| format!("Failed to start network proxy: {e}"))?;

        let proxy_url = format!("http://127.0.0.1:{}", proxy.port());
        env.insert("HTTP_PROXY".to_string(), proxy_url.clone());
        env.insert("HTTPS_PROXY".to_string(), proxy_url.clone());
        env.insert("http_proxy".to_string(), proxy_url.clone());
        env.insert("https_proxy".to_string(), proxy_url);

        // Remove NO_PROXY — it bypasses our proxy entirely
        env.remove("NO_PROXY");
        env.remove("no_proxy");

        Some(proxy)
    } else {
        None
    };

    let proxy_port = proxy.as_ref().map(|p| p.port());
    let profile = generate_seatbelt_profile(config, proxy_port)?;

    // Build the sandbox-exec command.
    // Single arg: treat as shell string (user typed it in quotes)
    // Multiple args: use exec "$@" to preserve argument boundaries and prevent injection
    let mut cmd = Command::new("sandbox-exec");
    cmd.args(["-p", &profile, &shell, "--norc", "--noprofile"]);

    if config.command.len() == 1 {
        // Single string command: "npm install express"
        let wrapped = format!("hash -r 2>/dev/null; {}", &config.command[0]);
        cmd.args(["-c", &wrapped]);
    } else {
        // Multiple args: preserve boundaries with exec "$@"
        // bash -c 'hash -r 2>/dev/null; exec "$@"' _ arg1 arg2 arg3
        cmd.arg("-c");
        cmd.arg("hash -r 2>/dev/null; exec \"$@\"");
        cmd.arg("_"); // $0 placeholder
        cmd.args(&config.command);
    }

    let output = cmd
        .env_clear()
        .envs(&env)
        .current_dir(&config.cwd)
        .output()
        .map_err(|e| format!("Failed to execute sandbox-exec: {e}"))?;

    // Print stdout
    if !output.stdout.is_empty() {
        use std::io::Write;
        std::io::stdout().write_all(&output.stdout)?;
    }

    // Process stderr: surface "Operation not permitted" as ⚠ warnings and count them
    let mut file_reads_blocked = 0;
    if !output.stderr.is_empty() {
        let stderr_str = String::from_utf8_lossy(&output.stderr);
        for line in stderr_str.lines() {
            if line.contains("Operation not permitted") {
                file_reads_blocked += 1;
                if !config.quiet {
                    let path = line
                        .split(": Operation not permitted")
                        .next()
                        .and_then(|s| s.split(": ").nth(1))
                        .unwrap_or("unknown path");
                    eprintln!("\x1b[33m\u{26a0}\x1b[0m safe-shell: blocked file read: {path}");
                }
            }
            eprintln!("{line}");
        }
    }

    // Get network block count from proxy before it drops
    let network_requests_blocked = proxy.as_ref().map(|p| p.blocked_count()).unwrap_or(0);

    Ok(SandboxResult {
        status: output.status,
        file_reads_blocked,
        network_requests_blocked,
    })
}

/// Generate a Seatbelt profile string from the sandbox config.
///
/// Strategy: allow broad read access (the process needs to read dyld caches,
/// frameworks, libs, etc.), then DENY specific sensitive paths. Seatbelt
/// evaluates deny rules after allow rules, so explicit denies win.
///
/// Writes are restrictive: only /dev, /tmp, and explicitly allowed paths.
fn generate_seatbelt_profile(
    config: &SandboxConfig,
    proxy_port: Option<u16>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut p = String::new();
    let cwd = &config.cwd;

    // Base: deny everything by default
    p.push_str("(version 1)\n");
    p.push_str("(deny default)\n");

    // Process, IPC, and system access — required for any process to run
    p.push_str("(allow process*)\n");
    p.push_str("(allow sysctl*)\n");
    p.push_str("(allow mach*)\n");
    p.push_str("(allow signal)\n");
    p.push_str("(allow ipc*)\n");

    // Broad file read access — the process needs dyld shared cache, frameworks, etc.
    p.push_str("(allow file-read*)\n");

    // Write access — restrictive, only specific paths
    // /dev (stdout, stderr, tty)
    p.push_str("(allow file-write* (subpath \"/dev\"))\n");
    // /tmp and /private/tmp
    p.push_str("(allow file-write* (subpath \"/tmp\"))\n");
    p.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
    // /var/folders — macOS per-user temp directory (used by mktemp, many build tools)
    p.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");

    // Project directory — write access to cwd itself for general use
    let cwd_str = cwd.to_string_lossy();
    p.push_str(&format!("(allow file-write* (subpath \"{cwd_str}\"))\n"));

    // Additional writable paths from profile
    for path_pattern in &config.allow_write {
        let resolved = resolve_path(path_pattern, cwd);
        if resolved.contains('*') {
            continue;
        }
        p.push_str(&format!("(allow file-write* (subpath \"{resolved}\"))\n"));
    }

    // DENY read for sensitive paths — these override the broad allow above
    for path_pattern in &config.deny_read {
        // Skip glob patterns (*.pem, .env.*) — Seatbelt can't match by extension.
        // These files are protected by the write restrictions (can't exfiltrate
        // without network) and will be handled by the content-aware proxy in Phase 2.
        if path_pattern.contains('*') {
            continue;
        }

        let resolved = resolve_path(path_pattern, cwd);
        p.push_str(&format!("(deny file-read* (subpath \"{resolved}\"))\n"));
    }

    // Network rules — three modes:
    if config.network_allow.is_empty() {
        // Full block: no outbound network at all
        p.push_str("(deny network*)\n");
    } else if let Some(port) = proxy_port {
        // Domain filter: allow network but only to the proxy's specific port
        p.push_str("(allow network*)\n");
        // Deny outbound to all remote hosts, then allow only the proxy port
        p.push_str("(deny network-outbound (remote ip \"*:*\"))\n");
        p.push_str(&format!(
            "(allow network-outbound (remote ip \"localhost:{port}\"))\n"
        ));
    }
    // else: allow = ["*"] → full access, don't add any network deny rules

    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            command: vec!["echo hello".to_string()],
            env: HashMap::new(),
            cwd: PathBuf::from("/project"),
            allow_write: vec!["./node_modules".to_string(), "/tmp".to_string()],
            deny_read: vec!["~/.aws".to_string(), "~/.ssh".to_string()],
            network_allow: vec![],
            quiet: true,
        }
    }

    #[test]
    fn profile_starts_with_deny_default() {
        let config = test_config();
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        assert!(profile.starts_with("(version 1)\n(deny default)\n"));
    }

    #[test]
    fn profile_has_broad_read_access() {
        let config = test_config();
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        assert!(profile.contains("(allow file-read*)"));
    }

    #[test]
    fn profile_allows_writable_paths() {
        let config = test_config();
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        assert!(profile.contains("(allow file-write* (subpath \"/project/node_modules\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp\"))"));
    }

    #[test]
    fn profile_allows_cwd_write() {
        let config = test_config();
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        assert!(profile.contains("(allow file-write* (subpath \"/project\"))"));
    }

    #[test]
    fn profile_denies_sensitive_paths() {
        let config = test_config();
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        let home = dirs::home_dir().unwrap();
        let home_str = home.to_string_lossy();
        assert!(profile.contains(&format!("(deny file-read* (subpath \"{home_str}/.aws\"))")));
        assert!(profile.contains(&format!("(deny file-read* (subpath \"{home_str}/.ssh\"))")));
    }

    #[test]
    fn profile_denies_network_when_empty() {
        let config = test_config();
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn profile_full_allow_network() {
        let mut config = test_config();
        config.network_allow = vec!["*".to_string()];
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        assert!(!profile.contains("(deny network"));
    }

    #[test]
    fn profile_proxy_mode_allows_only_proxy_port() {
        let mut config = test_config();
        config.network_allow = vec!["registry.npmjs.org".to_string()];
        let profile = generate_seatbelt_profile(&config, Some(54321)).unwrap();
        assert!(profile.contains("(deny network-outbound (remote ip \"*:*\"))"));
        assert!(profile.contains("(allow network-outbound (remote ip \"localhost:54321\"))"));
        // Must NOT allow all of localhost
        assert!(!profile.contains("localhost:*"));
    }

    #[test]
    fn deny_comes_after_allow() {
        let config = test_config();
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        let home = dirs::home_dir().unwrap();
        let home_str = home.to_string_lossy();

        let allow_pos = profile.find("(allow file-read*)").unwrap();
        let deny_pos = profile
            .find(&format!("(deny file-read* (subpath \"{home_str}/.aws\"))"))
            .unwrap();
        assert!(
            deny_pos > allow_pos,
            "deny rules must come after allow rules"
        );
    }

    #[test]
    fn skips_glob_patterns_in_deny() {
        let mut config = test_config();
        config.deny_read.push("*.pem".to_string());
        config.deny_read.push(".env.*".to_string());
        let profile = generate_seatbelt_profile(&config, None).unwrap();
        assert!(!profile.contains("*.pem"));
        assert!(!profile.contains(".env.*"));
    }
}
