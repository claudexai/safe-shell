use crate::profiles::{load_shield_mappings, ShieldMapping};

/// Generate shell hook functions that auto-intercept package manager commands.
///
/// Each hook wraps a command (npm, pip, cargo, etc.) with a shell function
/// that checks the subcommand and routes dangerous ones through safe-shell.
pub fn generate_hook(shell: &str) -> Result<String, Box<dyn std::error::Error>> {
    match shell {
        "zsh" | "bash" => {
            let (mappings, warnings) = load_shield_mappings();
            for w in &warnings {
                eprintln!("\x1b[33m\u{26a0}\x1b[0m safe-shell: {w}");
            }
            Ok(generate_posix_hook_from_mappings(&mappings))
        }
        _ => Err(format!("Unsupported shell: '{shell}'. Use 'zsh' or 'bash'.").into()),
    }
}

/// Generate hooks and return any warnings about invalid profiles.
pub fn generate_hook_with_warnings(
    shell: &str,
) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
    match shell {
        "zsh" | "bash" => {
            let (mappings, warnings) = load_shield_mappings();
            Ok((generate_posix_hook_from_mappings(&mappings), warnings))
        }
        _ => Err(format!("Unsupported shell: '{shell}'. Use 'zsh' or 'bash'.").into()),
    }
}

fn generate_posix_hook_from_mappings(mappings: &[ShieldMapping]) -> String {
    let mut hook = String::new();

    hook.push_str("# --- safe-shell shield hooks (do not edit) ---\n\n");

    // Clear aliases that conflict with hook functions
    hook.push_str("# Clear aliases that conflict with hook functions\n");
    for m in mappings {
        hook.push_str(&format!("unalias {} 2>/dev/null\n", m.command));
    }
    hook.push('\n');

    for m in mappings {
        let subcmds: Vec<&str> = m
            .subcommands
            .as_ref()
            .map(|s| s.iter().map(|x| x.as_str()).collect())
            .unwrap_or_default();
        hook.push_str(&generate_wrapper(&m.command, &m.profile, &subcmds));
        hook.push('\n');
    }

    hook.push_str("# --- end safe-shell shield hooks ---\n");
    hook
}

fn generate_wrapper(cmd: &str, profile: &str, subcommands: &[&str]) -> String {
    // Resolve the binary path BEFORE entering the sandbox.
    // Inside the sandbox, PATH might differ and find a different binary.
    // $(command -v cmd) runs in the user's shell, not inside the sandbox.

    // For commands where ALL invocations are sandboxed (npx, custom aliases)
    if subcommands.is_empty() {
        return format!(
            r#"{cmd}() {{
  if [ -n "$SAFE_SHELL_BYPASS" ] || ! command -v safe-shell >/dev/null 2>&1; then
    command {cmd} "$@"
    return $?
  fi
  local _bin
  _bin="$(command -v {cmd})" || {{ echo "safe-shell: {cmd} not found" >&2; return 127; }}
  safe-shell exec --profile {profile} -- "$_bin" "$@"
}}

"#
        );
    }

    // Build the case match for sandboxed subcommands
    let cases = subcommands.join("|");

    format!(
        r#"{cmd}() {{
  if [ -n "$SAFE_SHELL_BYPASS" ] || ! command -v safe-shell >/dev/null 2>&1; then
    command {cmd} "$@"
    return $?
  fi
  case "$1" in
    {cases})
      local _bin
      _bin="$(command -v {cmd})" || {{ echo "safe-shell: {cmd} not found" >&2; return 127; }}
      safe-shell exec --profile {profile} -- "$_bin" "$@"
      return $?
      ;;
  esac
  command {cmd} "$@"
}}

"#
    )
}

/// Check if the safe-shell hook line exists in a shell config file.
pub fn is_hook_installed(shell_config: &str) -> bool {
    shell_config.contains("safe-shell hook")
}

/// The lines to add to shell config.
/// Uses a two-step approach: first writes hooks to a cache file,
/// then sources it. This avoids zsh's "alias vs function" parse conflict.
pub fn hook_eval_line(shell: &str) -> String {
    let cache_dir = "~/.cache/safe-shell";
    let cache_file = format!("{cache_dir}/hooks.sh");
    format!(
        "mkdir -p {cache_dir} 2>/dev/null; safe-shell hook {shell} > {cache_file} 2>/dev/null && source {cache_file}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_zsh_hook() {
        let hook = generate_hook("zsh").unwrap();
        assert!(hook.contains("npm()"));
        assert!(hook.contains("pip()"));
        assert!(hook.contains("cargo()"));
        assert!(hook.contains("go()"));
        assert!(hook.contains("docker()"));
        assert!(hook.contains("terraform()"));
        assert!(hook.contains("--profile npm"));
        assert!(hook.contains("--profile pip"));
        assert!(hook.contains("--profile cargo"));
    }

    #[test]
    fn generates_bash_hook() {
        let hook = generate_hook("bash").unwrap();
        assert!(hook.contains("npm()"));
    }

    #[test]
    fn unknown_shell_errors() {
        assert!(generate_hook("fish").is_err());
    }

    #[test]
    fn npm_hook_has_subcommand_detection() {
        let hook = generate_hook("zsh").unwrap();
        assert!(hook.contains("install|ci|run|exec|test"));
    }

    #[test]
    fn npm_version_not_sandboxed() {
        let hook = generate_hook("zsh").unwrap();
        // --version is not in the case match, so it falls through to `command npm`
        assert!(!hook.contains("--version"));
    }

    #[test]
    fn npx_always_sandboxed() {
        let hook = generate_hook("zsh").unwrap();
        // npx doesn't have a case match — all invocations are sandboxed
        let npx_section: &str = hook.split("npx()").nth(1).unwrap();
        let npx_fn = npx_section.split("\n\n").next().unwrap();
        assert!(
            !npx_fn.contains("case"),
            "npx should not have subcommand filtering"
        );
    }

    #[test]
    fn hook_falls_back_when_safe_shell_missing() {
        let hook = generate_hook("zsh").unwrap();
        assert!(hook.contains("command -v safe-shell"));
        assert!(
            hook.contains("command npm"),
            "should fall back to real command"
        );
    }

    #[test]
    fn hook_eval_line_format() {
        let line = hook_eval_line("zsh");
        assert!(line.contains("safe-shell hook zsh"));
        assert!(line.contains("source"));
    }

    #[test]
    fn is_hook_installed_detects() {
        assert!(is_hook_installed(
            "some stuff\neval \"$(safe-shell hook zsh)\"\nmore stuff"
        ));
        assert!(!is_hook_installed("normal zshrc content"));
    }
}
