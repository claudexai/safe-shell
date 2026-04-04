use std::process::Command;

fn safe_shell_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe-shell"))
}

/// Create an isolated config dir. Tests NEVER touch user's real config.
fn empty_config_dir() -> tempfile::TempDir {
    tempfile::TempDir::new().unwrap()
}

fn config_dir_with(config_content: &str) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("config.toml"), config_content).unwrap();
    dir
}

fn config_dir_with_profiles(config: &str, profiles: &str) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("config.toml"), config).unwrap();
    std::fs::write(dir.path().join("profiles.toml"), profiles).unwrap();
    dir
}

// ============================================================
// Hook generation — built-in defaults
// ============================================================

#[test]
fn hook_includes_builtin_commands() {
    let dir = empty_config_dir();
    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm()"));
    assert!(stdout.contains("pip()"));
    assert!(stdout.contains("cargo()"));
    assert!(stdout.contains("docker()"));
    assert!(stdout.contains("terraform()"));
}

#[test]
fn hook_has_marker_comments() {
    let dir = empty_config_dir();
    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# --- safe-shell shield hooks (do not edit) ---"));
    assert!(stdout.contains("# --- end safe-shell shield hooks ---"));
}

#[test]
fn hook_npm_has_subcommand_filtering() {
    let dir = empty_config_dir();
    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("install|ci|run|exec|test"));
}

// ============================================================
// Simple string aliases — sandbox all subcommands
// ============================================================

#[test]
fn simple_alias_sandboxes_all() {
    let dir = config_dir_with(
        r#"
[shield.aliases]
bun = "npm"
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bun()"));
    let bun_section = stdout.split("bun()").nth(1).unwrap_or("");
    let bun_fn = bun_section.split("\n\n").next().unwrap_or("");
    assert!(
        !bun_fn.contains("case"),
        "Simple alias should sandbox all (no case statement)"
    );
}

#[test]
fn simple_alias_uses_correct_profile() {
    let dir = config_dir_with(
        r#"
[shield.aliases]
bun = "npm"
poetry = "pip"
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bun()"));
    assert!(stdout.contains("poetry()"));
    assert!(stdout.contains("--profile npm"));
    assert!(stdout.contains("--profile pip"));
}

// ============================================================
// Detailed table aliases — selective subcommands
// ============================================================

#[test]
fn detailed_alias_with_subcommands() {
    let dir = config_dir_with(
        r#"
[shield.aliases]
pnpm = { profile = "npm", subcommands = ["install", "run", "test"] }
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pnpm()"));
    assert!(
        stdout.contains("install|run|test"),
        "Should have selective subcommands. Got: {stdout}"
    );
}

#[test]
fn detailed_alias_without_subcommands_sandboxes_all() {
    let dir = config_dir_with(
        r#"
[shield.aliases]
mytool = { profile = "minimal" }
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mytool()"));
    let section = stdout.split("mytool()").nth(1).unwrap_or("");
    let func = section.split("\n\n").next().unwrap_or("");
    assert!(!func.contains("case"), "No subcommands = sandbox all");
}

#[test]
fn mixed_simple_and_detailed_aliases() {
    let dir = config_dir_with(
        r#"
[shield.aliases]
bun = "npm"
pnpm = { profile = "npm", subcommands = ["install", "run"] }
yarn = { profile = "npm", subcommands = ["add", "install"] }
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // bun = simple → no case
    let bun_section = stdout.split("bun()").nth(1).unwrap_or("");
    let bun_fn = bun_section.split("\n\n").next().unwrap_or("");
    assert!(!bun_fn.contains("case"));

    // pnpm = detailed → has case
    assert!(stdout.contains("install|run"));

    // yarn = detailed → has case
    assert!(stdout.contains("add|install"));
}

// ============================================================
// Built-in overrides
// ============================================================

#[test]
fn override_builtin_uses_custom_profile() {
    let dir = config_dir_with_profiles(
        r#"
[shield.aliases]
npm = "my-npm"
"#,
        r#"
[my-npm]
description = "Custom npm"
network.allow = ["registry.npmjs.org"]
env.scrub = ["*_KEY"]
env.pass = ["PATH", "HOME"]
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--profile my-npm"),
        "npm should use overridden profile. Got: {stdout}"
    );
}

#[test]
fn override_builtin_keeps_subcommand_filtering() {
    let dir = config_dir_with_profiles(
        r#"
[shield.aliases]
npm = "my-npm"
"#,
        r#"
[my-npm]
description = "Custom npm"
network.allow = ["registry.npmjs.org"]
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("install|ci|run|exec|test"),
        "Override should keep built-in subcommands"
    );
}

#[test]
fn override_builtin_with_custom_subcommands() {
    let dir = config_dir_with_profiles(
        r#"
[shield.aliases]
npm = { profile = "my-npm", subcommands = ["install", "publish"] }
"#,
        r#"
[my-npm]
description = "Custom npm"
network.allow = ["registry.npmjs.org"]
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("install|publish"),
        "Override should use custom subcommands. Got: {stdout}"
    );
}

// ============================================================
// Invalid config handling
// ============================================================

#[test]
fn invalid_profile_reference_shows_warning() {
    let dir = config_dir_with(
        r#"
[shield.aliases]
fake-tool = "nonexistent-profile"
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nonexistent-profile") && stderr.contains("skipped"),
        "Should warn about invalid profile. Got stderr: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm()"), "Built-ins should still work");
    assert!(
        !stdout.contains("fake-tool()"),
        "Invalid alias should not appear"
    );
}

#[test]
fn malformed_config_does_not_crash() {
    let dir = config_dir_with("this is not [valid toml {{{");

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm()"));
}

#[test]
fn empty_aliases_section_works() {
    let dir = config_dir_with("[shield.aliases]\n");

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm()"));
}

#[test]
fn subcommands_as_string_does_not_crash() {
    let dir = config_dir_with(
        r#"
[shield.aliases]
bun = { profile = "npm", subcommands = "install" }
"#,
    );

    let output = safe_shell_bin()
        .args(["hook", "zsh"])
        .env("SAFE_SHELL_CONFIG_DIR", dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm()"), "Built-ins should still work");
}

// ============================================================
// Status and shield commands
// ============================================================

#[test]
fn status_command_works() {
    let output = safe_shell_bin().args(["status"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("shield"));
}

#[test]
fn unshield_does_not_crash() {
    let output = safe_shell_bin().args(["unshield"]).output().unwrap();
    assert!(output.status.success());
}

#[test]
fn shield_is_idempotent() {
    let output1 = safe_shell_bin().args(["shield"]).output().unwrap();
    let output2 = safe_shell_bin().args(["shield"]).output().unwrap();
    assert!(output1.status.success());
    assert!(output2.status.success());
}
