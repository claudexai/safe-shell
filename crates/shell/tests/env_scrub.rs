use std::process::Command;

fn safe_shell_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe-shell"))
}

#[test]
fn scrubs_secret_key_from_env() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "minimal",
            "echo $AWS_SECRET_ACCESS_KEY",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("supersecret"), "Secret should be scrubbed");
    assert!(stdout.trim().is_empty() || stdout.trim() == "\n");
}

#[test]
fn scrubs_token_from_env() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "minimal", "echo $GITHUB_TOKEN"])
        .env("GITHUB_TOKEN", "ghp_fakefakefakefakefakefakefakefakefake")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("ghp_"), "Token should be scrubbed");
}

#[test]
fn scrubs_value_with_secret_pattern() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "minimal", "echo $MY_INNOCENT_VAR"])
        .env("MY_INNOCENT_VAR", "AKIAIOSFODNN7EXAMPLE")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("AKIA"),
        "Value containing AWS key pattern should be scrubbed"
    );
}

#[test]
fn preserves_path() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo $PATH"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("/usr/bin") || stdout.contains("/bin"),
        "PATH should be preserved"
    );
}

#[test]
fn preserves_home() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo $HOME"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty(), "HOME should be preserved");
}

#[test]
fn basic_command_works() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "minimal", "echo hello"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn command_failure_passes_exit_code() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "minimal", "exit 42"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(42));
}

#[test]
fn unknown_profile_returns_exit_3() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "nonexistent", "echo hi"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn profiles_list_shows_all() {
    let output = safe_shell_bin().args(["profiles"]).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm"));
    assert!(stdout.contains("pip"));
    assert!(stdout.contains("cargo"));
    assert!(stdout.contains("go"));
    assert!(stdout.contains("docker"));
    assert!(stdout.contains("terraform"));
    assert!(stdout.contains("minimal"));
}

#[test]
fn profiles_show_npm() {
    let output = safe_shell_bin().args(["profiles", "npm"]).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("registry.npmjs.org"));
    assert!(stdout.contains("node_modules"));
    assert!(stdout.contains("~/.aws"));
}

#[test]
fn dry_run_shows_info() {
    let output = safe_shell_bin()
        .args(["exec", "--dry-run", "--profile", "npm", "npm install"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dry run"));
    assert!(stdout.contains("npm install"));
    assert!(stdout.contains("Filesystem"));
    assert!(stdout.contains("Network"));
    assert!(stdout.contains("Platform"));
}

#[test]
fn version_flag() {
    let output = safe_shell_bin().args(["--version"]).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("safe-shell"));
    // Check version format, not exact number (avoids breaking on version bumps)
    assert!(
        stdout.contains("0."),
        "Should contain version number. Got: {stdout}"
    );
}
