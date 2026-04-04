use std::process::Command;

fn safe_shell_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe-shell"))
}

// --- Hook generation ---

#[test]
fn hook_zsh_generates_functions() {
    let output = safe_shell_bin().args(["hook", "zsh"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm()"));
    assert!(stdout.contains("npx()"));
    assert!(stdout.contains("pip()"));
    assert!(stdout.contains("cargo()"));
    assert!(stdout.contains("go()"));
    assert!(stdout.contains("docker()"));
    assert!(stdout.contains("terraform()"));
}

#[test]
fn hook_bash_works() {
    let output = safe_shell_bin().args(["hook", "bash"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm()"));
}

#[test]
fn hook_unknown_shell_fails() {
    let output = safe_shell_bin().args(["hook", "fish"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn hook_has_subcommand_detection() {
    let output = safe_shell_bin().args(["hook", "zsh"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // npm only sandboxes install/ci/run/exec/test
    assert!(stdout.contains("install|ci|run|exec|test"));
    // cargo sandboxes build/run/test/install
    assert!(stdout.contains("build|run|test|install"));
}

#[test]
fn hook_falls_back_when_safe_shell_missing() {
    let output = safe_shell_bin().args(["hook", "zsh"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("command -v safe-shell"));
    assert!(stdout.contains("command npm"));
}

#[test]
fn hook_uses_correct_profiles() {
    let output = safe_shell_bin().args(["hook", "zsh"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--profile npm"));
    assert!(stdout.contains("--profile pip"));
    assert!(stdout.contains("--profile cargo"));
    assert!(stdout.contains("--profile go"));
    assert!(stdout.contains("--profile docker"));
    assert!(stdout.contains("--profile terraform"));
}

// --- Status ---

#[test]
fn status_shows_state() {
    let output = safe_shell_bin().args(["status"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Either active or inactive
    assert!(stdout.contains("shield:"));
}

// --- Bypass ---

#[test]
fn bypass_runs_command() {
    let output = safe_shell_bin()
        .args(["bypass", "echo", "hello"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn bypass_shows_warning() {
    let output = safe_shell_bin()
        .args(["bypass", "echo", "test"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("without sandbox"),
        "bypass should warn. Got: {stderr}"
    );
}

#[test]
fn bypass_does_not_scrub_env() {
    let output = safe_shell_bin()
        .args(["bypass", "echo", "$AWS_SECRET_ACCESS_KEY"])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("supersecret"),
        "bypass should NOT scrub env. Got: {stdout}"
    );
}

// --- One-line status output ---

#[test]
fn exec_shows_status_line() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo", "hello"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("profile active") && stderr.contains("env scrubbed"),
        "exec should show status line. Got: {stderr}"
    );
}

#[test]
fn exec_quiet_suppresses_status() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "--quiet", "echo", "hello"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("profile active"),
        "exec --quiet should suppress status line. Got: {stderr}"
    );
}

#[test]
fn exec_status_shows_correct_counts() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "minimal", "echo", "hi"])
        .env("SECRET_KEY", "leaked")
        .env("API_TOKEN", "leaked")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("profile active") && stderr.contains("secret env vars removed"),
        "Status should show posture and scrub count. Got: {stderr}"
    );
}

// --- Cumulative: all previous phases still work ---

#[test]
fn phase0_env_scrub_still_works() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "echo $AWS_SECRET_ACCESS_KEY",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("supersecret"));
}

#[test]
fn phase1_filesystem_still_works() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "cat ~/.aws/credentials 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("Operation not permitted") || combined.contains("BLOCKED"),);
}

#[test]
fn phase2_network_still_works() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "curl -m 5 -s http://evil.com 2>&1",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("Network blocked") || combined.contains("blocked network"));
}
