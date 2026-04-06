use std::process::Command;

fn safe_shell_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe-shell"))
}

// ============================================================
// Postinstall scripts work inside sandbox
// Proves safe-shell doesn't break packages like --ignore-scripts does
// ============================================================

#[test]
fn esbuild_installs_in_sandbox() {
    // esbuild uses optionalDependencies for platform binary (no postinstall needed)
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"test","version":"1.0.0"}"#,
    )
    .unwrap();

    let output = safe_shell_bin()
        .current_dir(dir.path())
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "npm install esbuild --no-save 2>&1 | tail -3",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("added") || combined.contains("up to date"),
        "esbuild should install successfully. Got: {combined}"
    );
}

#[test]
fn esbuild_runs_after_sandboxed_install() {
    // Proves the installed binary works inside the sandbox
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "npx esbuild --version",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // esbuild version is a number like 0.28.0
    assert!(
        stdout.trim().contains('.'),
        "esbuild should run and print version. Got: {stdout}"
    );
}

// ============================================================
// Protections hold during postinstall execution
// ============================================================

#[test]
fn secrets_scrubbed_during_install() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "echo $AWS_SECRET_ACCESS_KEY",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("AKIA"),
        "Secrets should be scrubbed even during install. Got: {stdout}"
    );
}

#[test]
fn filesystem_blocked_during_install() {
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
    assert!(
        combined.contains("Operation not permitted") || combined.contains("BLOCKED"),
        "Filesystem should be blocked during install. Got: {combined}"
    );
}

#[test]
fn network_filtered_during_install() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "curl -m 3 -s http://untrusted.test 2>&1",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Network blocked") || combined.contains("blocked network"),
        "Unauthorized domains should be blocked during install. Got: {combined}"
    );
}

#[test]
fn allowed_domains_work_during_install() {
    // npm registry must be reachable for install to work
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "curl -m 10 -s -o /dev/null -w '%{http_code}' https://registry.npmjs.org/",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("200") || stdout.contains("301"),
        "registry.npmjs.org must be reachable. Got: {stdout}"
    );
}
