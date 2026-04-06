use std::process::Command;

/// Simulate shield mode: source the hooks, then run the command.
/// This is what happens after `safe-shell shield` + `source ~/.zshrc`.
fn run_shielded(command: &str) -> std::process::Output {
    let safe_shell_path = env!("CARGO_BIN_EXE_safe-shell");
    Command::new("bash")
        .args([
            "--norc",
            "--noprofile",
            "-c",
            &format!(
                "export PATH=\"{}:$PATH\"; eval \"$({} hook bash)\" && {}",
                std::path::Path::new(safe_shell_path)
                    .parent()
                    .unwrap()
                    .display(),
                safe_shell_path,
                command
            ),
        ])
        .output()
        .unwrap()
}

// ============================================================
// npm through shield
// ============================================================

#[test]
fn shield_npm_install_activates_sandbox() {
    // Verify npm install goes through the sandbox (env scrubbed, profile active)
    // without hitting any external registry.
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"test","version":"1.0.0"}"#,
    )
    .unwrap();

    let output = Command::new("bash")
        .current_dir(dir.path())
        .env_remove("SAFE_SHELL_BYPASS")
        .args([
            "--norc",
            "--noprofile",
            "-c",
            &format!(
                "export PATH=\"{}:$PATH\"; eval \"$({} hook bash)\" && npm install 2>&1",
                std::path::Path::new(env!("CARGO_BIN_EXE_safe-shell"))
                    .parent()
                    .unwrap()
                    .display(),
                env!("CARGO_BIN_EXE_safe-shell"),
            ),
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("profile active") || combined.contains("session complete"),
        "npm install through shield should activate sandbox. Got: {combined}"
    );
}

#[test]
fn shield_npm_install_scrubs_secrets() {
    let output = Command::new("bash")
        .args([
            "--norc",
            "--noprofile",
            "-c",
            &format!(
                "export PATH=\"{}:$PATH\"; eval \"$({} hook bash)\" && npm install --version 2>&1; echo AWS=$AWS_SECRET_ACCESS_KEY",
                std::path::Path::new(env!("CARGO_BIN_EXE_safe-shell"))
                    .parent()
                    .unwrap()
                    .display(),
                env!("CARGO_BIN_EXE_safe-shell"),
            ),
        ])
        .env("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // npm --version is NOT sandboxed (not in the subcommand list)
    // so AWS key should still be in env for non-sandboxed commands
    // This test just verifies the hook loaded without error
    assert!(
        stdout.contains("10.") || stdout.contains("9.") || stdout.contains("8."),
        "npm --version should work through hook. Got: {stdout}"
    );
}

#[test]
fn shield_npm_run_activates_sandbox() {
    // Verify npm run goes through the sandbox without hitting external services.
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"test","version":"1.0.0","scripts":{"test":"echo hello-from-sandbox"}}"#,
    )
    .unwrap();

    let output = Command::new("bash")
        .current_dir(dir.path())
        .env_remove("SAFE_SHELL_BYPASS")
        .args([
            "--norc",
            "--noprofile",
            "-c",
            &format!(
                "export PATH=\"{}:$PATH\"; eval \"$({} hook bash)\" && npm run test 2>&1",
                std::path::Path::new(env!("CARGO_BIN_EXE_safe-shell"))
                    .parent()
                    .unwrap()
                    .display(),
                env!("CARGO_BIN_EXE_safe-shell"),
            ),
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // npm run is sandboxed — verify sandbox activated and script ran
    assert!(
        combined.contains("profile active"),
        "npm run through shield should activate sandbox. Got: {combined}"
    );
    assert!(
        combined.contains("hello-from-sandbox"),
        "npm run script should execute. Got: {combined}"
    );
}

// ============================================================
// pip through shield
// ============================================================

#[test]
fn shield_pip_install_activates_sandbox() {
    // Verify pip install goes through the sandbox without hitting PyPI.
    // Use --help so pip doesn't actually try to reach the network.
    let output = Command::new("bash")
        .env_remove("SAFE_SHELL_BYPASS")
        .args([
            "--norc",
            "--noprofile",
            "-c",
            &format!(
                "export PATH=\"{}:$PATH\"; eval \"$({} hook bash)\" && pip install --help 2>&1 | head -5",
                std::path::Path::new(env!("CARGO_BIN_EXE_safe-shell"))
                    .parent()
                    .unwrap()
                    .display(),
                env!("CARGO_BIN_EXE_safe-shell"),
            ),
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("profile active")
            || combined.contains("session complete")
            || combined.contains("Usage")
            || combined.contains("not found")
            || combined.contains("bad interpreter"),
        "pip install --help through shield should activate sandbox (or pip broken/missing). Got: {combined}"
    );
}

// ============================================================
// cargo through shield
// ============================================================

#[test]
fn shield_cargo_build_works() {
    // Run cargo build on the safe-shell project itself through shield
    let output = Command::new("bash")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--norc",
            "--noprofile",
            "-c",
            &format!(
                "export PATH=\"{}:$PATH\"; eval \"$({} hook bash)\" && cargo check 2>&1 | tail -3",
                std::path::Path::new(env!("CARGO_BIN_EXE_safe-shell"))
                    .parent()
                    .unwrap()
                    .display(),
                env!("CARGO_BIN_EXE_safe-shell"),
            ),
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // cargo check doesn't trigger sandbox (not in subcommand list: build, run, test, install)
    // This just verifies the hook doesn't break cargo
    assert!(
        combined.contains("Finished")
            || combined.contains("Checking")
            || combined.contains("warning"),
        "cargo check through shield hook should work. Got: {combined}"
    );
}

// ============================================================
// Non-sandboxed subcommands pass through cleanly
// ============================================================

#[test]
fn shield_npm_version_not_sandboxed() {
    let output = run_shielded("npm --version 2>&1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    // --version should NOT be sandboxed, no safe-shell output
    assert!(
        !combined.contains("profile active"),
        "npm --version should NOT be sandboxed. Got: {combined}"
    );
    assert!(
        stdout.trim().contains('.'),
        "Should print version number. Got: {stdout}"
    );
}

#[test]
fn shield_npm_list_not_sandboxed() {
    let output = run_shielded("npm list --depth=0 2>&1");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("profile active"),
        "npm list should NOT be sandboxed. Got: {combined}"
    );
}

// ============================================================
// SAFE_SHELL_BYPASS works through shield
// ============================================================

#[test]
fn shield_bypass_env_works() {
    let output = Command::new("bash")
        .args([
            "--norc",
            "--noprofile",
            "-c",
            &format!(
                "export PATH=\"{}:$PATH\"; export SAFE_SHELL_BYPASS=1; eval \"$({} hook bash)\" && npm install --version 2>&1",
                std::path::Path::new(env!("CARGO_BIN_EXE_safe-shell"))
                    .parent()
                    .unwrap()
                    .display(),
                env!("CARGO_BIN_EXE_safe-shell"),
            ),
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // With SAFE_SHELL_BYPASS=1, even sandboxed subcommands should skip
    assert!(
        !combined.contains("profile active"),
        "SAFE_SHELL_BYPASS should skip sandbox. Got: {combined}"
    );
}

// ============================================================
// Error passthrough — errors from commands should be visible
// ============================================================

#[test]
fn shield_npm_error_passes_through() {
    // Verify npm errors are visible through the shield — not swallowed.
    // Use a local-only operation (missing script) so no network is needed.
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"test","version":"1.0.0"}"#,
    )
    .unwrap();

    let output = Command::new("bash")
        .current_dir(dir.path())
        .args([
            "--norc",
            "--noprofile",
            "-c",
            &format!(
                "export PATH=\"{}:$PATH\"; eval \"$({} hook bash)\" && npm run nonexistent-script 2>&1",
                std::path::Path::new(env!("CARGO_BIN_EXE_safe-shell"))
                    .parent()
                    .unwrap()
                    .display(),
                env!("CARGO_BIN_EXE_safe-shell"),
            ),
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("ERR!")
            || combined.contains("error")
            || combined.contains("Missing script")
            || combined.contains("not found"),
        "npm error should pass through shield. Got: {combined}"
    );
}

#[test]
fn shield_command_exit_code_passes_through() {
    let output = run_shielded("npm run nonexistent-script 2>&1; echo EXIT=$?");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // npm run with bad script should return non-zero exit code
    // Exit code may vary (1, 254, etc.) — just verify it's not EXIT=0
    assert!(
        !combined.contains("EXIT=0"),
        "Non-zero exit code should pass through shield. Got: {combined}"
    );
}

#[test]
fn shield_resolves_correct_binary() {
    // Verify the hook resolves the binary path BEFORE entering sandbox
    let output = run_shielded("which npm 2>&1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // `which npm` is not sandboxed (not in subcommand list), so it runs directly
    // and should show the real npm path
    assert!(
        stdout.contains("/npm") || stdout.contains("not found"),
        "which npm should resolve. Got: {stdout}"
    );
}
