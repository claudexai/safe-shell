use std::process::Command;

fn safe_shell_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe-shell"))
}

#[test]
fn blocks_aws_credentials() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ~/.aws/credentials 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
            || combined.contains("No such file"),
        "~/.aws should be blocked. Got: {combined}"
    );
}

#[test]
fn blocks_ssh_keys() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "ls ~/.ssh 2>&1; echo EXIT=$?"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
            || combined.contains("No such file"),
        "~/.ssh should be blocked. Got: {combined}"
    );
}

#[test]
fn blocks_gnupg() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "ls ~/.gnupg 2>&1; echo EXIT=$?"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
            || combined.contains("No such file"),
        "~/.gnupg should be blocked. Got: {combined}"
    );
}

#[test]
fn blocks_docker_config() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ~/.docker/config.json 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
            || combined.contains("No such file"),
        "~/.docker should be blocked. Got: {combined}"
    );
}

#[test]
fn blocks_kube_config() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ~/.kube/config 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
            || combined.contains("No such file"),
        "~/.kube should be blocked. Got: {combined}"
    );
}

#[test]
fn basic_echo_works_in_sandbox() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo hello"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn can_write_to_tmp() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "touch /tmp/safe-shell-test-phase1 && echo OK",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OK"), "/tmp should be writable");

    // Clean up
    let _ = std::fs::remove_file("/tmp/safe-shell-test-phase1");
}

#[test]
fn can_read_system_files() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "cat /etc/hosts"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("localhost"),
        "Should be able to read system files like /etc/hosts"
    );
}

#[test]
fn env_scrubbing_works_with_sandbox() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo $AWS_SECRET_ACCESS_KEY"])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("supersecret"),
        "Phase 0 env scrubbing should work inside Phase 1 sandbox"
    );
}

#[test]
fn path_preserved_in_sandbox() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "which cat"])
        .output()
        .unwrap();

    assert!(output.status.success(), "cat should be findable via PATH");
}

#[test]
fn cat_command_found_in_sandbox() {
    // Regression: bash hash table was stale inside sandbox-exec, causing "command not found"
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "cat /etc/hosts"])
        .output()
        .unwrap();

    assert!(output.status.success(), "cat should be found in sandbox");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("localhost"));
}

#[test]
fn ls_command_found_in_sandbox() {
    // Regression: bare ls/cat were not found due to stale bash hash table
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "ls /tmp"])
        .output()
        .unwrap();

    assert!(output.status.success(), "ls should be found in sandbox");
}

#[test]
fn common_commands_available() {
    // Verify that common system commands are all reachable via PATH inside sandbox
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "which cat && which ls && which touch && which mkdir && which rm",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Common commands should all be findable. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn write_to_sensitive_dir_blocked() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "touch ~/.aws/hacked 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
            || combined.contains("No such file"),
        "Writing to ~/.aws should be blocked. Got: {combined}"
    );
}

#[test]
fn both_layers_block_simultaneously() {
    // Phase 0 (env scrub) + Phase 1 (filesystem block) in one command
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "echo ENV=$AWS_SECRET_ACCESS_KEY && cat ~/.aws/credentials 2>&1 || echo FS_BLOCKED",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("supersecret"), "Env should be scrubbed");
    assert!(
        stdout.contains("Operation not permitted") || stdout.contains("FS_BLOCKED"),
        "Filesystem should be blocked"
    );
}

#[test]
fn node_runs_in_sandbox() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "node --version"])
        .output()
        .unwrap();

    // Node might not be installed, so just check it didn't get "command not found"
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("command not found"),
        "node should be findable if installed. Got: {combined}"
    );
}

#[test]
fn minimal_profile_blocks_everything() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "minimal",
            "cat ~/.aws/credentials 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
            || combined.contains("No such file"),
        "minimal profile should block ~/.aws"
    );
}

// --- Symlink and path traversal attack tests ---

#[test]
fn symlink_to_sensitive_dir_blocked() {
    // Attacker creates symlink in /tmp pointing to ~/.aws
    let link_path = "/tmp/safe-shell-test-symlink-aws";
    let _ = std::fs::remove_file(link_path);

    let home = std::env::var("HOME").unwrap();
    let _ = std::os::unix::fs::symlink(format!("{home}/.aws"), link_path);

    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            &format!("cat {link_path}/credentials 2>&1 || echo BLOCKED"),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "Symlink to ~/.aws should be blocked by Seatbelt. Got: {combined}"
    );

    let _ = std::fs::remove_file(link_path);
}

#[test]
fn symlink_created_inside_sandbox_blocked() {
    // Attacker creates symlink inside writable /tmp pointing to sensitive file
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "ln -sf ~/.aws/credentials /tmp/safe-shell-cred-link 2>/dev/null; cat /tmp/safe-shell-cred-link 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "Symlink created inside sandbox should still be blocked. Got: {combined}"
    );

    let _ = std::fs::remove_file("/tmp/safe-shell-cred-link");
}

#[test]
fn path_traversal_blocked() {
    // Try to escape project dir via ../
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ./../../.aws/credentials 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "Path traversal to ~/.aws should be blocked. Got: {combined}"
    );
}

#[test]
fn deep_path_traversal_blocked() {
    // Try deeply nested traversal
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ./../../../../../../../../../etc/../home/../Users/$USER/.aws/credentials 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "Deep path traversal should be blocked. Got: {combined}"
    );
}
