use std::process::Command;

fn safe_shell_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe-shell"))
}

// --- Full block (minimal profile) ---

#[test]
fn minimal_blocks_all_network() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "minimal",
            "curl -m 5 -s http://example.com 2>&1 || echo NETWORK_BLOCKED",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("NETWORK_BLOCKED") || stdout.contains("Could not resolve"),
        "minimal profile should block all network. Got: {stdout}"
    );
}

// --- Domain filtering (npm profile) ---

#[test]
fn npm_blocks_unauthorized_domain() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "curl -m 5 -s http://evil.com 2>&1",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Network blocked") || combined.contains("blocked network"),
        "npm profile should block evil.com. Got: {combined}"
    );
}

#[test]
fn npm_allows_registry() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "curl -m 10 -s -o /dev/null -w '%{http_code}' https://registry.npmjs.org/",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("200") || stdout.contains("301") || stdout.contains("302"),
        "npm profile should allow registry.npmjs.org. Got: {stdout}"
    );
}

#[test]
fn npm_allows_github() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "curl -m 10 -s -o /dev/null -w '%{http_code}' https://github.com/",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("200") || stdout.contains("301") || stdout.contains("302"),
        "npm profile should allow github.com. Got: {stdout}"
    );
}

#[test]
fn npm_blocks_sfrclak_attack_domain() {
    // The actual C&C domain from the axios attack
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "curl -m 5 -s http://sfrclak.com:8000 2>&1",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Network blocked") || combined.contains("blocked network"),
        "npm profile should block sfrclak.com. Got: {combined}"
    );
}

// --- Commands still work ---

#[test]
fn echo_works_with_network_sandbox() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo hello"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
}

// --- Phase 0 + 1 + 2 combined ---

#[test]
fn all_three_layers_combined() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "echo ENV=$AWS_SECRET_ACCESS_KEY && cat ~/.aws/credentials 2>&1 || echo FS_BLOCKED && curl -m 5 -s http://sfrclak.com:8000 2>&1 || echo NET_BLOCKED",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    // Phase 0: env scrubbed
    assert!(!combined.contains("supersecret"), "Env should be scrubbed");
    // Phase 1: filesystem blocked
    assert!(
        combined.contains("Operation not permitted") || combined.contains("FS_BLOCKED"),
        "Filesystem should be blocked"
    );
    // Phase 2: network blocked
    assert!(
        combined.contains("Network blocked")
            || combined.contains("blocked network")
            || combined.contains("NET_BLOCKED"),
        "Network should be blocked"
    );
}

// --- HTTPS shows block message (not silent) ---

#[test]
fn https_blocked_shows_message() {
    // Regression: HTTPS CONNECT rejections were silent — curl swallowed the 403 body
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "curl -m 5 -s https://gmail.com 2>&1",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        (combined.contains("Network blocked") || combined.contains("blocked network"))
            && combined.contains("gmail.com"),
        "HTTPS block should show clear message. Got: {combined}"
    );
}

// --- Dry run shows network mode ---

#[test]
fn dry_run_shows_network_full_block() {
    let output = safe_shell_bin()
        .args(["exec", "--dry-run", "--profile", "minimal", "echo hi"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("none") || stdout.contains("blocked"));
}

#[test]
fn dry_run_shows_network_allowed_domains() {
    let output = safe_shell_bin()
        .args(["exec", "--dry-run", "--profile", "npm", "echo hi"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("registry.npmjs.org"));
    assert!(stdout.contains("github.com"));
}
