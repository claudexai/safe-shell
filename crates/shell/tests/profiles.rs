use std::process::Command;

fn safe_shell_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe-shell"))
}

fn assert_sandboxed(profile: &str) {
    // Basic command works
    let output = safe_shell_bin()
        .args(["exec", "--profile", profile, "--quiet", "echo", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{profile}: basic command failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello",
        "{profile}: unexpected output"
    );
}

fn assert_env_scrubbed(profile: &str) {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            profile,
            "--quiet",
            "echo",
            "$AWS_SECRET_ACCESS_KEY",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("AKIA"),
        "{profile}: AWS key not scrubbed. Got: {stdout}"
    );
}

fn assert_filesystem_blocked(profile: &str) {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            profile,
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
        combined.contains("Operation not permitted")
            || combined.contains("BLOCKED")
            || combined.contains("No such file"),
        "{profile}: ~/.aws not blocked. Got: {combined}"
    );
}

fn assert_network_blocked(profile: &str) {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            profile,
            "--quiet",
            "curl -m 5 -s http://evil.com 2>&1 || echo NET_BLOCKED",
        ])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Network blocked")
            || combined.contains("blocked network")
            || combined.contains("NET_BLOCKED")
            || combined.contains("Could not resolve"),
        "{profile}: evil.com not blocked. Got: {combined}"
    );
}

fn assert_profile_shows(profile: &str) {
    let output = safe_shell_bin()
        .args(["profiles", profile])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(profile),
        "{profile}: profiles show didn't contain profile name"
    );
}

// ============================================================
// npm profile
// ============================================================

#[test]
fn npm_basic_command() {
    assert_sandboxed("npm");
}

#[test]
fn npm_env_scrubbed() {
    assert_env_scrubbed("npm");
}

#[test]
fn npm_filesystem_blocked() {
    assert_filesystem_blocked("npm");
}

#[test]
fn npm_network_blocked() {
    assert_network_blocked("npm");
}

#[test]
fn npm_allows_registry() {
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
        "npm: registry.npmjs.org should be allowed. Got: {stdout}"
    );
}

#[test]
fn npm_profile_shows() {
    assert_profile_shows("npm");
}

// ============================================================
// pip profile
// ============================================================

#[test]
fn pip_basic_command() {
    assert_sandboxed("pip");
}

#[test]
fn pip_env_scrubbed() {
    assert_env_scrubbed("pip");
}

#[test]
fn pip_filesystem_blocked() {
    assert_filesystem_blocked("pip");
}

#[test]
fn pip_network_blocked() {
    assert_network_blocked("pip");
}

#[test]
fn pip_allows_pypi() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "pip",
            "--quiet",
            "curl -m 10 -s -o /dev/null -w '%{http_code}' https://pypi.org/",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("200") || stdout.contains("301"),
        "pip: pypi.org should be allowed. Got: {stdout}"
    );
}

#[test]
fn pip_profile_shows() {
    assert_profile_shows("pip");
}

// ============================================================
// cargo profile
// ============================================================

#[test]
fn cargo_basic_command() {
    assert_sandboxed("cargo");
}

#[test]
fn cargo_env_scrubbed() {
    assert_env_scrubbed("cargo");
}

#[test]
fn cargo_filesystem_blocked() {
    assert_filesystem_blocked("cargo");
}

#[test]
fn cargo_network_blocked() {
    assert_network_blocked("cargo");
}

#[test]
fn cargo_allows_crates_io() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "cargo",
            "--quiet",
            "curl -m 10 -s -o /dev/null -w '%{http_code}' https://crates.io/",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // crates.io returns 404 on root but that means the domain IS reachable
    let code: u16 = stdout.trim().parse().unwrap_or(0);
    assert!(
        code > 0 && code != 403,
        "cargo: crates.io should be allowed (got HTTP {code}, 403 = proxy blocked)"
    );
}

#[test]
fn cargo_profile_shows() {
    assert_profile_shows("cargo");
}

// ============================================================
// go profile
// ============================================================

#[test]
fn go_basic_command() {
    assert_sandboxed("go");
}

#[test]
fn go_env_scrubbed() {
    assert_env_scrubbed("go");
}

#[test]
fn go_filesystem_blocked() {
    assert_filesystem_blocked("go");
}

#[test]
fn go_network_blocked() {
    assert_network_blocked("go");
}

#[test]
fn go_allows_proxy() {
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "go",
            "--quiet",
            "curl -m 10 -s -o /dev/null -w '%{http_code}' https://proxy.golang.org/",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("200") || stdout.contains("301"),
        "go: proxy.golang.org should be allowed. Got: {stdout}"
    );
}

#[test]
fn go_profile_shows() {
    assert_profile_shows("go");
}

// ============================================================
// docker profile
// ============================================================

#[test]
fn docker_basic_command() {
    assert_sandboxed("docker");
}

#[test]
fn docker_env_scrubbed() {
    assert_env_scrubbed("docker");
}

#[test]
fn docker_filesystem_blocked() {
    assert_filesystem_blocked("docker");
}

#[test]
fn docker_network_blocked() {
    assert_network_blocked("docker");
}

#[test]
fn docker_profile_shows() {
    assert_profile_shows("docker");
}

// ============================================================
// terraform profile
// ============================================================

#[test]
fn terraform_basic_command() {
    assert_sandboxed("terraform");
}

#[test]
fn terraform_env_scrubbed() {
    // terraform scrubs *_PASSWORD, DATABASE_URL but NOT AWS_* (terraform needs them)
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "terraform",
            "--quiet",
            "echo $DATABASE_URL",
        ])
        .env("DATABASE_URL", "postgres://admin:secret@prod/db")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("postgres://"),
        "terraform: DATABASE_URL should be scrubbed. Got: {stdout}"
    );
}

#[test]
fn terraform_passes_aws_creds() {
    // terraform NEEDS AWS_* — they should NOT be scrubbed
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "terraform",
            "--quiet",
            "echo $AWS_REGION",
        ])
        .env("AWS_REGION", "us-east-1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("us-east-1"),
        "terraform: AWS_REGION should be passed through. Got: {stdout}"
    );
}

#[test]
fn terraform_network_blocked() {
    assert_network_blocked("terraform");
}

#[test]
fn terraform_profile_shows() {
    assert_profile_shows("terraform");
}

// ============================================================
// minimal profile
// ============================================================

#[test]
fn minimal_basic_command() {
    assert_sandboxed("minimal");
}

#[test]
fn minimal_env_scrubbed() {
    assert_env_scrubbed("minimal");
}

#[test]
fn minimal_filesystem_blocked() {
    assert_filesystem_blocked("minimal");
}

#[test]
fn minimal_network_fully_blocked() {
    // minimal blocks ALL network, not just unauthorized domains
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "minimal",
            "--quiet",
            "curl -m 5 -s http://example.com 2>&1 || echo BLOCKED",
        ])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("BLOCKED") || combined.contains("Could not resolve"),
        "minimal: ALL network should be blocked. Got: {combined}"
    );
}

#[test]
fn minimal_scrubs_more_patterns() {
    // minimal scrubs STRIPE_*, ANTHROPIC_*, OPENAI_* in addition to standard patterns
    let output = safe_shell_bin()
        .args([
            "exec",
            "--profile",
            "minimal",
            "--quiet",
            "echo $STRIPE_PUBLISHABLE_KEY",
        ])
        .env("STRIPE_PUBLISHABLE_KEY", "pk_live_abc123")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("pk_live_"),
        "minimal: STRIPE_* should be scrubbed. Got: {stdout}"
    );
}

#[test]
fn minimal_profile_shows() {
    assert_profile_shows("minimal");
}

// ============================================================
// Cross-profile: all profiles list correctly
// ============================================================

#[test]
fn all_profiles_listed() {
    let output = safe_shell_bin().args(["profiles"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in [
        "npm",
        "pip",
        "cargo",
        "go",
        "docker",
        "terraform",
        "minimal",
    ] {
        assert!(
            stdout.contains(name),
            "profiles list missing {name}. Got: {stdout}"
        );
    }
}
