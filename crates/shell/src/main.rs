mod cli;
mod hook;
mod profiles;

use std::process;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Exec(args) => run_exec(args),
        Commands::Profiles(args) => run_profiles(args),
        Commands::Hook(args) => run_hook(args),
        Commands::Shield => run_shield(),
        Commands::Unshield => run_unshield(),
        Commands::Status => run_status(),
        Commands::Bypass(args) => run_bypass(args),
    };

    match result {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("[safe-shell] Error: {e}");
            process::exit(3);
        }
    }
}

fn run_exec(args: cli::ExecArgs) -> Result<i32, Box<dyn std::error::Error>> {
    // Load and merge profile
    let profile = profiles::load_merged_profile(
        args.profile.as_deref(),
        &args.allow_net,
        &args.allow_env,
        &args.allow_read,
        &args.allow_write,
        &args.deny_read,
        &args.scrub_env,
    )?;

    let command_display = args.command.join(" ");

    if args.dry_run {
        print_dry_run(&command_display, args.profile.as_deref(), &profile);
        return Ok(0);
    }

    // Scrub environment and execute
    let env_config = profile.env.as_ref();
    let scrub_patterns = env_config.map(|e| e.scrub.as_slice()).unwrap_or(&[]);
    let pass_patterns = env_config.map(|e| e.pass.as_slice()).unwrap_or(&[]);

    let scanner = safe_shell_scanner::Scanner::new();
    let current_env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let clean_env =
        safe_shell_scanner::scrub_env(&current_env, scrub_patterns, pass_patterns, &scanner);

    let scrubbed_count = current_env.len() - clean_env.len();

    // Build full sandbox config
    let fs_config = profile.filesystem.as_ref();
    let net_config = profile.network.as_ref();

    let sandbox_config = safe_shell_sandbox::SandboxConfig {
        command: args.command.clone(),
        env: clean_env,
        cwd: std::env::current_dir()?,
        allow_write: fs_config.map(|f| f.allow_write.clone()).unwrap_or_default(),
        deny_read: fs_config.map(|f| f.deny_read.clone()).unwrap_or_default(),
        network_allow: net_config.map(|n| n.allow.clone()).unwrap_or_default(),
        quiet: args.quiet,
    };

    // Split deny_read into enforced (Seatbelt) and unenforced (globs)
    let deny_read = fs_config.map(|f| f.deny_read.clone()).unwrap_or_default();
    let enforced_paths: Vec<&String> = deny_read.iter().filter(|p| !p.contains('*')).collect();
    let enforced_count = enforced_paths.len();

    // Compute scrubbed keys for display
    let mut scrubbed_keys: Vec<&String> = current_env
        .keys()
        .filter(|k| !sandbox_config.env.contains_key(*k))
        .collect();
    scrubbed_keys.sort();

    // Determine network posture label
    let net_allow = net_config.map(|n| &n.allow).cloned().unwrap_or_default();
    let net_label = if net_allow.is_empty() {
        "network blocked"
    } else if net_allow.iter().any(|d| d == "*") {
        "network open"
    } else {
        "network filtered"
    };

    // Show status
    if !args.quiet {
        let profile_label = args.profile.as_deref().unwrap_or("default");
        eprintln!(
            "\x1b[36m\u{1f6e1}\x1b[0m safe-shell: {profile_label} profile active (env scrubbed, fs restricted, {net_label})"
        );

        // Show scrubbed env vars summary
        if !scrubbed_keys.is_empty() {
            let preview: Vec<&str> = scrubbed_keys.iter().take(3).map(|s| s.as_str()).collect();
            let suffix = if scrubbed_keys.len() > 3 {
                format!(", ... +{} more", scrubbed_keys.len() - 3)
            } else {
                String::new()
            };
            eprintln!(
                "\x1b[32m\u{1f512}\x1b[0m safe-shell: {} secret env vars removed ({}{})",
                scrubbed_keys.len(),
                preview.join(", "),
                suffix
            );
        }
    }

    if args.verbose {
        // Verbose: show full details
        if scrubbed_keys.is_empty() {
            eprintln!("  Env: no secrets found");
        } else {
            eprintln!("  Env scrubbed ({scrubbed_count}):");
            for key in &scrubbed_keys {
                eprintln!("    - {key}");
            }
        }

        if enforced_paths.is_empty() {
            eprintln!("  Filesystem: no paths restricted");
        } else {
            eprintln!("  Filesystem restricted ({enforced_count}):");
            for path in &enforced_paths {
                eprintln!("    - {path}");
            }
        }

        if net_allow.is_empty() {
            eprintln!("  Network: all outbound blocked");
        } else {
            eprintln!("  Network allowed:");
            for domain in &net_allow {
                eprintln!("    - {domain}");
            }
        }
    }

    if !args.quiet {
        eprintln!();
    }

    let result = safe_shell_sandbox::execute_with_config(&sandbox_config)?;

    // Session summary
    if !args.quiet {
        eprintln!(
            "\x1b[36m\u{1f6e1}\x1b[0m safe-shell: session complete — {} env secrets scrubbed, {} file reads blocked, {} network requests blocked",
            scrubbed_count,
            result.file_reads_blocked,
            result.network_requests_blocked,
        );
    }

    Ok(result.status.code().unwrap_or(1))
}

fn run_profiles(args: cli::ProfilesArgs) -> Result<i32, Box<dyn std::error::Error>> {
    match args.show {
        Some(name) => {
            let profile = profiles::load_builtin(&name)?;
            print_profile_details(&name, &profile);
        }
        None => {
            print_profile_list();
        }
    }
    Ok(0)
}

fn print_profile_list() {
    println!("Built-in profiles:\n");
    for (name, desc) in profiles::list_builtin_profiles() {
        println!("  {:<12} {}", name, desc);
    }

    let custom = profiles::list_custom_profiles();
    if !custom.is_empty() {
        println!("\nCustom profiles (~/.config/safe-shell/profiles.toml):\n");
        for (name, desc) in &custom {
            println!("  {:<12} {}", name, desc);
        }
    }

    println!("\nUsage: safe-shell exec --profile <NAME> \"<command>\"");
    println!("Details: safe-shell profiles <NAME>");
}

fn print_profile_details(name: &str, profile: &safe_shell_scanner::config::Profile) {
    println!();
    if let Some(ref meta) = profile.meta {
        if let Some(ref desc) = meta.description {
            println!("  {name} - {desc}");
        } else {
            println!("  {name}");
        }
    } else {
        println!("  {name}");
    }
    println!();

    if let Some(ref net) = profile.network {
        if net.allow.is_empty() {
            println!("  Network:     all blocked");
        } else {
            print_wrapped("Network", &net.allow);
        }
    }

    if let Some(ref fs) = profile.filesystem {
        if !fs.allow_write.is_empty() {
            print_wrapped("Writable", &fs.allow_write);
        }
        if !fs.deny_read.is_empty() {
            print_wrapped("Blocked", &fs.deny_read);
        }
    }

    if let Some(ref env) = profile.env {
        if !env.scrub.is_empty() {
            print_wrapped("Scrub", &env.scrub);
        }
        if !env.pass.is_empty() {
            print_wrapped("Pass", &env.pass);
        }
    }

    println!();
}

/// Print a labeled list with count, wrapping long lines with indent.
fn print_wrapped(label: &str, items: &[String]) {
    let count = items.len();
    let prefix = format!("  {label} ({count}): ");
    let indent = " ".repeat(prefix.len());
    let max_width = 90;

    print!("{prefix}");

    let mut line_len = prefix.len();
    for (i, item) in items.iter().enumerate() {
        let separator = if i > 0 { ", " } else { "" };
        let addition = format!("{separator}{item}");

        if line_len + addition.len() > max_width && i > 0 {
            println!(",");
            print!("{indent}");
            line_len = indent.len();
            print!("{item}");
            line_len += item.len();
        } else {
            print!("{addition}");
            line_len += addition.len();
        }
    }
    println!();
}

fn print_dry_run(
    command: &str,
    profile_name: Option<&str>,
    profile: &safe_shell_scanner::config::Profile,
) {
    println!("safe-shell dry run:");
    println!("  Command: {command}");
    if let Some(name) = profile_name {
        println!("  Profile: {name}");
    }
    println!();

    // Environment
    let env_config = profile.env.as_ref();
    let scrub_patterns = env_config.map(|e| e.scrub.as_slice()).unwrap_or(&[]);
    let pass_patterns = env_config.map(|e| e.pass.as_slice()).unwrap_or(&[]);

    let scanner = safe_shell_scanner::Scanner::new();
    let current_env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let clean_env =
        safe_shell_scanner::scrub_env(&current_env, scrub_patterns, pass_patterns, &scanner);

    let scrubbed_count = current_env.len() - clean_env.len();
    let scrubbed_keys: Vec<&String> = current_env
        .keys()
        .filter(|k| !clean_env.contains_key(*k))
        .collect();

    println!("  Environment:");
    println!(
        "    Scrubbed ({scrubbed_count} vars): {}",
        if scrubbed_keys.is_empty() {
            "(none)".to_string()
        } else {
            scrubbed_keys
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!("    Passed through ({} vars): {}", clean_env.len(), {
        let mut keys: Vec<&String> = clean_env.keys().collect();
        keys.sort();
        keys.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    });
    println!();

    // Filesystem
    if let Some(ref fs) = profile.filesystem {
        println!("  Filesystem:");
        println!(
            "    Writable: {}",
            if fs.allow_write.is_empty() {
                "(none)".to_string()
            } else {
                fs.allow_write.join(", ")
            }
        );
        println!(
            "    Blocked reads: {} ({} patterns)",
            fs.deny_read.join(", "),
            fs.deny_read.len()
        );
        println!();
    }

    // Network
    if let Some(ref net) = profile.network {
        println!("  Network:");
        if net.allow.is_empty() {
            println!("    Allowed: (none — all outbound blocked)");
        } else {
            println!("    Allowed: {}", net.allow.join(", "));
        }
        println!("    Everything else: BLOCKED");
        println!();
    }

    // Platform
    println!(
        "  Platform: {}",
        if cfg!(target_os = "macos") {
            "macOS (Seatbelt)"
        } else {
            "unsupported"
        }
    );
}

fn run_hook(args: cli::HookArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let output = hook::generate_hook(&args.shell)?;
    print!("{output}");
    Ok(0)
}

fn run_shield() -> Result<i32, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let (shell_name, config_path) = if shell.contains("zsh") {
        ("zsh", home.join(".zshrc"))
    } else {
        ("bash", home.join(".bashrc"))
    };

    // Generate hooks with config aliases
    let (_, warnings) = hook::generate_hook_with_warnings(shell_name)?;

    // Show warnings for invalid profiles
    for w in &warnings {
        eprintln!("\x1b[33m\u{26a0}\x1b[0m safe-shell: {w}");
    }

    let eval_line = hook::hook_eval_line(shell_name);

    // Remove old hooks if present (idempotent re-run)
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        if hook::is_hook_installed(&content) {
            let cleaned = remove_between_markers(&content);
            // Also remove the old eval line
            let cleaned: String = cleaned
                .lines()
                .filter(|line| {
                    !line.contains("safe-shell hook")
                        && !line.contains("safe-shell: automatic sandbox")
                })
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(&config_path, cleaned)?;
        }
    }

    // Append the eval line
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config_path)?;
    use std::io::Write;
    writeln!(file)?;
    writeln!(file, "# safe-shell: automatic sandbox for package managers")?;
    writeln!(file, "{eval_line}")?;

    // Print summary
    let (mappings, _) = profiles::load_shield_mappings();
    println!("safe-shell shield activated.");
    println!();
    print_shield_summary(&mappings);
    println!();
    println!(
        "  Restart your shell or run: source {}",
        config_path.display()
    );
    println!("  Bypass: SAFE_SHELL_BYPASS=1 <command>");

    Ok(0)
}

fn print_shield_summary(mappings: &[profiles::ShieldMapping]) {
    println!("  Intercepted commands:");

    // Calculate column widths
    let cmd_width = mappings.iter().map(|m| m.command.len()).max().unwrap_or(8);
    let profile_width = mappings
        .iter()
        .map(|m| {
            let label = match m.source {
                profiles::ShieldMappingSource::Builtin => "",
                profiles::ShieldMappingSource::Override => " (override)",
                profiles::ShieldMappingSource::Custom => " (custom)",
            };
            m.profile.len() + label.len()
        })
        .max()
        .unwrap_or(10);

    for m in mappings {
        let subcmd_info = match &m.subcommands {
            Some(cmds) => cmds.join(", "),
            None => "all subcommands".to_string(),
        };
        let source_label = match m.source {
            profiles::ShieldMappingSource::Builtin => "",
            profiles::ShieldMappingSource::Override => " (override)",
            profiles::ShieldMappingSource::Custom => " (custom)",
        };
        let profile_col = format!("{}{}", m.profile, source_label);
        println!(
            "    {:<cw$} → {:<pw$}  {}",
            m.command,
            profile_col,
            subcmd_info,
            cw = cmd_width,
            pw = profile_width
        );
    }
}

/// Remove content between marker comments.
fn remove_between_markers(content: &str) -> String {
    let start_marker = "# --- safe-shell shield hooks (do not edit) ---";
    let end_marker = "# --- end safe-shell shield hooks ---";

    let mut result = String::new();
    let mut inside_markers = false;

    for line in content.lines() {
        if line.contains(start_marker) {
            inside_markers = true;
            continue;
        }
        if line.contains(end_marker) {
            inside_markers = false;
            continue;
        }
        if !inside_markers {
            result.push_str(line);
            result.push('\n');
        }
    }

    result
}

fn run_unshield() -> Result<i32, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let config_path = if shell.contains("zsh") {
        home.join(".zshrc")
    } else {
        home.join(".bashrc")
    };

    if !config_path.exists() {
        println!("safe-shell shield is not active.");
        return Ok(0);
    }

    let content = std::fs::read_to_string(&config_path)?;
    if !hook::is_hook_installed(&content) {
        println!("safe-shell shield is not active.");
        return Ok(0);
    }

    // Remove marker-bounded hooks AND the eval/source lines
    let cleaned = remove_between_markers(&content);
    let cleaned: String = cleaned
        .lines()
        .filter(|line| {
            !line.contains("safe-shell hook") && !line.contains("safe-shell: automatic sandbox")
        })
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&config_path, cleaned)?;

    println!("safe-shell shield deactivated.");
    println!("  Removed from {}", config_path.display());
    println!(
        "  Restart your shell or run: source {}",
        config_path.display()
    );

    Ok(0)
}

fn run_status() -> Result<i32, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let config_path = if shell.contains("zsh") {
        home.join(".zshrc")
    } else {
        home.join(".bashrc")
    };

    let active = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        hook::is_hook_installed(&content)
    } else {
        false
    };

    if active {
        println!("safe-shell shield: active");
        println!();
        let (mappings, _) = profiles::load_shield_mappings();
        print_shield_summary(&mappings);
        println!();
        println!("  Bypass: SAFE_SHELL_BYPASS=1 <command>");
        println!("  Disable: safe-shell unshield");
    } else {
        println!("safe-shell shield: inactive");
        println!();
        println!("  Run `safe-shell shield` to activate automatic sandboxing.");
    }

    Ok(0)
}

fn run_bypass(args: cli::BypassArgs) -> Result<i32, Box<dyn std::error::Error>> {
    eprintln!("\x1b[33m\u{26a0}\x1b[0m safe-shell: running without sandbox protection");

    let command = args.command.join(" ");
    let status = std::process::Command::new("bash")
        .arg("-c")
        .arg(&command)
        .env("SAFE_SHELL_BYPASS", "1")
        .status()
        .map_err(|e| format!("Failed to execute: {e}"))?;

    Ok(status.code().unwrap_or(1))
}
