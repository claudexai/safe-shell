use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "safe-shell")]
#[command(version)]
#[command(about = "Run any command in a secret-aware OS-level sandbox")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Execute a command inside the sandbox
    Exec(ExecArgs),
    /// List or inspect built-in profiles
    Profiles(ProfilesArgs),
    /// Generate shell hooks for automatic interception
    Hook(HookArgs),
    /// Activate automatic sandboxing for all package managers
    Shield,
    /// Deactivate automatic sandboxing
    Unshield,
    /// Show whether shield is active and what's being intercepted
    Status,
    /// Run a command without sandbox protection
    Bypass(BypassArgs),
}

#[derive(clap::Args)]
pub struct ExecArgs {
    /// Built-in profile to use (npm, pip, cargo, go, docker, terraform, minimal)
    #[arg(long)]
    pub profile: Option<String>,

    /// Show what would happen without executing
    #[arg(long)]
    pub dry_run: bool,

    /// Suppress status output (used by shield hooks)
    #[arg(long)]
    pub quiet: bool,

    /// Show detailed info: which secrets scrubbed, which paths blocked, then execute
    #[arg(long, short)]
    pub verbose: bool,

    /// Additional domains to allow network access to (repeatable)
    #[arg(long = "allow-net", value_name = "DOMAIN")]
    pub allow_net: Vec<String>,

    /// Additional environment variables to pass through (repeatable)
    #[arg(long = "allow-env", value_name = "VAR")]
    pub allow_env: Vec<String>,

    /// Additional paths to allow reading (repeatable)
    #[arg(long = "allow-read", value_name = "PATH")]
    pub allow_read: Vec<String>,

    /// Additional paths to allow writing (repeatable)
    #[arg(long = "allow-write", value_name = "PATH")]
    pub allow_write: Vec<String>,

    /// Additional paths to deny reading (repeatable)
    #[arg(long = "deny-read", value_name = "PATH")]
    pub deny_read: Vec<String>,

    /// Additional environment variable patterns to scrub (repeatable)
    #[arg(long = "scrub-env", value_name = "PATTERN")]
    pub scrub_env: Vec<String>,

    /// The command to execute
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

#[derive(clap::Args)]
pub struct ProfilesArgs {
    /// Show details of a specific profile
    #[arg(value_name = "NAME")]
    pub show: Option<String>,
}

#[derive(clap::Args)]
pub struct HookArgs {
    /// Shell type (zsh or bash)
    #[arg(value_name = "SHELL")]
    pub shell: String,
}

#[derive(clap::Args)]
pub struct BypassArgs {
    /// The command to run without sandbox
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}
