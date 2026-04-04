# safe-shell-sandbox

OS-level isolation for [safe-shell](https://github.com/claudexai/safe-shell).

- macOS Seatbelt (`sandbox-exec`) filesystem isolation
- Domain-filtering HTTP proxy with HTTPS CONNECT tunnel support
- Kernel-enforced read blocking for sensitive paths
- Localhost port restriction (only proxy port allowed)

This is an internal crate. Install [safe-shell](https://crates.io/crates/safe-shell) for the CLI tool.
