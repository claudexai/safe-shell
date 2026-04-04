# safe-shell-scanner

Secret detection engine for [safe-shell](https://github.com/claudexai/safe-shell).

- 27+ regex rules detecting AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, database URIs, and more
- Environment variable scrubbing by key patterns and value scanning
- Shannon entropy detection for high-entropy secrets
- Sensitive file path detection

This is an internal crate. Install [safe-shell](https://crates.io/crates/safe-shell) for the CLI tool.
