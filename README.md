# safe-shell

Run any command in a secret-aware OS-level sandbox. Protects against supply chain attacks like the [axios npm compromise](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html) (March 30, 2026) where a malicious postinstall hook stole credentials, read sensitive files, and phoned home to a C&C server.

![safe-shell demo](https://raw.githubusercontent.com/claudexai/safe-shell/main/demo/demo.gif)

## The axios attack would have failed

On March 30, 2026, axios (100M+ weekly downloads) was compromised. A phantom dependency injected a postinstall hook that:

| Attack step | Without safe-shell | With safe-shell |
|---|---|---|
| Read `process.env` for API keys | All secrets exposed | **Scrubbed** — env vars removed before process spawns |
| Read `~/.aws/credentials` | All AWS keys stolen | **Blocked** — Seatbelt denies at kernel level |
| Read `~/.ssh/id_rsa` | Private key stolen | **Blocked** — kernel enforced |
| Connect to C&C server | Data exfiltrated | **Blocked** — domain not in allowlist |
| Download RAT payload | Malware installed | **Blocked** — network filtered |
| Write to `/Library/Caches` | Persistence achieved | **Blocked** — writes restricted |

## How it works

Three protection layers, all enforced at the OS level:

| Layer | What it does | Enforced by |
|---|---|---|
| **Env scrubbing** | Removes secret values from env vars before the process spawns. Pattern matching on keys (`*_KEY`, `*_SECRET`, `*_TOKEN`) AND content scanning on values (27+ regex rules). | sf-core scanner |
| **Filesystem isolation** | Kernel blocks reads to `~/.aws`, `~/.ssh`, `~/.gnupg`, `.env`, and other sensitive paths. | macOS Seatbelt |
| **Network filtering** | Local proxy filters by domain. npm can reach `registry.npmjs.org` but nothing else. HTTP, HTTPS, raw TCP — all blocked except the allowlist. | Domain-filtering proxy + Seatbelt |

## Quick start

```bash
cargo install safe-shell
```

### Shield — automatic protection (recommended)

One command. Done forever.

```bash
safe-shell shield
source ~/.zshrc   # or restart your terminal
```

From now on, every `npm install`, `pip install`, `cargo build` is automatically sandboxed. You never type `safe-shell` again:

```
$ npm install express
🛡 safe-shell: npm profile active (env scrubbed, fs restricted, network filtered)
🔒 safe-shell: 12 secret env vars removed (ARM_CLIENT_KEY, CLIENT_KEY, ... +9 more)

added 65 packages in 2.1s

🛡 safe-shell: session complete — 12 env secrets scrubbed, 0 file reads blocked, 0 network requests blocked
```

When something is blocked, you see it:

```
$ npm install malicious-package
🛡 safe-shell: npm profile active (env scrubbed, fs restricted, network filtered)
🔒 safe-shell: 15 secret env vars removed (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, ... +12 more)

⚠ safe-shell: blocked file read: /Users/you/.aws/credentials
⚠ safe-shell: blocked network: sfrclak.com

🛡 safe-shell: session complete — 15 env secrets scrubbed, 1 file reads blocked, 1 network requests blocked
```

The shield only sandboxes dangerous subcommands. Safe commands pass through with zero overhead:

| Command | Sandboxed subcommands | Not sandboxed (no overhead) |
|---|---|---|
| `npm` | install, ci, run, exec, test | --version, list, help |
| `npx` | all | — |
| `pip` / `pip3` | install | list, show, freeze |
| `cargo` | build, run, test, install | check, --version |
| `go` | build, run, test, install, get | fmt, vet, version |
| `docker` | build, run | pull, push, inspect |
| `terraform` | init, plan, apply | validate, fmt |

**Manage shield:**

```bash
safe-shell status      # Show what's being intercepted
safe-shell unshield    # Deactivate — removes hooks from ~/.zshrc, restores original behavior
```

**Bypass when needed:**

```bash
SAFE_SHELL_BYPASS=1 npm install    # Skip sandbox for one command
safe-shell bypass npm install      # Same thing, explicit
```

### Manual mode

If you prefer explicit control per command:

```bash
safe-shell exec --profile npm "npm install express"
safe-shell exec --profile pip "pip install requests"
safe-shell exec --profile cargo "cargo build"
safe-shell exec --profile minimal "bash untrusted-script.sh"
```

## Built-in profiles

| Profile | Network allowed | Use case |
|---|---|---|
| `npm` | registry.npmjs.org, github.com | `npm install`, `npm run`, `npm test` |
| `pip` | pypi.org, files.pythonhosted.org | `pip install` |
| `cargo` | crates.io, github.com | `cargo build`, `cargo test` |
| `go` | proxy.golang.org, github.com | `go build`, `go test` |
| `docker` | registry-1.docker.io, github.com | `docker build`, `docker run` |
| `terraform` | registry.terraform.io, AWS/GCP/Azure | `terraform init`, `terraform plan` |
| `minimal` | **none** (all blocked) | Maximum isolation for untrusted scripts |

View profile details:

```
$ safe-shell profiles npm

  npm - Node.js package manager — install, build, test

  Network (5): registry.npmjs.org, *.npmjs.org, github.com, *.githubusercontent.com,
               *.github.com
  Writable (6): ./node_modules, ./package-lock.json, ./yarn.lock, ./pnpm-lock.yaml, /tmp,
                ~/.npm
  Blocked (17): ~/.aws, ~/.ssh, ~/.gnupg, ~/.config/gcloud, ~/.azure, ~/.docker, ~/.kube,
                .env, .env.*, *.pem, *.key, *.p12, *.pfx, *.tfvars, *.tfstate,
                credentials.json, secrets.*
  Scrub (8): *_KEY, *_SECRET, *_TOKEN, *_PASSWORD, *_CREDENTIAL, DATABASE_URL, MONGO*_URI,
             REDIS_URL
  Pass (14): PATH, HOME, USER, SHELL, TERM, LANG, LC_*, NODE_ENV, NODE_*, npm_config_*,
             NPM_CONFIG_*, CI, GITHUB_ACTIONS, RUNNER_*
```

## Compared to alternatives

| Tool | Env protection | FS isolation | Network filtering | Profiles | Auto-intercept | Platform |
|---|---|---|---|---|---|---|
| **safe-shell** | Pattern + content scan (27+ rules) | Kernel (Seatbelt) | Domain-level (proxy) | 7 built-in (npm, pip, cargo...) | Yes (`shield`) | macOS (Linux planned) |
| **Anthropic srt** | None | Kernel (Seatbelt/bwrap) | Domain-level (proxy) | None | No | macOS + Linux |
| **Deno** | Per-variable allowlist | Per-path allowlist | Per-domain allowlist | None | No | Cross-platform (JS/TS only) |
| **bubblewrap** | Blanket wipe (`--clearenv`) | Kernel (namespaces) | All-or-nothing (`--unshare-net`) | None | No | Linux only |
| **firejail** | None | Kernel (namespaces) | All-or-nothing (`--net=none`) | 1000+ (desktop apps, not pkg managers) | No | Linux only |
| **Docker** | Manual (`-e` flags) | Container | Configurable (not domain-level) | None | No | Cross-platform (needs daemon) |
| **LavaMoat** | None | None (JS runtime only) | None | Per-package policy | Partial (`allow-scripts`) | Node.js only |
| `--ignore-scripts` | None | None | None | None | No | Any |

**Notes:**
- Deno's sandbox is bypassed when spawning subprocesses (`--allow-run`). A malicious npm postinstall hook runs as a subprocess, not inside Deno's sandbox.
- Firejail's 1000+ profiles target desktop applications (Firefox, VLC, Chromium), not package managers. There are no built-in profiles for npm, pip, or cargo.
- Anthropic srt was built for Claude Code's bash tool. It can sandbox any command but has no package-manager-specific defaults.
- `--ignore-scripts` blocks postinstall hooks but breaks packages that need them (sqlite3, bcrypt, sharp, node-gyp, etc.). safe-shell lets postinstall run — it just can't steal anything. See below.

### Why not just `--ignore-scripts`?

`--ignore-scripts` breaks packages that need postinstall to compile native bindings:

```
$ npm install sqlite3 --ignore-scripts
$ node -e "require('sqlite3')"
Error: Could not locate the bindings file.
 → node_modules/sqlite3/build/Release/node_sqlite3.node
 → node_modules/sqlite3/compiled/22.14.0/darwin/arm64/node_sqlite3.node
 ...13 paths tried, none found
```

safe-shell lets postinstall run — it just can't steal anything:

```
$ safe-shell exec --profile npm "npm install sqlite3"
🛡 safe-shell: npm profile active (env scrubbed, fs restricted, network filtered)

added 104 packages in 8s

$ node -e "require('sqlite3'); console.log('sqlite3 loaded successfully')"
sqlite3 loaded successfully
```

`--ignore-scripts` disables functionality. safe-shell contains it. The postinstall hook runs, native bindings compile, npm works — but secrets are scrubbed, sensitive files are blocked, and unauthorized network is filtered.

## CLI reference

```bash
safe-shell exec --profile <PROFILE> "<command>"
```

| Flag | Description |
|---|---|
| `--profile <name>` | Profile: npm, pip, cargo, go, docker, terraform, minimal |
| `--dry-run` | Show what would happen without executing |
| `-v, --verbose` | Show detailed scrub/block info, then execute |
| `--quiet` | Suppress all safe-shell output |
| `--allow-net <domain>` | Add allowed network domain (repeatable) |
| `--allow-env <var>` | Pass through an env var (repeatable) |
| `--allow-read <path>` | Remove path from deny list (repeatable) |
| `--allow-write <path>` | Add writable path (repeatable) |
| `--deny-read <path>` | Block additional path (repeatable) |
| `--scrub-env <pattern>` | Add scrub pattern (repeatable) |

**Examples:**

```bash
# Add a custom registry
safe-shell exec --profile npm --allow-net "npm.company.com" "npm install"

# Pass through a token for publishing
safe-shell exec --profile npm --allow-env "NPM_TOKEN" "npm publish"

# See what would happen
safe-shell exec --profile npm --dry-run "npm install"

# Verbose — see every scrubbed var and blocked path
safe-shell exec --profile npm -v "npm install"

# Block an extra path
safe-shell exec --profile npm --deny-read "~/.config" "npm install"

# Maximum isolation
safe-shell exec --profile minimal "bash untrusted-script.sh"
```

## Custom profiles

Create `~/.config/safe-shell/profiles.toml`:

```toml
[company-npm]
description = "npm with internal company registry"

network.allow = [
  "registry.npmjs.org",
  "*.npmjs.org",
  "npm.company-internal.com",
]

filesystem.allow_write = ["./node_modules", "./package-lock.json", "/tmp", "~/.npm"]
filesystem.deny_read = ["~/.aws", "~/.ssh", "~/.gnupg", "~/.docker", ".env"]

env.scrub = ["*_KEY", "*_SECRET", "*_TOKEN", "*_PASSWORD"]
env.pass = ["PATH", "HOME", "USER", "SHELL", "TERM", "NODE_*", "NPM_TOKEN", "MY_REGISTRY_TOKEN", "CI"]
```

Use it:

```bash
safe-shell exec --profile company-npm "npm install"
```

Custom profiles appear in `safe-shell profiles`. Built-in profile definitions cannot be modified, but you can change which profile a command uses via [shield aliases](#shield-aliases).

## Shield aliases

Add custom commands to shield and override built-in profile mappings via `~/.config/safe-shell/config.toml`:

```toml
[shield.aliases]
# Override built-in — use company profile with custom subcommands
npm = { profile = "company-npm", subcommands = ["install", "ci", "run", "exec", "test", "publish"] }

# Map new commands to built-in profiles with selective subcommands
bun = { profile = "npm", subcommands = ["install", "run", "test", "add"] }
pnpm = { profile = "npm", subcommands = ["install", "run", "test", "add"] }
yarn = { profile = "npm", subcommands = ["install", "run", "test", "add"] }
poetry = { profile = "pip", subcommands = ["install", "add", "update"] }

# Simple format — sandbox all subcommands
mycli = "minimal"
```

Two formats:
- **Simple:** `bun = "npm"` — sandbox all subcommands (safe default for unknown tools)
- **Detailed:** `bun = { profile = "npm", subcommands = ["install", "run"] }` — sandbox only specific subcommands

After editing config, reload:

```bash
safe-shell shield      # re-generates hooks
source ~/.zshrc        # load them
safe-shell status      # verify
```

```
$ safe-shell status

  Intercepted commands:
    bun       → npm (custom)            install, run, test, add
    cargo     → cargo                   build, run, test, install
    docker    → docker                  build, run
    go        → go                      build, run, test, install, get
    npm       → company-npm (override)  install, ci, run, exec, test, publish
    npx       → npm                     all subcommands
    pip       → pip                     install
    pip3      → pip                     install
    pnpm      → npm (custom)            install, run, test, add
    poetry    → pip (custom)            install, add, update
    terraform → terraform               init, plan, apply
    yarn      → npm (custom)            install, run, test, add
```

**What changes need reload:**
- Add/remove aliases or change subcommands in `config.toml` → `safe-shell shield && source ~/.zshrc`

**What takes effect immediately (no reload):**
- Edit profile content in `profiles.toml` (network, scrub, pass patterns)
- Edit project config `safe-shell.toml`
- CLI flags (`--allow-net`, `--allow-env`)

## Malicious repos can't weaken your sandbox

Project-level config files (`safe-shell.toml`) use **restrictive merge only**. They can add restrictions but never relax them.

A malicious repo ships this `safe-shell.toml`:
```toml
[network]
allow = ["evil.com"]          # ← IGNORED

[env]
pass = ["*_SECRET", "AWS_*"]  # ← IGNORED

[filesystem]
allow_write = ["~/.ssh"]      # ← IGNORED
```

**None of it works.** Project configs can only:
- Add more `deny_read` paths (tighten filesystem)
- Add more `scrub` patterns (tighten env scrubbing)

They cannot add allowed domains, add writable paths, or pass through secrets. Relaxing the sandbox requires an explicit CLI flag (`--allow-net`, `--allow-env`) that you type yourself.

## Security model

| Attack vector | Protection | Enforced by |
|---|---|---|
| `process.env` secrets | Scrubbed before process spawns | sf-core scanner (27+ regex rules) |
| `~/.aws/credentials` | Read blocked | macOS Seatbelt (kernel) |
| `~/.ssh/id_rsa` | Read blocked | macOS Seatbelt (kernel) |
| Symlink to `~/.aws` | Resolved and blocked | Seatbelt resolves real path |
| Path traversal `../../.aws` | Resolved and blocked | Seatbelt canonicalizes |
| `curl evil.com` | Blocked by proxy | Domain-filtering HTTP proxy |
| `curl --noproxy '*'` | Blocked by Seatbelt | Kernel blocks non-localhost outbound |
| Raw TCP (`nc evil.com`) | Blocked by Seatbelt | Kernel blocks outbound |
| Reverse shell (`/dev/tcp`) | Blocked by Seatbelt | Kernel blocks outbound |
| `NO_PROXY` bypass | Stripped from env | Explicitly removed before sandbox |
| Access `localhost:5432` | Blocked by Seatbelt | Only proxy port allowed on localhost |
| Malicious `safe-shell.toml` | Restrictive merge only | Cannot add domains or passthroughs |
| Shell injection via args | Preserved argv boundaries | `exec "$@"` instead of string join |

### Secret detection rules (27+)

| Category | Patterns detected |
|---|---|
| AWS | Access keys (`AKIA*`), secret keys, session tokens |
| AI | Anthropic (`sk-ant-*`), OpenAI (`sk-*`, `sk-proj-*`) |
| Code hosting | GitHub PAT/OAuth/fine-grained, GitLab PAT |
| Payment | Stripe secret/restricted keys |
| Auth | JWT tokens, bearer tokens |
| Private keys | RSA, EC, PKCS8, OpenSSH |
| Databases | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| Communication | Slack tokens/webhooks, Discord bot tokens |
| SaaS | SendGrid, HashiCorp Vault tokens |
| Generic | Password assignments (`password=`, `pwd:`) |

## Demo

Run the axios attack simulation with fake credentials:

```bash
# One-time setup (creates fake credentials at /tmp/safe-shell-demo)
bash demo/setup-fake-home.sh

# Run the before/after comparison
bash demo/run-demo.sh
```

**Before** — without safe-shell, all attack steps succeed:
- Environment secrets stolen
- AWS credentials read from disk
- SSH private key read
- Data exfiltrated to C&C server
- Persistent RAT installed

**After** — with safe-shell, all attack steps blocked:
- Environment secrets scrubbed
- File reads denied by kernel
- Network requests blocked by proxy
- Persistence write blocked by kernel

## Known limitations

1. **macOS only** — v0.1.0 uses Apple's Seatbelt (`sandbox-exec`). Linux support via Landlock + bubblewrap and Windows support are planned.

2. **Glob patterns in deny_read** (`*.pem`, `*.key`, `.env.*`) are not enforced by Seatbelt — it can't match by file extension. These files are readable in the project directory, but the attacker can't exfiltrate them (network is filtered).

3. **Project directory is always writable** — package managers need to write to `./node_modules`, `./target`, etc. A malicious script can modify project files, but writes are contained to the project dir (no system access), and the next run is also sandboxed by shield.

4. **Pass-through env patterns** (`NODE_*`, `CARGO_*`) bypass value scanning — needed because npm/cargo break without these variables. Use `--scrub-env` to explicitly scrub specific variables if needed.

## Development

```bash
git clone https://github.com/claudexai/safe-shell
cd safe-shell
cargo build
cargo test          # 306 tests
cargo clippy        # lint
cargo fmt --check   # format check
```

### Project structure

```
safe-shell/
├── crates/
│   ├── scanner/        # safe-shell-scanner — secret detection, env scrubbing
│   ├── sandbox/        # safe-shell-sandbox — Seatbelt, proxy, OS isolation
│   └── shell/          # safe-shell — CLI binary
├── profiles/           # Built-in TOML profiles (embedded in binary)
├── demo/               # Attack simulation scripts
└── .github/workflows/  # CI pipeline
```

## License

MIT
