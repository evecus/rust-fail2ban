# rust-fail2ban

A lightweight **Fail2Ban-like** intrusion prevention tool written in pure Rust.

It monitors log files for failed authentication attempts (using configurable regular expressions), tracks failures per IP address, and automatically bans offenders by updating firewall rules (`iptables` / `nftables`) or simply logging the action in dummy mode.

## Features

- 🚀 **Async** log tailing with `tokio` + `notify`
- 📝 Multiple **jails** (like classic fail2ban)
- ⏱️ Configurable `maxretry`, `findtime`, `bantime`
- 🔥 Ban backends: `iptables`, `nftables`, or `dummy` (safe for testing)
- 🧹 Automatic unban when ban time expires
- 📦 Single static binary, easy to deploy

## Quick Start

```bash
# Clone
git clone https://github.com/evecus/rust-fail2ban.git
cd rust-fail2ban

# Build
cargo build --release

# Copy example config and edit
cp config.example.toml config.toml
# Edit log paths, regexes, backend, etc.

# Run (needs appropriate privileges for real ban backends)
./target/release/rust-fail2ban -c config.toml
```

### Dummy mode (recommended for testing)

In `config.toml`:

```toml
[global]
ban_backend = "dummy"
```

No root required — it only prints BAN / UNBAN messages.

## Configuration

See `config.example.toml`. Key sections:

```toml
[global]
cleanup_interval = 30          # seconds
ban_backend = "dummy"          # dummy | iptables | nftables

[[jails]]
name = "sshd"
enabled = true
logpath = "/var/log/auth.log"
failregex = '''(?i)Failed password for .* from (?P<ip>\S+) port \d+'''
maxretry = 5
findtime = 600                 # 10 minutes
bantime = 3600                 # 1 hour
port = "22"
protocol = "tcp"
```

The regex **must** capture the IP address either as named group `ip` or as the first capture group.

## Ban Backends

| Backend    | Requirements                          | Notes                                      |
|------------|---------------------------------------|--------------------------------------------|
| `dummy`    | none                                  | Safe for development / CI                  |
| `iptables` | root + `iptables` command             | Creates chain `f2b-<jail>`                 |
| `nftables` | root + `nft` + pre-created set        | Expects set `f2b-<jail>` in `inet filter` |

For `nftables` you need to prepare the set once:

```bash
nft add table inet filter
nft add set inet filter f2b-sshd '{ type ipv4_addr; }'
nft add rule inet filter input ip saddr @f2b-sshd drop
```

## GitHub Actions

The repository includes a CI workflow that:

- Builds on Ubuntu (stable + nightly)
- Runs `cargo check`, `cargo test`, `cargo clippy`
- Produces a release binary artifact

## License

MIT
