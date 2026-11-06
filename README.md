# rust-fail2ban

A lightweight **Fail2Ban-like** intrusion prevention tool written in pure Rust.

It monitors sshd logs for failed authentication attempts, tracks failures per IP address, and automatically bans offenders via `nftables` or `iptables` (log-only fallback when neither is available).

**Zero configuration** — there is no config file. Everything is detected automatically at startup.

## Features

- 🚀 **Async** log tailing with `tokio` + `notify`
- 🧠 **Fully automatic**: sshd ports, auth methods, failure patterns, log source and firewall backend are all auto-detected
- 💾 **Persistent state**: active bans and failure history are stored in a SQLite database, so **bans survive process restarts and reboots** (they are re-applied to the firewall on startup)
- 🔥 Ban backends: `nftables` (preferred), `iptables`/`ip6tables`, or log-only dummy mode
- 🧹 Automatic unban when the ban time expires
- 🛡️ Built-in whitelist (loopback + the client of the current SSH session)
- 📦 Single static binary, easy to deploy

## Quick Start

```bash
git clone https://github.com/evecus/rust-fail2ban.git
cd rust-fail2ban
cargo build --release

# Run (root is required for real firewall backends)
sudo ./target/release/rust-fail2ban
```

That's it. Useful flags:

| Flag | Description |
|------|-------------|
| `-v` / `-vv` | Verbose (debug / trace) logging |
| `--detect` | Print what would be detected (sshd settings, log source, firewall backend) and exit |

## Persistence

All state is written immediately to `/etc/rust-fail2ban/rust-fail2ban.db` (SQLite, WAL mode):

- every **ban** (ip, banned-at, bantime)
- every **failure record** within the findtime window

On startup the program loads the database, prunes expired entries and **re-applies every unexpired ban to the firewall**, so restarting the daemon — or rebooting the whole machine — does not unban anyone. Whitelisted addresses are never restored.

Default policy: **5 failures within 600 s → 3600 s ban**.

## Detection Details

| What | How |
|------|-----|
| sshd ports & auth methods | `sshd -T`, falling back to parsing `/etc/ssh/sshd_config` (+ `Include` files) |
| Failure patterns | Derived from the enabled auth methods (password / keyboard-interactive / publickey) plus connection-level signals (`Invalid user`, pre-auth disconnect, max-auth-exceeded) |
| Log source | systemd journal (`journalctl -f -t sshd`) if available, else `/var/log/auth.log` or `/var/log/secure` (rotation/truncation handled) |
| Firewall | `nftables` (own table `inet rust_fail2ban`), else `iptables` + `ip6tables` (own chain `rust-f2b`), else log-only mode |
| Whitelist | `127.0.0.0/8`, `::1`, plus the client IP of the current SSH session (so you never lock yourself out) |

## systemd

```ini
[Unit]
Description=rust-fail2ban SSH brute-force protection
After=network.target

[Service]
ExecStart=/usr/local/bin/rust-fail2ban
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

On graceful shutdown the firewall rules are removed, but the bans stay in the database and are re-applied within milliseconds of the next start.

## GitHub Actions

The repository includes a CI workflow that builds on Ubuntu (stable + nightly), runs `cargo check` / `cargo test` / `cargo clippy`, and produces a release binary artifact.

## License

MIT
