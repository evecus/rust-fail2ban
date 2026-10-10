//! rust-fail2ban — zero-config SSH brute-force protection (fail2ban-like).
//!
//! Everything is detected automatically:
//!   * sshd port(s), password / keyboard-interactive / public-key auth
//!     (via `sshd -T`, falling back to parsing sshd_config + Include files)
//!   * which failure patterns to watch (derived from the auth methods)
//!   * where to read logs from (systemd journal or /var/log/auth.log|secure)
//!   * which firewall to use (nftables or iptables/ip6tables)
//!
//! No `[[jails]]` are needed; only optional global tunables remain.

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::Deserialize;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

// ───────────────────────────── CLI & config ─────────────────────────────

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(
    name = "rust-fail2ban",
    about = "Zero-config SSH brute-force protection (fail2ban-like)"
)]
struct Args {
    /// Optional config file. Default: ./config.toml, then
    /// /etc/rust-fail2ban/config.toml, otherwise built-in defaults.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Increase verbosity (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Detect the environment, print what would be used, then exit
    #[arg(long)]
    detect: bool,
}

/// Global (and only) configuration section. Every field is optional.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
struct GlobalConfig {
    /// How often to check for expired bans (seconds)
    cleanup_interval: u64,
    /// auto | nftables | iptables | dummy
    ban_backend: String,
    /// auto | journal | file
    log_source: String,
    /// Log file to tail (implies file mode when log_source = "auto")
    logpath: Option<String>,
    /// sshd configuration file used for detection
    sshd_config: String,
    /// Override detected SSH ports (empty = auto)
    ports: Vec<u16>,
    /// Failures within `findtime` that trigger a ban
    maxretry: u32,
    /// Window for counting failures (seconds)
    findtime: u64,
    /// Ban duration (seconds)
    bantime: u64,
    /// Never ban these addresses / CIDRs
    ignoreip: Vec<String>,
    /// Also match scanner-type noise (no banner, failed negotiation...).
    /// Off by default: load balancer health checks can trigger these.
    aggressive: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            cleanup_interval: 30,
            ban_backend: "auto".into(),
            log_source: "auto".into(),
            logpath: None,
            sshd_config: "/etc/ssh/sshd_config".into(),
            ports: Vec::new(),
            maxretry: 5,
            findtime: 600,
            bantime: 3600,
            ignoreip: vec!["127.0.0.0/8".into(), "::1".into()],
            aggressive: false,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    global: GlobalConfig,
}

fn load_config(explicit: Option<&Path>) -> Result<GlobalConfig> {
    let path: Option<PathBuf> = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => ["config.toml", "/etc/rust-fail2ban/config.toml"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file()),
    };
    let Some(path) = path else {
        info!("no config file found, using built-in defaults");
        return Ok(GlobalConfig::default());
    };

    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read config {}", path.display()))?;
    let raw: toml::Value = toml::from_str(&text).context("invalid TOML config")?;
    if raw.get("jails").is_some() {
        warn!("[[jails]] is no longer used and will be ignored (everything is auto-detected)");
    }
    let file: ConfigFile = raw.try_into().context("invalid config values")?;
    let cfg = file.global;
    if cfg.maxretry == 0 || cfg.findtime == 0 || cfg.bantime == 0 {
        bail!("maxretry, findtime and bantime must be greater than 0");
    }
    info!("loaded config from {}", path.display());
    Ok(cfg)
}

// ───────────────────────────── helpers ─────────────────────────────

/// Look for an executable in PATH plus the usual sbin directories.
fn find_bin(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    for d in [
        "/usr/local/sbin",
        "/usr/sbin",
        "/sbin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ] {
        dirs.push(PathBuf::from(d));
    }
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

fn run(bin: &Path, args: &[&str]) -> Result<Output> {
    Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {}", bin.display()))
}

fn run_ok(bin: &Path, args: &[&str]) -> Result<()> {
    let out = run(bin, args)?;
    if !out.status.success() {
        bail!(
            "{} {} failed: {}",
            bin.display(),
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn cmd_ok(bin: &Path, args: &[&str]) -> bool {
    run(bin, args).map(|o| o.status.success()).unwrap_or(false)
}

fn run_stdin(bin: &Path, args: &[&str], input: &str) -> Result<()> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {}", bin.display()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("no stdin"))?
        .write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "{} {} failed: {}",
            bin.display(),
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Map IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to plain IPv4.
fn canon(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Minimal glob matcher supporting `*` and `?`.
fn wildcard_match(pat: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| go(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && go(&p[1..], &t[1..]),
            Some(c) => t.first() == Some(c) && go(&p[1..], &t[1..]),
        }
    }
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

// ───────────────────────────── whitelist ─────────────────────────────

#[derive(Debug, Clone)]
struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let net = canon(addr.parse::<IpAddr>().ok()?);
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Cidr { net, prefix })
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix as u32);
                (u32::from(*n) & mask) == (u32::from(*i) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix as u32);
                (u128::from(*n) & mask) == (u128::from(*i) & mask)
            }
            _ => false,
        }
    }
}

fn build_whitelist(cfg: &GlobalConfig) -> Vec<Cidr> {
    let mut list = Vec::new();
    for s in &cfg.ignoreip {
        match Cidr::parse(s) {
            Some(c) => list.push(c),
            None => warn!("ignoring invalid ignoreip entry: {}", s),
        }
    }
    // If we are started from an SSH session, never ban that client.
    if let Ok(conn) = std::env::var("SSH_CONNECTION") {
        if let Some(first) = conn.split_whitespace().next() {
            if let Some(c) = Cidr::parse(first) {
                info!("auto-whitelisting current SSH client {}", first);
                list.push(c);
            }
        }
    }
    list
}

// ───────────────────────────── sshd detection ─────────────────────────────

#[derive(Debug, Clone)]
struct SshSettings {
    ports: Vec<u16>,
    password: bool,
    kbd_interactive: bool,
    pubkey: bool,
    source: String,
}

/// Raw directives; for booleans the first value wins (sshd semantics).
#[derive(Default, Debug)]
struct RawSsh {
    ports: Vec<u16>,
    password: Option<bool>,
    kbd: Option<bool>,
    pubkey: Option<bool>,
}

fn parse_yes_no(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" => Some(true),
        "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

impl RawSsh {
    fn apply(&mut self, key: &str, value: &str) {
        let value = value.split('#').next().unwrap_or("");
        let v = value
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('"');
        match key.to_ascii_lowercase().as_str() {
            "port" => {
                if let Ok(p) = v.parse::<u16>() {
                    if !self.ports.contains(&p) {
                        self.ports.push(p);
                    }
                }
            }
            "passwordauthentication" => {
                if self.password.is_none() {
                    self.password = parse_yes_no(v);
                }
            }
            "kbdinteractiveauthentication" | "challengeresponseauthentication" => {
                if self.kbd.is_none() {
                    self.kbd = parse_yes_no(v);
                }
            }
            "pubkeyauthentication" => {
                if self.pubkey.is_none() {
                    self.pubkey = parse_yes_no(v);
                }
            }
            _ => {}
        }
    }

    fn finish(self, source: String) -> SshSettings {
        SshSettings {
            ports: if self.ports.is_empty() {
                vec![22]
            } else {
                self.ports
            },
            // OpenSSH defaults
            password: self.password.unwrap_or(true),
            kbd_interactive: self.kbd.unwrap_or(true),
            pubkey: self.pubkey.unwrap_or(true),
            source,
        }
    }
}

fn expand_include(pat: &str) -> Vec<PathBuf> {
    let p = if Path::new(pat).is_absolute() {
        PathBuf::from(pat)
    } else {
        Path::new("/etc/ssh").join(pat)
    };
    let name = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if !name.contains('*') && !name.contains('?') {
        return vec![p];
    }
    // wildcard only supported in the last path component (covers sshd_config.d/*.conf)
    let dir = p.parent().unwrap_or_else(|| Path::new("/")).to_path_buf();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|f| {
                    f.file_name()
                        .map(|n| wildcard_match(&name, &n.to_string_lossy()))
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// Parse an sshd_config file (global section only, `Include` followed in place).
/// A `Match` line ends the global section of that file.
fn parse_sshd_file(path: &Path, depth: u32, raw: &mut RawSsh) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, rest)) = line.split_once(|c: char| c.is_whitespace() || c == '=') else {
            continue;
        };
        let value = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=');
        match key.to_ascii_lowercase().as_str() {
            "match" => break,
            "include" => {
                if depth >= 8 {
                    continue;
                }
                let value = value.split('#').next().unwrap_or("");
                for pat in value.split_whitespace() {
                    for f in expand_include(pat.trim_matches('"')) {
                        parse_sshd_file(&f, depth + 1, raw);
                    }
                }
            }
            k => raw.apply(k, value),
        }
    }
}

fn detect_ssh(cfg: &GlobalConfig) -> SshSettings {
    let cfg_exists = Path::new(&cfg.sshd_config).is_file();
    let mut raw = RawSsh::default();
    let source;

    // 1. Ask sshd itself: handles Include, defaults, everything.
    let mut from_sshd = false;
    if let Some(sshd) = find_bin("sshd") {
        let mut cmd = Command::new(&sshd);
        cmd.arg("-T");
        if cfg_exists {
            cmd.arg("-f").arg(&cfg.sshd_config);
        }
        match cmd.output() {
            Ok(out) if out.status.success() => {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Some((k, v)) = line.split_once(' ') {
                        raw.apply(k, v);
                    }
                }
                from_sshd = true;
            }
            Ok(out) => debug!(
                "sshd -T failed ({}), falling back to parsing the file",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => debug!("cannot run sshd -T: {}", e),
        }
    }

    if from_sshd {
        source = "sshd -T".to_string();
    } else if cfg_exists {
        parse_sshd_file(Path::new(&cfg.sshd_config), 0, &mut raw);
        source = format!("{} (+Include)", cfg.sshd_config);
    } else {
        warn!(
            "sshd config not found ({}), assuming OpenSSH defaults",
            cfg.sshd_config
        );
        source = "defaults".to_string();
    }

    let mut ssh = raw.finish(source);
    if !cfg.ports.is_empty() {
        ssh.ports = cfg.ports.clone();
        ssh.source.push_str(" + ports override");
    }
    ssh
}

// ───────────────────────────── log source ─────────────────────────────

#[derive(Debug, Clone)]
enum LogSource {
    Journal,
    File(PathBuf),
}

impl std::fmt::Display for LogSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogSource::Journal => write!(f, "systemd journal (journalctl -f)"),
            LogSource::File(p) => write!(f, "file {}", p.display()),
        }
    }
}

fn journal_available() -> bool {
    find_bin("journalctl").is_some() && Path::new("/run/systemd/journal").exists()
}

fn detect_log_file() -> Option<PathBuf> {
    ["/var/log/auth.log", "/var/log/secure"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

fn detect_log_source(cfg: &GlobalConfig) -> Result<LogSource> {
    match cfg.log_source.as_str() {
        "journal" => {
            if find_bin("journalctl").is_none() {
                bail!("log_source = \"journal\" but journalctl was not found");
            }
            Ok(LogSource::Journal)
        }
        "file" => {
            if let Some(p) = &cfg.logpath {
                Ok(LogSource::File(PathBuf::from(p)))
            } else if let Some(p) = detect_log_file() {
                Ok(LogSource::File(p))
            } else {
                bail!("log_source = \"file\" but no log file found; set `logpath`")
            }
        }
        "auto" => {
            if let Some(p) = &cfg.logpath {
                Ok(LogSource::File(PathBuf::from(p)))
            } else if journal_available() {
                Ok(LogSource::Journal)
            } else if let Some(p) = detect_log_file() {
                Ok(LogSource::File(p))
            } else {
                bail!(
                    "no log source found (no systemd journal, no /var/log/auth.log or \
                     /var/log/secure). Install rsyslog or set `logpath`."
                )
            }
        }
        other => bail!("unknown log_source '{}' (auto | journal | file)", other),
    }
}

// ───────────────────────────── filters ─────────────────────────────

/// Attempt: a real credential attempt that failed (each one counts).
/// Soft: connection-level signal (invalid user, pre-auth disconnect...).
///       At most one Soft failure is counted per connection, and none if the
///       connection also produced Attempt lines — so one connection is not
///       counted several times for the same attack.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Attempt,
    Soft,
}

struct Filter {
    name: &'static str,
    kind: Kind,
    re: Regex,
}

// NOTE: patterns use greedy `.*` before "from <ip>", so a malicious user name
// containing " from 1.2.3.4" cannot override the real (last) address.
const IP: &str = r"(?P<ip>[0-9a-fA-F:.]+)";

fn push_filter(v: &mut Vec<Filter>, name: &'static str, kind: Kind, pat: String) -> Result<()> {
    let re = Regex::new(&pat).with_context(|| format!("bad built-in regex '{}'", name))?;
    v.push(Filter { name, kind, re });
    Ok(())
}

/// Choose failure patterns based on the detected auth methods.
fn build_filters(ssh: &SshSettings, aggressive: bool) -> Result<Vec<Filter>> {
    let mut v = Vec::new();

    // Credential attempts (only for enabled methods)
    if ssh.password {
        push_filter(
            &mut v,
            "failed-password",
            Kind::Attempt,
            format!(r"Failed password for .* from {IP} port \d+"),
        )?;
    }
    if ssh.kbd_interactive {
        push_filter(
            &mut v,
            "failed-keyboard-interactive",
            Kind::Attempt,
            format!(r"Failed keyboard-interactive(?:/pam)? for .* from {IP} port \d+"),
        )?;
    }
    if ssh.pubkey {
        push_filter(
            &mut v,
            "failed-publickey",
            Kind::Attempt,
            format!(r"Failed publickey for .* from {IP} port \d+"),
        )?;
    }

    // Connection-level signals (useful for every auth method, essential for key-only)
    push_filter(
        &mut v,
        "max-auth-attempts",
        Kind::Soft,
        format!(r"maximum authentication attempts exceeded for .* from {IP} port \d+"),
    )?;
    push_filter(
        &mut v,
        "invalid-user",
        Kind::Soft,
        format!(r"Invalid user .* from {IP}(?: port \d+)?"),
    )?;
    push_filter(
        &mut v,
        "preauth-disconnect",
        Kind::Soft,
        format!(
            r"(?:Connection closed by|Disconnected from|Connection reset by) (?:authenticating|invalid) user .* {IP} port \d+ \[preauth\]"
        ),
    )?;

    if aggressive {
        push_filter(
            &mut v,
            "no-identification",
            Kind::Soft,
            format!(
                r"(?:Did not receive identification string from|Unable to negotiate with|banner exchange: Connection from) {IP}"
            ),
        )?;
        push_filter(
            &mut v,
            "bad-protocol",
            Kind::Soft,
            format!(r"Bad protocol version identification .* from {IP}"),
        )?;
    }
    Ok(v)
}

struct Hit {
    ip: IpAddr,
    pid: Option<u32>,
    kind: Kind,
    filter: &'static str,
}

struct Detector {
    filters: Vec<Filter>,
    pid_re: Regex,
}

impl Detector {
    fn new(filters: Vec<Filter>) -> Self {
        Self {
            filters,
            pid_re: Regex::new(r"sshd[\w-]*\[(\d+)\]").expect("static regex"),
        }
    }

    fn parse(&self, line: &str) -> Option<Hit> {
        // Only sshd lines (the auth log also contains sudo, su, cron...)
        if !line.contains("sshd") {
            return None;
        }
        for f in &self.filters {
            if let Some(caps) = f.re.captures(line) {
                let ip = match caps.name("ip").and_then(|m| m.as_str().parse::<IpAddr>().ok()) {
                    Some(ip) => canon(ip),
                    None => {
                        debug!("[{}] matched but invalid IP in: {}", f.name, line);
                        return None;
                    }
                };
                // First match in the line is the syslog header pid
                let pid = self
                    .pid_re
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .and_then(|m| m.as_str().parse::<u32>().ok());
                return Some(Hit {
                    ip,
                    pid,
                    kind: f.kind,
                    filter: f.name,
                });
            }
        }
        None
    }
}

// ───────────────────────────── ban backends ─────────────────────────────

trait BanBackend: Send + Sync {
    fn name(&self) -> String;
    /// Create firewall structures (cleans leftovers of a previous run)
    fn init(&self) -> Result<()>;
    fn ban(&self, ip: IpAddr) -> Result<()>;
    fn unban(&self, ip: IpAddr) -> Result<()>;
    /// Remove everything we created
    fn shutdown(&self);
}

/// Log only
struct DummyBackend;

impl BanBackend for DummyBackend {
    fn name(&self) -> String {
        "dummy (log only, nothing is blocked)".into()
    }
    fn init(&self) -> Result<()> {
        Ok(())
    }
    fn ban(&self, ip: IpAddr) -> Result<()> {
        info!("[DUMMY] BAN {}", ip);
        Ok(())
    }
    fn unban(&self, ip: IpAddr) -> Result<()> {
        info!("[DUMMY] UNBAN {}", ip);
        Ok(())
    }
    fn shutdown(&self) {}
}

const NFT_TABLE: &str = "rust_fail2ban";

/// nftables: own table `inet rust_fail2ban` with sets + a drop chain.
/// Nothing needs to be prepared by the user.
struct NftBackend {
    bin: PathBuf,
    ports: Vec<u16>,
}

impl NftBackend {
    fn set_for(ip: &IpAddr) -> &'static str {
        if ip.is_ipv4() {
            "banned4"
        } else {
            "banned6"
        }
    }
}

impl BanBackend for NftBackend {
    fn name(&self) -> String {
        format!("nftables (table inet {})", NFT_TABLE)
    }

    fn init(&self) -> Result<()> {
        let _ = cmd_ok(&self.bin, &["delete", "table", "inet", NFT_TABLE]);
        let ports = self
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let script = format!(
            "table inet {t} {{\n\
             \tset banned4 {{ type ipv4_addr; }}\n\
             \tset banned6 {{ type ipv6_addr; }}\n\
             \tchain input {{\n\
             \t\ttype filter hook input priority -10; policy accept;\n\
             \t\tip saddr @banned4 tcp dport {{ {p} }} drop\n\
             \t\tip6 saddr @banned6 tcp dport {{ {p} }} drop\n\
             \t}}\n\
             }}\n",
            t = NFT_TABLE,
            p = ports
        );
        run_stdin(&self.bin, &["-f", "-"], &script)
    }

    fn ban(&self, ip: IpAddr) -> Result<()> {
        let elem = format!("{{ {} }}", ip);
        run_ok(
            &self.bin,
            &["add", "element", "inet", NFT_TABLE, Self::set_for(&ip), &elem],
        )?;
        info!("[nftables] BAN {}", ip);
        Ok(())
    }

    fn unban(&self, ip: IpAddr) -> Result<()> {
        let elem = format!("{{ {} }}", ip);
        let out = run(
            &self.bin,
            &["delete", "element", "inet", NFT_TABLE, Self::set_for(&ip), &elem],
        )?;
        if out.status.success() {
            info!("[nftables] UNBAN {}", ip);
        } else {
            warn!(
                "nftables unban warning: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn shutdown(&self) {
        let _ = cmd_ok(&self.bin, &["delete", "table", "inet", NFT_TABLE]);
    }
}

const IPT_CHAIN: &str = "rust-f2b";

/// iptables (+ ip6tables for IPv6): own chain `rust-f2b` jumped to from INPUT.
struct IptablesBackend {
    v4: PathBuf,
    v6: Option<PathBuf>,
    ports: Vec<u16>,
}

impl IptablesBackend {
    fn ports_csv(&self) -> String {
        self.ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn bin_for(&self, ip: &IpAddr) -> Result<&Path> {
        match ip {
            IpAddr::V4(_) => Ok(self.v4.as_path()),
            IpAddr::V6(_) => self
                .v6
                .as_deref()
                .ok_or_else(|| anyhow!("ip6tables not found, cannot ban IPv6 address")),
        }
    }

    fn teardown_one(bin: &Path) {
        for _ in 0..10 {
            if !cmd_ok(bin, &["-w", "-D", "INPUT", "-j", IPT_CHAIN]) {
                break;
            }
        }
        let _ = cmd_ok(bin, &["-w", "-F", IPT_CHAIN]);
        let _ = cmd_ok(bin, &["-w", "-X", IPT_CHAIN]);
    }

    fn setup_one(bin: &Path) -> Result<()> {
        Self::teardown_one(bin);
        run_ok(bin, &["-w", "-N", IPT_CHAIN])?;
        run_ok(bin, &["-w", "-I", "INPUT", "1", "-j", IPT_CHAIN])?;
        Ok(())
    }

    fn rule_args<'a>(op: &'a str, ip: &'a str, ports: &'a str) -> Vec<&'a str> {
        vec![
            "-w", op, IPT_CHAIN, "-s", ip, "-p", "tcp", "-m", "multiport", "--dports", ports,
            "-j", "DROP",
        ]
    }
}

impl BanBackend for IptablesBackend {
    fn name(&self) -> String {
        format!(
            "iptables{} (chain {})",
            if self.v6.is_some() { " + ip6tables" } else { "" },
            IPT_CHAIN
        )
    }

    fn init(&self) -> Result<()> {
        Self::setup_one(&self.v4)?;
        if let Some(v6) = &self.v6 {
            if let Err(e) = Self::setup_one(v6) {
                warn!("ip6tables setup failed, IPv6 bans disabled: {}", e);
            }
        }
        Ok(())
    }

    fn ban(&self, ip: IpAddr) -> Result<()> {
        let bin = self.bin_for(&ip)?;
        let ip_s = ip.to_string();
        let ports = self.ports_csv();
        run_ok(bin, &Self::rule_args("-I", &ip_s, &ports))?;
        info!("[iptables] BAN {}", ip);
        Ok(())
    }

    fn unban(&self, ip: IpAddr) -> Result<()> {
        let bin = self.bin_for(&ip)?;
        let ip_s = ip.to_string();
        let ports = self.ports_csv();
        let out = run(bin, &Self::rule_args("-D", &ip_s, &ports))?;
        if out.status.success() {
            info!("[iptables] UNBAN {}", ip);
        } else {
            warn!(
                "iptables unban warning: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn shutdown(&self) {
        Self::teardown_one(&self.v4);
        if let Some(v6) = &self.v6 {
            Self::teardown_one(v6);
        }
    }
}

fn try_nft(ports: &[u16]) -> Option<NftBackend> {
    let bin = find_bin("nft")?;
    if cmd_ok(&bin, &["list", "tables"]) {
        Some(NftBackend {
            bin,
            ports: ports.to_vec(),
        })
    } else {
        None
    }
}

fn try_iptables(ports: &[u16]) -> Option<IptablesBackend> {
    let v4 = find_bin("iptables")?;
    if !cmd_ok(&v4, &["-w", "-S"]) {
        return None;
    }
    Some(IptablesBackend {
        v4,
        v6: find_bin("ip6tables"),
        ports: ports.to_vec(),
    })
}

/// Choose the ban backend. `auto` prefers nftables, then iptables.
fn pick_backend(cfg: &GlobalConfig, ports: &[u16]) -> Result<Arc<dyn BanBackend>> {
    match cfg.ban_backend.as_str() {
        "auto" => {
            if let Some(b) = try_nft(ports) {
                Ok(Arc::new(b))
            } else if let Some(b) = try_iptables(ports) {
                Ok(Arc::new(b))
            } else {
                warn!(
                    "no usable firewall found (need root and nft or iptables) — \
                     falling back to LOG-ONLY mode, nothing will be blocked!"
                );
                Ok(Arc::new(DummyBackend))
            }
        }
        "nftables" | "nft" => try_nft(ports)
            .map(|b| Arc::new(b) as Arc<dyn BanBackend>)
            .ok_or_else(|| anyhow!("nft not found or not usable (are you root?)")),
        "iptables" => try_iptables(ports)
            .map(|b| Arc::new(b) as Arc<dyn BanBackend>)
            .ok_or_else(|| anyhow!("iptables not found or not usable (are you root?)")),
        "dummy" | "none" => Ok(Arc::new(DummyBackend)),
        other => bail!(
            "unknown ban_backend '{}' (auto | nftables | iptables | dummy)",
            other
        ),
    }
}

// ───────────────────────────── core state ─────────────────────────────

#[derive(Debug, Clone)]
struct BanEntry {
    banned_at: DateTime<Utc>,
    bantime: u64,
}

impl BanEntry {
    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.banned_at + chrono::Duration::seconds(self.bantime as i64)
    }
}

/// Per-connection (ip, sshd pid) bookkeeping used to avoid counting the same
/// attack several times (Invalid user + Failed password + preauth close).
struct ConnState {
    soft: bool,
    attempts: u32,
    last: DateTime<Utc>,
}

struct AppState {
    failures: DashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    bans: DashMap<IpAddr, BanEntry>,
    conns: DashMap<(IpAddr, u32), ConnState>,
    backend: Arc<dyn BanBackend>,
    maxretry: u32,
    findtime: u64,
    bantime: u64,
    whitelist: Vec<Cidr>,
}

impl AppState {
    fn new(
        backend: Arc<dyn BanBackend>,
        maxretry: u32,
        findtime: u64,
        bantime: u64,
        whitelist: Vec<Cidr>,
    ) -> Self {
        Self {
            failures: DashMap::new(),
            bans: DashMap::new(),
            conns: DashMap::new(),
            backend,
            maxretry,
            findtime,
            bantime,
            whitelist,
        }
    }

    fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.whitelist.iter().any(|c| c.contains(ip))
    }

    fn handle_hit(&self, hit: &Hit) {
        let ip = hit.ip;
        if self.is_whitelisted(&ip) {
            debug!("[{}] {} is whitelisted, ignoring", hit.filter, ip);
            return;
        }
        if self.bans.contains_key(&ip) {
            debug!("[{}] {} already banned, ignoring", hit.filter, ip);
            return;
        }

        let counts = match hit.pid {
            None => true,
            Some(pid) => {
                let mut c = self.conns.entry((ip, pid)).or_insert_with(|| ConnState {
                    soft: false,
                    attempts: 0,
                    last: Utc::now(),
                });
                c.last = Utc::now();
                let r = match hit.kind {
                    Kind::Soft => {
                        if c.soft || c.attempts > 0 {
                            false
                        } else {
                            c.soft = true;
                            true
                        }
                    }
                    Kind::Attempt => {
                        c.attempts += 1;
                        // the first attempt is the same event as an earlier
                        // "Invalid user" line of this connection
                        !(c.attempts == 1 && c.soft)
                    }
                };
                r
            }
        };

        if counts {
            debug!("[{}] failure from {} (pid {:?})", hit.filter, ip, hit.pid);
            self.record_failure(ip, hit.filter);
        } else {
            debug!("[{}] {} duplicate of same connection, not counted", hit.filter, ip);
        }
    }

    fn record_failure(&self, ip: IpAddr, reason: &str) {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(self.findtime as i64);

        // The guard must be dropped before touching `failures` again.
        let should_ban = {
            let mut q = self.failures.entry(ip).or_default();
            while let Some(front) = q.front() {
                if *front < cutoff {
                    q.pop_front();
                } else {
                    break;
                }
            }
            q.push_back(now);
            q.len() as u32 >= self.maxretry
        };

        if should_ban {
            self.failures.remove(&ip);
            info!(
                "Ban {} after {} failures within {}s (last: {})",
                ip, self.maxretry, self.findtime, reason
            );
            match self.backend.ban(ip) {
                Ok(()) => {
                    self.bans.insert(
                        ip,
                        BanEntry {
                            banned_at: now,
                            bantime: self.bantime,
                        },
                    );
                }
                Err(e) => error!("Failed to ban {}: {}", ip, e),
            }
        }
    }

    fn cleanup_expired(&self) {
        let now = Utc::now();

        let expired: Vec<IpAddr> = self
            .bans
            .iter()
            .filter(|e| e.value().is_expired(now))
            .map(|e| *e.key())
            .collect();
        for ip in expired {
            if self.bans.remove(&ip).is_some() {
                match self.backend.unban(ip) {
                    Ok(()) => info!("Unban {} (bantime expired)", ip),
                    Err(e) => error!("Failed to unban {}: {}", ip, e),
                }
            }
        }

        // Memory hygiene
        let cutoff = now - chrono::Duration::seconds(self.findtime as i64);
        self.failures
            .retain(|_, q| q.back().map(|t| *t >= cutoff).unwrap_or(false));
        let conn_cutoff = now - chrono::Duration::seconds(300);
        self.conns.retain(|_, c| c.last >= conn_cutoff);
    }
}

// ───────────────────────────── log readers ─────────────────────────────

/// Follow a log file. Handles rotation (inode change) and truncation.
async fn tail_log(path: PathBuf, tx: mpsc::Sender<String>) -> Result<()> {
    // Open and seek to end: only lines written after startup are processed
    let mut file =
        File::open(&path).with_context(|| format!("cannot open log {}", path.display()))?;
    let mut inode = file.metadata()?.ino();
    let mut pos = file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);

    let (watch_tx, mut watch_rx) = mpsc::channel(32);
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_)) {
                    let _ = watch_tx.try_send(());
                }
            }
        },
        Config::default(),
    )?;
    watcher.watch(&path, RecursiveMode::NonRecursive)?;

    let mut line = String::new();
    loop {
        // 1. Drain everything currently readable
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => {
                    if !line.ends_with('\n') {
                        // partial line: rewind and retry later
                        let _ = reader.seek_relative(-(n as i64));
                        break;
                    }
                    pos += n as u64;
                    let trimmed = line.trim_end().to_string();
                    if !trimmed.is_empty() && tx.send(trimmed).await.is_err() {
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!("Error reading {}: {}", path.display(), e);
                    break;
                }
            }
        }

        // 2. Rotation / truncation: reopen and read the new file from the start
        if let Ok(meta) = std::fs::metadata(&path) {
            let rotated = meta.ino() != inode;
            let truncated = meta.len() < pos;
            if rotated || truncated {
                match File::open(&path) {
                    Ok(new_file) => {
                        info!(
                            "{} {} — reopening from start",
                            path.display(),
                            if rotated { "rotated" } else { "truncated" }
                        );
                        inode = new_file.metadata().map(|m| m.ino()).unwrap_or(meta.ino());
                        pos = 0;
                        reader = BufReader::new(new_file);
                        let _ = watcher.unwatch(&path);
                        let _ = watcher.watch(&path, RecursiveMode::NonRecursive);
                        continue;
                    }
                    Err(e) => warn!("Cannot reopen {}: {}", path.display(), e),
                }
            }
        }

        // 3. Wait for inotify or poll every 2s
        tokio::select! {
            _ = watch_rx.recv() => {},
            _ = time::sleep(Duration::from_secs(2)) => {},
        }
    }
}

/// Follow sshd messages in the systemd journal via `journalctl -f`.
async fn tail_journal(tx: mpsc::Sender<String>) -> Result<()> {
    use tokio::io::AsyncBufReadExt;

    let bin = find_bin("journalctl").ok_or_else(|| anyhow!("journalctl not found"))?;
    let mut child = tokio::process::Command::new(bin)
        .args([
            "-q",
            "--no-pager",
            "-f",
            "-n",
            "0",
            "-o",
            "short",
            "-t",
            "sshd",
            "-t",
            "sshd-session",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start journalctl")?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("no stdout from journalctl"))?;
    let mut reader = tokio::io::BufReader::new(stdout);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf).await?;
        if n == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buf).trim_end().to_string();
        if !line.is_empty() && tx.send(line).await.is_err() {
            return Ok(());
        }
    }
    let status = child.wait().await?;
    bail!("journalctl exited with {}", status)
}

// ───────────────────────────── main ─────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let cfg = load_config(args.config.as_deref())?;

    // ── detection ──
    let ssh = detect_ssh(&cfg);
    let source = detect_log_source(&cfg)?;
    let filters = build_filters(&ssh, cfg.aggressive)?;
    let filter_names: Vec<&str> = filters.iter().map(|f| f.name).collect();
    let whitelist = build_whitelist(&cfg);
    let backend = pick_backend(&cfg, &ssh.ports)?;

    info!(
        "sshd settings ({}): ports={:?} password={} keyboard-interactive={} pubkey={}",
        ssh.source, ssh.ports, ssh.password, ssh.kbd_interactive, ssh.pubkey
    );
    info!("log source: {}", source);
    info!("ban backend: {}", backend.name());
    info!("active filters: {}", filter_names.join(", "));
    info!(
        "policy: {} failures within {}s -> ban for {}s; {} whitelist entries",
        cfg.maxretry,
        cfg.findtime,
        cfg.bantime,
        whitelist.len()
    );

    if args.detect {
        return Ok(());
    }

    backend.init().context("firewall initialisation failed")?;

    let state = Arc::new(AppState::new(
        backend,
        cfg.maxretry,
        cfg.findtime,
        cfg.bantime,
        whitelist,
    ));
    let detector = Detector::new(filters);

    // ── log reader task ──
    let (tx, mut rx) = mpsc::channel::<String>(1024);
    tokio::spawn(async move {
        loop {
            let res = match &source {
                LogSource::File(p) => tail_log(p.clone(), tx.clone()).await,
                LogSource::Journal => tail_journal(tx.clone()).await,
            };
            match res {
                Ok(()) => break, // receiver gone
                Err(e) => {
                    error!("Log reader failed: {}. Retrying in 5s...", e);
                    time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });

    // ── cleanup task ──
    let state_cleanup = Arc::clone(&state);
    let interval = cfg.cleanup_interval.max(1);
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(interval));
        loop {
            ticker.tick().await;
            state_cleanup.cleanup_expired();
        }
    });

    // ── main loop ──
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    info!("rust-fail2ban is running");
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(line) => {
                        if let Some(hit) = detector.parse(&line) {
                            state.handle_hit(&hit);
                        }
                    }
                    None => {
                        error!("log reader stopped unexpectedly");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => { info!("SIGINT received, shutting down"); break; }
            _ = sigterm.recv() => { info!("SIGTERM received, shutting down"); break; }
        }
    }

    state.backend.shutdown();
    info!("firewall rules removed, bye");
    Ok(())
}

// ───────────────────────────── tests ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh(password: bool, kbd: bool, pubkey: bool) -> SshSettings {
        SshSettings {
            ports: vec![22],
            password,
            kbd_interactive: kbd,
            pubkey,
            source: "test".into(),
        }
    }

    fn detector(s: &SshSettings, aggressive: bool) -> Detector {
        Detector::new(build_filters(s, aggressive).unwrap())
    }

    fn state(maxretry: u32) -> AppState {
        AppState::new(Arc::new(DummyBackend), maxretry, 600, 3600, vec![])
    }

    fn feed(st: &AppState, d: &Detector, line: &str) {
        if let Some(h) = d.parse(line) {
            st.handle_hit(&h);
        }
    }

    #[test]
    fn wildcard() {
        assert!(wildcard_match("*.conf", "50-cloud-init.conf"));
        assert!(!wildcard_match("*.conf", "foo.bak"));
        assert!(wildcard_match("a?c", "abc"));
    }

    #[test]
    fn cidr() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!c.contains(&"11.0.0.1".parse().unwrap()));
        let l = Cidr::parse("::1").unwrap();
        assert!(l.contains(&"::1".parse().unwrap()));
        assert!(!l.contains(&"::2".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
    }

    #[test]
    fn sshd_include_and_match() {
        let dir = std::env::temp_dir().join(format!("rf2b-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        std::fs::write(dir.join("conf.d/50.conf"), "PasswordAuthentication no\n").unwrap();
        std::fs::write(
            dir.join("sshd_config"),
            format!(
                "Include {}/conf.d/*.conf\nPort 2222\nPort 22022\nPasswordAuthentication yes\n\
                 Match User bob\n    PubkeyAuthentication no\n",
                dir.display()
            ),
        )
        .unwrap();

        let mut raw = RawSsh::default();
        parse_sshd_file(&dir.join("sshd_config"), 0, &mut raw);
        let s = raw.finish("t".into());
        assert_eq!(s.ports, vec![2222, 22022]);
        assert!(!s.password); // first value (from Include) wins
        assert!(s.pubkey); // Match block ignored
        assert!(s.kbd_interactive); // default
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn filters_follow_auth_methods() {
        let key_only = detector(&ssh(false, false, true), false);
        let l = "Oct 10 03:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2";
        assert!(key_only.parse(l).is_none());
        let l = "Oct 10 03:00:00 h sshd[1]: Failed publickey for root from 1.2.3.4 port 5 ssh2: RSA SHA256:x";
        assert_eq!(key_only.parse(l).unwrap().kind, Kind::Attempt);
        let l = "Oct 10 03:00:00 h sshd[1]: Connection closed by authenticating user root 1.2.3.4 port 5 [preauth]";
        assert_eq!(key_only.parse(l).unwrap().kind, Kind::Soft);

        let pw = detector(&ssh(true, true, true), false);
        let l = "Oct 10 03:00:00 h sshd[1]: Failed password for invalid user a from 2001:db8::1 port 5 ssh2";
        let h = pw.parse(l).unwrap();
        assert_eq!(h.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(h.pid, Some(1));

        // not an sshd line
        assert!(pw
            .parse("Oct 10 03:00:00 h sudo[1]: Failed password for root from 1.2.3.4 port 5")
            .is_none());
    }

    #[test]
    fn aggressive_filters_are_opt_in() {
        let l = "Oct 10 03:00:00 h sshd[1]: Did not receive identification string from 1.2.3.4 port 5";
        assert!(detector(&ssh(true, true, true), false).parse(l).is_none());
        assert!(detector(&ssh(true, true, true), true).parse(l).is_some());
    }

    #[test]
    fn same_connection_counted_once_per_attack() {
        let d = detector(&ssh(true, true, true), false);
        let st = state(100);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();

        // one invalid-user connection = 3 log lines = 1 failure
        feed(&st, &d, "Oct 10 03:00:00 h sshd[100]: Invalid user a from 1.1.1.1 port 1");
        feed(&st, &d, "Oct 10 03:00:00 h sshd[100]: Failed password for invalid user a from 1.1.1.1 port 1 ssh2");
        feed(&st, &d, "Oct 10 03:00:01 h sshd[100]: Connection closed by invalid user a 1.1.1.1 port 1 [preauth]");
        assert_eq!(st.failures.get(&ip).map(|q| q.len()), Some(1));

        // three password attempts on another connection = 3 failures
        for _ in 0..3 {
            feed(&st, &d, "Oct 10 03:00:02 h sshd[200]: Failed password for root from 1.1.1.1 port 2 ssh2");
        }
        assert_eq!(st.failures.get(&ip).map(|q| q.len()), Some(4));
    }

    #[test]
    fn ban_whitelist_and_ipv6() {
        let d = detector(&ssh(true, true, true), false);
        let mut st = state(3);
        st.whitelist = vec![Cidr::parse("9.9.9.9").unwrap()];

        for i in 0..3 {
            feed(&st, &d, &format!("Oct 10 03:00:00 h sshd[{}]: Failed password for root from 2.2.2.2 port 1 ssh2", 10 + i));
            feed(&st, &d, &format!("Oct 10 03:00:00 h sshd[{}]: Failed password for root from 9.9.9.9 port 1 ssh2", 20 + i));
            feed(&st, &d, &format!("Oct 10 03:00:00 h sshd[{}]: Failed password for root from 2001:db8::1 port 1 ssh2", 30 + i));
        }
        assert!(st.bans.contains_key(&"2.2.2.2".parse::<IpAddr>().unwrap()));
        assert!(st.bans.contains_key(&"2001:db8::1".parse::<IpAddr>().unwrap()));
        assert!(!st.bans.contains_key(&"9.9.9.9".parse::<IpAddr>().unwrap()));
    }
}
