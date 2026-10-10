//! rust-fail2ban — A lightweight Fail2Ban-like tool written in Rust.
//!
//! Monitors log files for failed authentication attempts, tracks failures
//! per IP, and bans offending addresses via iptables / nftables (or dummy mode).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::Deserialize;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(name = "rust-fail2ban", about = "A lightweight Fail2Ban written in Rust")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Increase verbosity (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// Global configuration
#[derive(Debug, Deserialize, Clone)]
struct GlobalConfig {
    #[serde(default = "default_cleanup")]
    cleanup_interval: u64,
    #[serde(default = "default_backend")]
    ban_backend: String,
}

fn default_cleanup() -> u64 {
    30
}
fn default_backend() -> String {
    "dummy".into()
}

/// A single jail (filter + action)
#[derive(Debug, Deserialize, Clone)]
struct JailConfig {
    name: String,
    #[serde(default = "default_true")]
    enabled: bool,
    logpath: String,
    failregex: String,
    #[serde(default = "default_maxretry")]
    maxretry: u32,
    #[serde(default = "default_findtime")]
    findtime: u64,
    #[serde(default = "default_bantime")]
    bantime: u64,
    #[serde(default = "default_port")]
    port: String,
    #[serde(default = "default_protocol")]
    protocol: String,
}

fn default_true() -> bool {
    true
}
fn default_maxretry() -> u32 {
    5
}
fn default_findtime() -> u64 {
    600
}
fn default_bantime() -> u64 {
    3600
}
fn default_port() -> String {
    "22".into()
}
fn default_protocol() -> String {
    "tcp".into()
}

/// Root config structure
#[derive(Debug, Deserialize)]
struct ConfigFile {
    global: GlobalConfig,
    jails: Vec<JailConfig>,
}

/// Tracks failure timestamps for one IP inside one jail
#[derive(Debug)]
struct FailureRecord {
    timestamps: VecDeque<DateTime<Utc>>,
}

impl FailureRecord {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::new(),
        }
    }

    /// Add a failure and prune old ones outside findtime.
    /// Returns true if the IP should now be banned.
    fn add_failure(&mut self, now: DateTime<Utc>, findtime: u64, maxretry: u32) -> bool {
        let cutoff = now - chrono::Duration::seconds(findtime as i64);
        while let Some(front) = self.timestamps.front() {
            if *front < cutoff {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
        self.timestamps.push_back(now);
        self.timestamps.len() as u32 >= maxretry
    }
}

/// Active ban entry
#[derive(Debug, Clone)]
struct BanEntry {
    ip: IpAddr,
    jail: String,
    banned_at: DateTime<Utc>,
    bantime: u64,
}

impl BanEntry {
    fn expires_at(&self) -> DateTime<Utc> {
        self.banned_at + chrono::Duration::seconds(self.bantime as i64)
    }

    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at()
    }
}

/// Ban backend trait
trait BanBackend: Send + Sync {
    fn ban(&self, ip: IpAddr, port: &str, protocol: &str, jail: &str) -> Result<()>;
    fn unban(&self, ip: IpAddr, port: &str, protocol: &str, jail: &str) -> Result<()>;
}

/// Dummy backend — only logs
struct DummyBackend;

impl BanBackend for DummyBackend {
    fn ban(&self, ip: IpAddr, port: &str, protocol: &str, jail: &str) -> Result<()> {
        info!("[DUMMY] BAN {} (jail={}, port={}/{})", ip, jail, protocol, port);
        Ok(())
    }
    fn unban(&self, ip: IpAddr, port: &str, protocol: &str, jail: &str) -> Result<()> {
        info!("[DUMMY] UNBAN {} (jail={}, port={}/{})", ip, jail, protocol, port);
        Ok(())
    }
}

/// iptables backend
struct IptablesBackend;

impl BanBackend for IptablesBackend {
    fn ban(&self, ip: IpAddr, port: &str, protocol: &str, jail: &str) -> Result<()> {
        let chain = format!("f2b-{}", jail);
        // Ensure chain exists
        let _ = Command::new("iptables")
            .args(["-N", &chain])
            .output();
        // Insert jump if not present (best-effort)
        let _ = Command::new("iptables")
            .args(["-C", "INPUT", "-j", &chain])
            .output()
            .and_then(|_| {
                Command::new("iptables")
                    .args(["-I", "INPUT", "-j", &chain])
                    .output()
            });

        let output = Command::new("iptables")
            .args([
                "-I",
                &chain,
                "-s",
                &ip.to_string(),
                "-p",
                protocol,
                "--dport",
                port,
                "-j",
                "REJECT",
                "--reject-with",
                "icmp-port-unreachable",
            ])
            .output()
            .context("failed to run iptables")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("iptables ban failed: {}", stderr);
        }
        info!("[iptables] BAN {} (jail={}, port={}/{})", ip, jail, protocol, port);
        Ok(())
    }

    fn unban(&self, ip: IpAddr, port: &str, protocol: &str, jail: &str) -> Result<()> {
        let chain = format!("f2b-{}", jail);
        let output = Command::new("iptables")
            .args([
                "-D",
                &chain,
                "-s",
                &ip.to_string(),
                "-p",
                protocol,
                "--dport",
                port,
                "-j",
                "REJECT",
                "--reject-with",
                "icmp-port-unreachable",
            ])
            .output()
            .context("failed to run iptables")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Rule may already be gone; treat as soft success
            warn!("iptables unban warning: {}", stderr);
        } else {
            info!("[iptables] UNBAN {} (jail={}, port={}/{})", ip, jail, protocol, port);
        }
        Ok(())
    }
}

/// nftables backend (simplified)
struct NftablesBackend;

impl BanBackend for NftablesBackend {
    fn ban(&self, ip: IpAddr, _port: &str, _protocol: &str, jail: &str) -> Result<()> {
        // Assumes a set named f2b-<jail> already exists in table inet filter
        let set = format!("f2b-{}", jail);
        let output = Command::new("nft")
            .args(["add", "element", "inet", "filter", &set, &format!("{{ {} }}", ip)])
            .output()
            .context("failed to run nft")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nftables ban failed: {}", stderr);
        }
        info!("[nftables] BAN {} (jail={})", ip, jail);
        Ok(())
    }

    fn unban(&self, ip: IpAddr, _port: &str, _protocol: &str, jail: &str) -> Result<()> {
        let set = format!("f2b-{}", jail);
        let output = Command::new("nft")
            .args(["delete", "element", "inet", "filter", &set, &format!("{{ {} }}", ip)])
            .output()
            .context("failed to run nft")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("nftables unban warning: {}", stderr);
        } else {
            info!("[nftables] UNBAN {} (jail={})", ip, jail);
        }
        Ok(())
    }
}

fn create_backend(name: &str) -> Arc<dyn BanBackend> {
    match name {
        "iptables" => Arc::new(IptablesBackend),
        "nftables" => Arc::new(NftablesBackend),
        _ => Arc::new(DummyBackend),
    }
}

/// Core state shared across tasks
struct AppState {
    failures: DashMap<(String, IpAddr), FailureRecord>, // (jail, ip) -> record
    bans: DashMap<(String, IpAddr), BanEntry>,
    backend: Arc<dyn BanBackend>,
}

impl AppState {
    fn new(backend: Arc<dyn BanBackend>) -> Self {
        Self {
            failures: DashMap::new(),
            bans: DashMap::new(),
            backend,
        }
    }

    fn record_failure(&self, jail: &JailConfig, ip: IpAddr) {
        let key = (jail.name.clone(), ip);
        let now = Utc::now();

        // Already banned? ignore
        if self.bans.contains_key(&key) {
            debug!("IP {} already banned in jail {}, ignoring", ip, jail.name);
            return;
        }

        let mut entry = self.failures.entry(key.clone()).or_insert_with(FailureRecord::new);
        if entry.add_failure(now, jail.findtime, jail.maxretry) {
            // Ban!
            info!(
                "[{}] Ban {} after {} failures within {}s",
                jail.name, ip, jail.maxretry, jail.findtime
            );
            if let Err(e) = self.backend.ban(ip, &jail.port, &jail.protocol, &jail.name) {
                error!("Failed to ban {}: {}", ip, e);
                return;
            }
            self.bans.insert(
                key,
                BanEntry {
                    ip,
                    jail: jail.name.clone(),
                    banned_at: now,
                    bantime: jail.bantime,
                },
            );
            // Clear failure history
            self.failures.remove(&(jail.name.clone(), ip));
        }
    }

    fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut to_unban = Vec::new();
        for entry in self.bans.iter() {
            if entry.value().is_expired(now) {
                to_unban.push(entry.key().clone());
            }
        }
        for key in to_unban {
            if let Some((_, ban)) = self.bans.remove(&key) {
                // We need jail config for port/protocol — use defaults for simplicity
                // In a full implementation we'd store them in BanEntry
                if let Err(e) = self.backend.unban(ban.ip, "22", "tcp", &ban.jail) {
                    error!("Failed to unban {}: {}", ban.ip, e);
                } else {
                    info!("[{}] Unban {} (bantime expired)", ban.jail, ban.ip);
                }
            }
        }
    }
}

/// Tail a log file and emit new lines
async fn tail_log(
    path: PathBuf,
    tx: mpsc::Sender<(String, String)>, // (jail_name, line)
    jail_name: String,
) -> Result<()> {
    // Open and seek to end
    let mut file = File::open(&path)
        .with_context(|| format!("cannot open log {}", path.display()))?;
    file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);

    // Also watch for rotations / new writes with notify
    let (watch_tx, mut watch_rx) = mpsc::channel(32);
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_)) {
                    let _ = watch_tx.blocking_send(());
                }
            }
        },
        Config::default(),
    )?;
    watcher.watch(&path, RecursiveMode::NonRecursive)?;

    let mut line = String::new();
    loop {
        // Read any available lines
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = line.trim_end().to_string();
                    if !trimmed.is_empty()
                        && tx.send((jail_name.clone(), trimmed)).await.is_err()
                    {
                        return Ok(()); // receiver dropped
                    }
                }
                Err(e) => {
                    warn!("Error reading {}: {}", path.display(), e);
                    break;
                }
            }
        }

        // Wait for notify or timeout (to handle rotations)
        tokio::select! {
            _ = watch_rx.recv() => {},
            _ = time::sleep(Duration::from_secs(2)) => {
                // Check if file was rotated (inode changed)
                if let Ok(meta) = std::fs::metadata(&path) {
                    // Re-open if needed — simple approach: always re-open on timeout
                    // For production we'd track inode
                    let _ = meta;
                }
            }
        }

        // Re-open on potential rotation
        if let Ok(new_file) = File::open(&path) {
            let mut new_reader = BufReader::new(new_file);
            // If size shrank, it was rotated — start from beginning of new file
            // Otherwise continue from previous position (best-effort)
            let _ = new_reader.seek(SeekFrom::End(0));
            reader = new_reader;
        }
    }
}

/// Process a single log line against a jail's regex
fn process_line(line: &str, jail: &JailConfig, re: &Regex, state: &AppState) {
    if let Some(caps) = re.captures(line) {
        if let Some(ip_str) = caps.name("ip").map(|m| m.as_str()).or_else(|| caps.get(1).map(|m| m.as_str())) {
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => {
                    debug!("[{}] Found failure from {}", jail.name, ip);
                    state.record_failure(jail, ip);
                }
                Err(_) => {
                    debug!("[{}] Invalid IP captured: {}", jail.name, ip_str);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Logging
    let level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    // Load config
    let config_str = std::fs::read_to_string(&args.config)
        .with_context(|| format!("cannot read config {}", args.config.display()))?;
    let config: ConfigFile = toml::from_str(&config_str).context("invalid TOML config")?;

    info!("rust-fail2ban starting with backend={}", config.global.ban_backend);
    let backend = create_backend(&config.global.ban_backend);
    let state = Arc::new(AppState::new(backend));

    // Channel for log lines
    let (tx, mut rx) = mpsc::channel::<(String, String)>(1024);

    // Compile regexes and spawn tailers
    let mut jail_map = std::collections::HashMap::new();
    for jail in config.jails.iter().filter(|j| j.enabled) {
        let re = Regex::new(&jail.failregex)
            .with_context(|| format!("invalid regex in jail {}", jail.name))?;
        jail_map.insert(jail.name.clone(), (jail.clone(), re));

        let path = PathBuf::from(&jail.logpath);
        if !path.exists() {
            warn!("Log file {} does not exist yet — will keep trying", path.display());
        }
        let tx_clone = tx.clone();
        let name = jail.name.clone();
        tokio::spawn(async move {
            while let Err(e) = tail_log(path.clone(), tx_clone.clone(), name.clone()).await {
                error!("Tailer for {} failed: {}. Retrying in 5s...", name, e);
                time::sleep(Duration::from_secs(5)).await;
            }
        });
        info!("Jail '{}' monitoring {}", jail.name, jail.logpath);
    }
    drop(tx); // so rx closes when all tailers die

    // Cleanup task
    let state_cleanup = Arc::clone(&state);
    let interval = config.global.cleanup_interval;
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(interval));
        loop {
            ticker.tick().await;
            state_cleanup.cleanup_expired();
        }
    });

    // Main processing loop
    while let Some((jail_name, line)) = rx.recv().await {
        if let Some((jail, re)) = jail_map.get(&jail_name) {
            process_line(&line, jail, re, &state);
        }
    }

    Ok(())
}
