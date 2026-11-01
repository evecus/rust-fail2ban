//! Configuration model (TOML). Deliberately a tiny subset of dae syntax:
//! ordered rule list + one outbound (SOCKS5 or Hysteria2) + one DNS upstream.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub general: General,
    /// Optional; only required when an outbound of type socks5 is actually used.
    #[serde(default)]
    pub socks5: Socks5,
    /// Optional; only required when outbound = "hysteria2".
    #[serde(default)]
    pub hysteria2: Hysteria2,
    /// Optional; only required when outbound = "vless".
    #[serde(default)]
    pub vless: Vless,
    pub dns: Dns,
    /// Optional; protocol sniffing + dial-by-domain for proxied TCP flows.
    #[serde(default)]
    pub sniff: Sniff,
    /// Optional per-process policy by cgroup v2 path (host traffic only).
    #[serde(default)]
    pub cgroups: Vec<CgroupRule>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// One per-cgroup policy. `path` is absolute (under /sys/fs/cgroup) or
/// relative to the cgroup v2 root; the rule covers the whole subtree and the
/// deepest matching rule wins.
#[derive(Debug, Deserialize)]
pub struct CgroupRule {
    pub path: String,
    /// "bypass" (alias "direct"): never captured. "proxy": public
    /// destinations are forced through the proxy.
    pub mode: String,
}

#[derive(Debug, Deserialize)]
pub struct Sniff {
    /// Peek at the first bytes of every proxied TCP flow for a TLS SNI or
    /// HTTP Host, re-run the domain rules on it, and dial by name.
    #[serde(default = "yes")]
    pub enable: bool,
    /// Dial the proxy exit with the domain (sniffed, or remembered from the
    /// DNS answer) instead of the bare IP, so the exit resolves it itself.
    #[serde(default = "yes")]
    pub dial_by_domain: bool,
}

impl Default for Sniff {
    fn default() -> Self {
        Sniff {
            enable: true,
            dial_by_domain: true,
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct General {
    /// LAN capture interface (gateway mode), e.g. "br-lan". Optional.
    pub lan_interface: Option<String>,
    /// WAN capture interface (host mode), e.g. "eth0". Optional.
    pub wan_interface: Option<String>,
    /// Skb mark steering traffic into the proxy namespace.
    pub tproxy_mark: Option<u32>,
    /// Verdict when no rule matches: "direct" | "proxy" | "block".
    #[serde(default = "default_verdict")]
    pub default_verdict: String,
    /// Outbound protocol: "socks5" | "hysteria2" | "vless" | "" (none).
    /// Empty is fine when no rule / default_verdict uses "proxy" and DNS
    /// does not need a remote (proxied) upstream.
    #[serde(default = "default_outbound")]
    pub outbound: String,
}

fn default_outbound() -> String {
    String::new()
}

fn default_verdict() -> String {
    "proxy".into()
}

#[derive(Debug, Default, Deserialize)]
pub struct Socks5 {
    /// "host:port"
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct Hysteria2 {
    /// "host:port" or "ip:port". Resolved via system DNS at startup.
    pub server: String,
    /// Auth credential (Hysteria-Auth header).
    #[serde(default)]
    pub password: String,
    /// TLS SNI; defaults to the server host.
    #[serde(default)]
    pub sni: String,
    /// Skip server certificate verification.
    #[serde(default)]
    pub insecure: bool,
    /// Local upload bandwidth ("100 Mbps", "80"); empty/"auto" = congestion control.
    #[serde(default)]
    pub up: String,
    /// Local download bandwidth; advertised to the server via Hysteria-CC-RX.
    #[serde(default)]
    pub down: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct Vless {
    /// VLESS server "host:port" or "ip:port" (hostname resolved via system
    /// DNS at startup, before the eBPF hooks are attached).
    #[serde(default)]
    pub server: String,
    /// VLESS user id (UUID).
    #[serde(default)]
    pub uuid: String,
    /// Transport: "tcp" | "ws".
    #[serde(default)]
    pub network: String,
    /// Wrap the transport in TLS (server must speak TLS on this port).
    #[serde(default)]
    pub tls: bool,
    /// TLS SNI; defaults to the server host.
    #[serde(default)]
    pub sni: String,
    /// Skip server certificate verification (self-signed servers).
    #[serde(default)]
    pub insecure: bool,
    /// WebSocket path (network = "ws"); defaults to "/".
    #[serde(default)]
    pub ws_path: String,
    /// WebSocket Host header; defaults to the SNI.
    #[serde(default)]
    pub ws_host: String,
}

#[derive(Debug, Deserialize)]
pub struct Dns {
    /// Upstream resolver, queried directly (control-plane marked socket).
    pub upstream: String,
    /// Optional overseas resolver, queried THROUGH the proxy outbound
    /// ("8.8.8.8:53"). Used for domains routed to the proxy, and for
    /// unmatched domains whose domestic answer is not a direct (CN) address.
    /// Unset = every domain is resolved by `upstream`.
    #[serde(default)]
    pub remote_upstream: Option<String>,
}

/// One routing rule; the list is evaluated in order and the first match on
/// its surface wins. Domain rules additionally drive the per-IP
/// DOMAIN_ROUTE map published by the DNS engine.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// "cidr" | "domain" | "port" | "source" | "list" | "binary"
    /// source/list = text (plain list or sing-box JSON); binary = ARST FST (.ars).
    pub kind: String,
    /// CIDR, domain suffix, port, or a ruleset file path for source/list/binary.
    pub value: String,
    /// "direct" | "proxy" | "block"
    pub verdict: String,
}

/// Expand `source` / `list` rules into concrete cidr/domain rules.
///
/// - `source` / `list`: plain list **or** sing-box JSON. Domains stay as
///   ordinary domain rules (Vec match at runtime — **no FST built at startup**).
/// - File is ARST / `.ars` → rewritten to `kind = "binary"` (FST).
pub fn expand_rules(config: &Config) -> Result<Vec<Rule>> {
    let mut out = Vec::new();
    for rule in &config.rules {
        if rule.kind == "binary" {
            out.push(rule.clone());
            continue;
        }
        if rule.kind != "source" && rule.kind != "list" {
            out.push(rule.clone());
            continue;
        }

        let path = std::path::Path::new(&rule.value);
        let raw = std::fs::read(path)
            .with_context(|| format!("read ruleset {}", rule.value))?;

        let is_ars = (raw.len() >= 4 && &raw[0..4] == b"ARST")
            || path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("ars"))
                .unwrap_or(false);
        if is_ars {
            out.push(Rule {
                kind: "binary".into(),
                value: rule.value.clone(),
                verdict: rule.verdict.clone(),
            });
            tracing::info!("imported binary ruleset {}", rule.value);
            continue;
        }

        let compiled = crate::ruleset::parse_source_bytes(&raw)
            .with_context(|| format!("parse source ruleset {}", rule.value))?;
        let n = compiled.domains.len()
            + compiled.domain_suffixes.len()
            + compiled.ipv4_cidrs.len()
            + compiled.ipv6_cidrs.len();
        out.extend(crate::ruleset::compiled_to_rules(&compiled, &rule.verdict));
        tracing::info!(
            path = %rule.value,
            entries = n,
            "imported source ruleset (no FST; use convert-ruleset for binary)"
        );
    }
    Ok(out)
}

/// Whether this config ever needs a working proxy outbound.
///
/// True if `default_verdict` is proxy, any rule verdict is proxy, or a
/// `dns.remote_upstream` is set (queried through the outbound). Otherwise
/// socks5/hysteria2/outbound may be omitted entirely.
pub fn needs_proxy(config: &Config) -> bool {
    if config.general.default_verdict.eq_ignore_ascii_case("proxy") {
        return true;
    }
    if config
        .dns
        .remote_upstream
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    config
        .rules
        .iter()
        .any(|r| r.verdict.eq_ignore_ascii_case("proxy"))
}

/// Validate outbound settings only when a proxy is actually required.
pub fn validate_outbound(config: &Config) -> Result<()> {
    if !needs_proxy(config) {
        return Ok(());
    }
    match config.general.outbound.as_str() {
        "socks5" => {
            if config.socks5.server.trim().is_empty() {
                anyhow::bail!(
                    "outbound = \"socks5\" but [socks5].server is empty                      (or omit proxy verdicts and set outbound = \"\")"
                );
            }
        }
        "hysteria2" => {
            if config.hysteria2.server.trim().is_empty() {
                anyhow::bail!(
                    "outbound = \"hysteria2\" but [hysteria2].server is empty"
                );
            }
        }
        "vless" => {
            if config.vless.server.trim().is_empty() {
                anyhow::bail!("outbound = \"vless\" but [vless].server is empty");
            }
            if config.vless.uuid.trim().is_empty() {
                anyhow::bail!("outbound = \"vless\" but [vless].uuid is empty");
            }
            let network = config.vless.network.trim().to_lowercase();
            if !network.is_empty() && network != "tcp" && network != "ws" {
                anyhow::bail!(
                    "[vless].network must be \"tcp\" or \"ws\" (got {network:?})"
                );
            }
        }
        "" => {
            anyhow::bail!(
                "proxy routing is configured (default_verdict/rules/dns.remote_upstream)                  but general.outbound is empty; set outbound = \"socks5\", \"hysteria2\" or \"vless\""
            );
        }
        other => anyhow::bail!("unknown outbound: {other}"),
    }
    Ok(())
}
