//! Configuration model (YAML). Deliberately a tiny subset of dae syntax:
//! named nodes (SOCKS5 / Hysteria2 / VLESS) + ordered rule list + split DNS.
//!
//! Every verdict ("direct", "block" or a node `name`) is matched top-down;
//! "direct" and "block" are resolved entirely in the kernel, anything else
//! captures the flow into userspace and selects the node by name.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    /// Proxy nodes; `type` selects the protocol, `name` is referenced by
    /// rules / cgroups / general.default. Several nodes may share a type.
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub dns: Dns,
    #[serde(default)]
    pub sniff: Sniff,
    /// cgroup path (or bare service name) -> verdict.
    #[serde(default)]
    pub cgroups: BTreeMap<String, String>,
    /// One "kind,value,verdict" string per entry, evaluated top-down.
    #[serde(default, deserialize_with = "rule_lines")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Default, Deserialize)]
pub struct General {
    /// LAN capture interface (gateway mode): "auto", an interface name, or
    /// empty to disable LAN capture.
    #[serde(default)]
    pub lan: Option<String>,
    /// WAN capture interface (host mode): "auto", a name, or empty to
    /// disable host-originated capture.
    #[serde(default)]
    pub wan: Option<String>,
    /// Skb mark steering traffic into the proxy namespace.
    pub tproxy_mark: Option<u32>,
    /// Verdict when no rule matches: "direct" | "block" | a node name.
    #[serde(default = "default_verdict")]
    pub default: String,
}

fn default_verdict() -> String {
    "direct".into()
}

impl General {
    /// Interface spec for capture: None = "all" (auto / unset / empty).
    pub fn lan_spec(&self) -> Option<&str> {
        interface_spec(self.lan.as_deref())
    }

    pub fn wan_spec(&self) -> Option<&str> {
        interface_spec(self.wan.as_deref())
    }
}

fn interface_spec(v: Option<&str>) -> Option<&str> {
    v.map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
}

/// One proxy node. `type` is the protocol tag ("socks5", alias "socks";
/// "hysteria2"; "vless"); every other field belongs to the payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Node {
    #[serde(alias = "socks")]
    Socks5(Socks5Node),
    Hysteria2(Hy2Node),
    Vless(VlessNode),
}

impl Node {
    pub fn name(&self) -> &str {
        match self {
            Node::Socks5(n) => &n.name,
            Node::Hysteria2(n) => &n.name,
            Node::Vless(n) => &n.name,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Socks5Node {
    /// Unique node name referenced by rules / cgroups / general.default.
    pub name: String,
    /// "host:port" (host must be a literal address).
    pub server: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Hy2Node {
    pub name: String,
    /// "host:port" or "ip:port" (hostname resolved via system DNS at startup).
    pub server: String,
    #[serde(default)]
    pub password: String,
    /// TLS SNI; defaults to the server host.
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub insecure: bool,
    /// Local upload bandwidth ("80 Mbps"); empty/"auto" = congestion control.
    #[serde(default)]
    pub up: String,
    /// Local download bandwidth; advertised via Hysteria-CC-RX.
    #[serde(default)]
    pub down: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VlessNode {
    pub name: String,
    /// "host:port" or "ip:port" (hostname resolved via system DNS at startup).
    pub server: String,
    /// VLESS user id (UUID).
    pub uuid: String,
    /// Transport: "tcp" | "ws".
    #[serde(default)]
    pub network: String,
    /// Wrap the transport in TLS.
    #[serde(default)]
    pub tls: bool,
    /// TLS SNI; defaults to the server host.
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub insecure: bool,
    /// WebSocket path (network = "ws"); defaults to "/".
    #[serde(default)]
    pub ws_path: String,
    /// WebSocket Host header; defaults to the SNI.
    #[serde(default)]
    pub ws_host: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct Dns {
    /// Domestic resolver, queried directly (control-plane marked socket).
    #[serde(default = "default_dns_upstream")]
    pub upstream: String,
    /// Overseas resolver, queried through the default proxy node; without it
    /// every domain is resolved by `upstream`.
    #[serde(default)]
    pub remote: Option<String>,
}

fn default_dns_upstream() -> String {
    "223.5.5.5:53".into()
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

/// One per-cgroup policy (host traffic only). `path` is relative to the
/// cgroup v2 root (or absolute); the rule covers the whole subtree and the
/// deepest matching rule wins.
#[derive(Debug, Clone, Deserialize)]
pub struct CgroupRule {
    pub path: String,
    /// "bypass" (alias "direct") or a node name ("block" is not supported
    /// here — cgroups only steer between bypass and proxy capture).
    pub mode: String,
}

/// One routing rule; the list is evaluated in order and the first match on
/// its surface wins. Domain rules additionally drive the per-IP
/// DOMAIN_ROUTE map published by the DNS engine.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// "cidr" | "domain" | "port" | "source" | "list" | "binary"
    /// source/list = text (plain list or sing-box JSON); binary = ARST FST
    /// ruleset (built by --convert-ruleset, any file name).
    pub kind: String,
    /// CIDR, domain suffix, port, or a ruleset file path for source/list/binary.
    pub value: String,
    /// "direct" | "block" | a node name.
    pub verdict: String,
}

/// Parse one "kind,value,verdict" rule line.
pub fn parse_rule_line(line: &str) -> Result<Rule> {
    let line = line.trim();
    let (kind, rest) = line
        .split_once(',')
        .with_context(|| format!("rule {line:?}: expected kind,value,verdict"))?;
    let (value, verdict) = rest
        .rsplit_once(',')
        .with_context(|| format!("rule {line:?}: expected kind,value,verdict"))?;
    Ok(Rule {
        kind: kind.trim().to_ascii_lowercase(),
        value: value.trim().to_string(),
        verdict: verdict.trim().to_string(),
    })
}

fn rule_lines<'de, D>(d: D) -> Result<Vec<Rule>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let lines: Vec<String> = Deserialize::deserialize(d)?;
    lines
        .iter()
        .map(|l| parse_rule_line(l).map_err(serde::de::Error::custom))
        .collect()
}

/// Bare cgroup names are shorthand for system services:
/// `frps: bypass` == `system.slice/frps.service: bypass`. Anything containing
/// a slash is used verbatim (e.g. user-1000.slice/session-c1.scope).
pub fn cgroup_rules(config: &Config) -> Vec<CgroupRule> {
    config
        .cgroups
        .iter()
        .map(|(k, mode)| {
            let path = if k.contains('/') {
                k.clone()
            } else {
                format!("system.slice/{k}.service")
            };
            CgroupRule {
                path,
                mode: mode.clone(),
            }
        })
        .collect()
}

/// Expand `source` / `list` rules into concrete cidr/domain rules.
///
/// - `source` / `list`: plain list **or** sing-box JSON. Domains stay as
///   ordinary domain rules (Vec match at runtime — **no FST built at startup**).
/// - File is ARST (or `.ars`) → rewritten to `kind = "binary"` (FST).
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
        let raw =
            std::fs::read(path).with_context(|| format!("read ruleset {}", rule.value))?;

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

/// Classify a verdict string: "direct" ("bypass" alias) | "block" | a
/// configured node name.
pub fn classify_verdict(s: &str, node_names: &[&str]) -> Result<()> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("direct")
        || t.eq_ignore_ascii_case("bypass")
        || t.eq_ignore_ascii_case("block")
    {
        return Ok(());
    }
    if node_names.contains(&t) {
        return Ok(());
    }
    if node_names.is_empty() {
        anyhow::bail!("verdict {t:?} is not \"direct\"/\"block\" and no nodes are defined");
    }
    anyhow::bail!(
        "verdict {t:?} does not match any node name (defined: {})",
        node_names.join(", ")
    );
}

/// Whether this config ever needs a working proxy node.
///
/// True if the default verdict or any rule/cgroup verdict names a node, or a
/// `dns.remote` is set (queried through the default node). Otherwise the
/// whole `nodes` section may be omitted.
pub fn needs_proxy(config: &Config) -> bool {
    let node_used = |s: &str| {
        !(s.eq_ignore_ascii_case("direct") || s.eq_ignore_ascii_case("block"))
    };
    if node_used(config.general.default.trim()) {
        return true;
    }
    if config
        .dns
        .remote
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    if config.rules.iter().any(|r| node_used(&r.verdict)) {
        return true;
    }
    config.cgroups.values().any(|m| node_used(m))
}

/// Validate verdict references and node settings up front.
pub fn validate(config: &Config) -> Result<()> {
    let node_names: Vec<&str> = config.nodes.iter().map(Node::name).collect();
    let mut seen = std::collections::BTreeSet::new();
    for n in &node_names {
        if !seen.insert(*n) {
            anyhow::bail!("duplicate node name: {n:?}");
        }
    }

    classify_verdict(&config.general.default, &node_names)
        .context("general.default")?;
    for r in &config.rules {
        classify_verdict(&r.verdict, &node_names)
            .with_context(|| format!("rule {}/{},{}", r.kind, r.value, r.verdict))?;
    }
    for (path, mode) in &config.cgroups {
        classify_verdict(mode, &node_names)
            .with_context(|| format!("cgroups {path:?}"))?;
    }

    for node in &config.nodes {
        match node {
            Node::Socks5(n) => {
                if n.server.trim().is_empty() {
                    anyhow::bail!("nodes.socks5 ({}): server is empty", n.name);
                }
            }
            Node::Hysteria2(n) => {
                if n.server.trim().is_empty() {
                    anyhow::bail!("nodes.hysteria2 ({}): server is empty", n.name);
                }
            }
            Node::Vless(n) => {
                if n.server.trim().is_empty() {
                    anyhow::bail!("nodes.vless ({}): server is empty", n.name);
                }
                if n.uuid.trim().is_empty() {
                    anyhow::bail!("nodes.vless ({}): uuid is empty", n.name);
                }
                let network = n.network.trim().to_lowercase();
                if !network.is_empty() && network != "tcp" && network != "ws" {
                    anyhow::bail!(
                        "nodes.vless ({}): network must be \"tcp\" or \"ws\" (got {network:?})",
                        n.name
                    );
                }
            }
        }
    }
    Ok(())
}
