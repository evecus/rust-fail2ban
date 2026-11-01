//! silk: a minimal transparent proxy reusing the honk/dae kernel
//! datapath design — eBPF steers in the kernel, direct traffic never
//! reaches userspace, only proxy-bound flows enter this process.

mod bpf_raw;
mod cgroup;
mod config;
mod datapath;
mod dns;
mod hysteria2;
mod listener;
mod names;
mod ns;
mod outbound;
mod relay;
mod rules;
mod ruleset;
mod sniffer;
mod socks5;
mod vless;

use anyhow::{Context, Result};
use clap::Parser;
use rules::{SharedRules, StaticMaps};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(name = "silk")]
struct Args {
    /// Config file path (YAML). Used by the default run mode.
    #[arg(short, long, default_value = "/etc/silk/config.yaml")]
    config: String,

    /// Convert a source ruleset (list or sing-box JSON) to a binary ruleset
    /// and exit. Usage: silk --convert-ruleset geosite-cn.json [-o cn-domain]
    #[arg(long, value_name = "INPUT")]
    convert_ruleset: Option<String>,

    /// Output path for --convert-ruleset (default: input file stem).
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if let Some(input) = args.convert_ruleset {
        let input = std::path::Path::new(&input);
        // Default output: alongside the input, stem only
        // (/etc/silk/geosite-cn.json -> /etc/silk/geosite-cn).
        let output: std::path::PathBuf = match args.output {
            Some(o) => o.into(),
            None => {
                let stem = input.file_stem().context("input has no file name")?;
                input
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join(stem)
            }
        };
        ruleset::convert_source_to_binary(input, &output)?;
        return Ok(());
    }
    let raw =
        std::fs::read_to_string(&args.config).with_context(|| format!("read {}", args.config))?;
    let config: config::Config =
        serde_yaml_ng::from_str(&raw).context("parse config")?;
    config::validate(&config)?;

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("silk must run as root (TC, sk_lookup, netns, transparent sockets)");
    }

    // Resolve every hysteria2/vless server before any eBPF hook is attached,
    // so the lookup cannot loop through our own datapath. Node construction
    // itself happens later (it marks sockets, needing the datapath up).
    let needs = config::needs_proxy(&config);
    let mut resolved: std::collections::HashMap<String, SocketAddr> = Default::default();
    if needs {
        for node in &config.nodes {
            let (name, server) = match node {
                config::Node::Hysteria2(n) => (&n.name, &n.server),
                config::Node::Vless(n) => (&n.name, &n.server),
                _ => continue,
            };
            let addr = tokio::net::lookup_host(server.as_str())
                .await
                .with_context(|| format!("resolve {server}"))?
                .next()
                .with_context(|| format!("{server}: no address"))?;
            resolved.insert(name.clone(), addr);
        }
    }

    // 1. Proxy namespace + veth bridge.
    ns::create_silkns()?;
    datapath::setup_links(&config)?;

    // 2. eBPF: load, write globals, attach hooks, expose maps.
    let lan = match config.general.lan_spec() {
        Some(spec) => datapath::resolve_interface(spec)?,
        None => None,
    };
    let wan = match config.general.wan_spec() {
        Some(spec) => datapath::resolve_interface(spec)?,
        None => None,
    };
    let mut dp = datapath::load_and_attach(&config, lan.clone(), wan.clone())?;

    // 3. Routing: static surfaces now, domain surface via the DNS engine.
    // "list" rules import their ruleset files before the engines see them.
    let rules_list = config::expand_rules(&config)?;
    {
        let m = dp.maps.as_mut().expect("maps");
        m.add_private_direct()?;
        m.populate_cidr_ports(&rules_list)?;
        let n = m.add_local_direct()?;
        tracing::info!(local_addrs = n, "local addresses routed direct");
    }
    let rules_engine = rules::Rules::new(&config.general.default, &rules_list)?;
    tracing::info!(
        domain_rules = rules_engine.domain_rule_count,
        "domain matcher ready (source Vec + binary FST)"
    );
    let rules: SharedRules = Arc::new(Mutex::new(rules_engine));
    let maps: Arc<Mutex<StaticMaps>> = Arc::new(Mutex::new(dp.take_maps()));
    datapath::install_control_marker(&dp)?;

    // 4. Proxy nodes (sockets get control-marked; the datapath must be up).
    let mut router = outbound::Router::new();
    if needs {
        for node in &config.nodes {
            let outbound = match node {
                config::Node::Socks5(n) => {
                    let server: SocketAddr = n
                        .server
                        .parse()
                        .with_context(|| format!("parse socks5 server {}", n.server))?;
                    outbound::Outbound::Socks5(Arc::new(socks5::Socks5Client {
                        server,
                        username: n.username.clone(),
                        password: n.password.clone(),
                    }))
                }
                config::Node::Hysteria2(n) => {
                    let server = resolved[&n.name];
                    outbound::Outbound::Hysteria2(Arc::new(hysteria2::Hysteria2Client::new(
                        server,
                        n.password.clone(),
                        n.sni.clone(),
                        n.insecure,
                        &n.up,
                        &n.down,
                    )?))
                }
                config::Node::Vless(n) => {
                    let server = resolved[&n.name];
                    outbound::Outbound::Vless(Arc::new(vless::VlessClient::new(server, n)?))
                }
            };
            router.add(node.name().to_string(), Arc::new(outbound));
        }
        // Default node: the one named by general.default, else the first.
        let d = config.general.default.trim();
        if let Some(o) = router.get(d) {
            router.default = Some(o);
        }
        tracing::info!(nodes = ?router.names(), default = %d, "proxy nodes ready");
    } else {
        tracing::info!("no proxy verdicts configured; outbound disabled");
    }

    // 5. Transparent listeners inside silkns, published to the sockmap.
    let listeners = listener::create(&mut dp, true).context("create transparent listeners")?;

    // 6. Engines (outbound only when a proxy node is actually needed).
    let upstream: SocketAddr = config.dns.upstream.parse().context("parse dns upstream")?;
    let remote_upstream: Option<SocketAddr> = match config.dns.remote.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(s.parse().context("parse dns remote")?),
        _ => None,
    };
    if !config.cgroups.is_empty() {
        cgroup::start(&config::cgroup_rules(&config), maps.clone()).await?;
    }

    let names = Arc::new(names::NameCache::new());
    let dns = Arc::new(dns::DnsEngine::new(
        upstream,
        remote_upstream,
        rules.clone(),
        router.default.clone(),
        names.clone(),
    ));
    let router = Arc::new(router);
    let tcp_ctx = Arc::new(relay::TcpCtx {
        router: router.clone(),
        rules: rules.clone(),
        names: names.clone(),
        sniff: config.sniff.enable,
        dial_by_domain: config.sniff.dial_by_domain,
    });
    tracing::info!(
        sniff = config.sniff.enable,
        dial_by_domain = config.sniff.dial_by_domain,
        "tcp sniffing"
    );

    tracing::info!(?lan, ?wan, default = %config.general.default, "datapath up; relaying");

    // 7. Relay loops.
    let mut tcp_task = tokio::spawn(relay::run_tcp(listeners.tcp4, tcp_ctx));
    let mut udp_task = tokio::spawn(relay::run_udp(
        listeners.udp4,
        router.clone(),
        dns.clone(),
        maps.clone(),
    ));

    // 8. Run until a signal (or a relay crash), then tear everything down:
    // netlink-attached TC filters, the veth bridge and the proxy namespace
    // all outlive the process and must be removed explicitly.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut relay_result: Option<Result<()>> = None;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("interrupted; cleaning up");
        }
        _ = sigterm.recv() => {
            tracing::info!("terminated; cleaning up");
        }
        r = &mut tcp_task => {
            relay_result = Some(match r {
                Ok(v) => v,
                Err(e) => Err(anyhow::Error::new(e)),
            });
            tracing::warn!("tcp relay ended; cleaning up");
        }
        r = &mut udp_task => {
            relay_result = Some(match r {
                Ok(v) => v,
                Err(e) => Err(anyhow::Error::new(e)),
            });
            tracing::warn!("udp relay ended; cleaning up");
        }
    }
    tcp_task.abort();
    udp_task.abort();

    ns::cleanup(
        lan.as_ref().map(|(n, _)| n.as_str()),
        wan.as_ref().map(|(n, _)| n.as_str()),
        datapath::SILK0_HOST,
    );
    if let Some(r) = relay_result {
        r?;
    }
    Ok(())
}
