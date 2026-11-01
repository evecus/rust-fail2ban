//! Outbound abstraction: SOCKS5, Hysteria2 or VLESS behind one TCP/UDP dial surface.

use crate::hysteria2::Hysteria2Client;
use crate::rules::Action;
use crate::socks5::Socks5Client;
use crate::vless::VlessClient;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};

/// A bidirectional byte stream to the proxy exit.
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}
pub type BoxStream = Box<dyn ByteStream>;

pub enum Outbound {
    Socks5(Arc<Socks5Client>),
    Hysteria2(Arc<Hysteria2Client>),
    Vless(Arc<VlessClient>),
}

impl Outbound {
    /// Open a TCP connection to `dst` through the outbound. With `domain`
    /// the exit is asked to connect to `domain:port(dst)` (and resolve it
    /// itself) instead of the bare IP.
    pub async fn connect_tcp(&self, dst: SocketAddr, domain: Option<&str>) -> Result<BoxStream> {
        match self {
            Outbound::Socks5(c) => Ok(Box::new(c.connect_tcp(dst, domain).await?)),
            Outbound::Hysteria2(c) => Ok(Box::new(c.connect_tcp(dst, domain).await?)),
            Outbound::Vless(c) => c.connect_tcp(dst, domain).await,
        }
    }

    /// Establish a UDP relay channel. The returned handle carries both
    /// directions; drop it to tear the flow down.
    pub async fn udp_session(&self) -> Result<UdpUpstream> {
        match self {
            Outbound::Socks5(c) => {
                let (control, sock) = c.associate_udp().await?;
                Ok(UdpUpstream::Socks5 {
                    _control: control,
                    sock,
                })
            }
            Outbound::Hysteria2(c) => Ok(UdpUpstream::Hy2(c.udp_session().await?)),
            Outbound::Vless(c) => Ok(UdpUpstream::Vless(c.udp_session().await?)),
        }
    }
}

pub enum UdpUpstream {
    Socks5 {
        /// ASSOCIATE control connection; dropped with the flow.
        _control: TcpStream,
        sock: UdpSocket,
    },
    Hy2(crate::hysteria2::UdpSession),
    Vless(crate::vless::VlessUdpSession),
}

impl UdpUpstream {
    /// Send one datagram to `dst` through the outbound.
    pub async fn send(&self, payload: &[u8], dst: SocketAddr) -> Result<()> {
        match self {
            UdpUpstream::Socks5 { sock, .. } => {
                let mut pkt = vec![0u8, 0, 0];
                push_udp_addr(&mut pkt, dst);
                pkt.extend_from_slice(payload);
                sock.send(&pkt).await?;
                Ok(())
            }
            UdpUpstream::Hy2(s) => s.send(payload, dst).await,
            UdpUpstream::Vless(s) => s.send(payload, dst).await,
        }
    }

    /// Receive one relayed datagram into `buf`, returning its length.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        match self {
            UdpUpstream::Socks5 { sock, .. } => {
                let n = sock.recv(buf).await?;
                if n < 4 {
                    anyhow::bail!("short UDP relay packet");
                }
                let atyp = buf[3];
                let hdr_len = match atyp {
                    1 => 10,
                    4 => 22,
                    other => anyhow::bail!("UDP relay ATYP {other}"),
                };
                if n < hdr_len {
                    anyhow::bail!("short UDP relay header");
                }
                buf.copy_within(hdr_len..n, 0);
                Ok(n - hdr_len)
            }
            UdpUpstream::Hy2(s) => s.recv(buf).await,
            UdpUpstream::Vless(s) => s.recv(buf).await,
        }
    }
}

fn push_udp_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(a) => {
            buf.push(1);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            buf.push(4);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
    }
}

/// Node-name -> outbound router, shared by the relay and DNS engines.
pub struct Router {
    nodes: std::collections::HashMap<String, Arc<Outbound>>,
    /// Node used when a verdict names no (specific) node: the node named by
    /// `general.default`, or the first configured node.
    pub default: Option<Arc<Outbound>>,
}

impl Router {
    pub fn new() -> Self {
        Router {
            nodes: Default::default(),
            default: None,
        }
    }

    pub fn add(&mut self, name: String, outbound: Arc<Outbound>) {
        if self.default.is_none() {
            self.default = Some(outbound.clone());
        }
        self.nodes.insert(name, outbound);
    }

    pub fn get(&self, name: &str) -> Option<Arc<Outbound>> {
        self.nodes.get(name).cloned()
    }

    /// Outbound for a userspace verdict: the named node, falling back to the
    /// default node (unknown names were rejected at config validation).
    pub fn pick(&self, action: &Action) -> Option<Arc<Outbound>> {
        match action {
            Action::Node(n) => self.get(n).or_else(|| self.default.clone()),
            _ => self.default.clone(),
        }
    }

    pub fn names(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.nodes.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }
}
