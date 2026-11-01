//! VLESS outbound (protocol aligned with Xray / ant's client).
//!
//! Transports: `tcp` | `ws`; TLS layer optional (rustls, skip-verify aware).
//!
//! * tcp: header written directly, response header read eagerly.
//! * ws: the VLESS header is merged into the first upstream write and the
//!   response header is skipped lazily on the first read (same as ant /
//!   sing-box). Waiting for the response eagerly would deadlock, since
//!   servers only answer once they got payload.
//!
//! Request: version(1) + uuid(16) + addon_len(1) + addon + cmd(1) + port(2 BE) + atyp + addr
//! Response: version(1) + addon_len(1) + addon
//!
//! Every socket this module dials is control-plane marked so the eBPF
//! datapath never loops on it.

mod ws;

use crate::config::Vless as VlessConfig;
use crate::datapath::mark_global_control;
use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;

use crate::outbound::BoxStream;

const VLESS_VERSION: u8 = 0;
const VLESS_CMD_TCP: u8 = 1;
const VLESS_CMD_UDP: u8 = 2;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

/// TLS + WS handshake timeout (matches ant / sing-box TCPTimeout).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct VlessClient {
    server: SocketAddr,
    uuid: [u8; 16],
    /// "tcp" | "ws"
    network: String,
    tls: bool,
    sni: String,
    ws_path: String,
    ws_host: String,
    tls_config: Option<Arc<ClientConfig>>,
}

impl VlessClient {
    pub fn new(server: SocketAddr, cfg: &VlessConfig) -> Result<Self> {
        let uuid = parse_uuid(cfg.uuid.trim())
            .with_context(|| format!("invalid vless uuid {:?}", cfg.uuid))?;
        let network = cfg.network.trim().to_lowercase();
        if network != "tcp" && network != "ws" {
            bail!("vless: unsupported network {network:?} (supported: tcp, ws)");
        }
        let server_host = cfg
            .server
            .rsplit_once(':')
            .map(|(h, _)| {
                h.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string()
            })
            .unwrap_or_else(|| server.ip().to_string());
        let sni = if cfg.sni.trim().is_empty() {
            server_host.clone()
        } else {
            cfg.sni.trim().to_string()
        };
        let ws_path = {
            let mut p = if cfg.ws_path.trim().is_empty() {
                "/".to_string()
            } else {
                cfg.ws_path.trim().to_string()
            };
            if !p.starts_with('/') {
                p.insert(0, '/');
            }
            p
        };
        let ws_host = if cfg.ws_host.trim().is_empty() {
            sni.clone()
        } else {
            cfg.ws_host.trim().to_string()
        };

        let tls_config = if cfg.tls {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok(); // already installed is fine
            // ws upgrade is HTTP/1.1; offer the matching ALPN there.
            let alpn: Vec<Vec<u8>> = if network == "ws" {
                vec![b"http/1.1".to_vec()]
            } else {
                Vec::new()
            };
            let builder = ClientConfig::builder();
            let mut config = if cfg.insecure {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(SkipVerify))
                    .with_no_client_auth()
            } else {
                let mut roots = RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            };
            config.alpn_protocols = alpn;
            Some(Arc::new(config))
        } else if cfg.insecure {
            tracing::warn!("vless: insecure set but tls is disabled — no effect");
            None
        } else {
            None
        };

        Ok(Self {
            server,
            uuid,
            network,
            tls: cfg.tls,
            sni,
            ws_path,
            ws_host,
            tls_config,
        })
    }

    /// Open a TCP connection to `dst` through the VLESS outbound. With
    /// `domain` the exit is asked to connect to `domain:port(dst)` (and
    /// resolve it itself) instead of the bare IP.
    pub async fn connect_tcp(&self, dst: SocketAddr, domain: Option<&str>) -> Result<BoxStream> {
        let header = build_vless_header(&self.uuid, domain, dst, VLESS_CMD_TCP);
        if self.network == "ws" {
            // Header merged into the first ws frame; response header is
            // skipped lazily (servers answer only after payload).
            return self.transport_with_header(header).await;
        }
        let mut io = self.transport().await?;
        io.write_all(&header).await.context("vless write request")?;
        read_vless_response(&mut io).await?;
        Ok(io)
    }

    /// Establish a UDP relay session (VLESS command=UDP, one stream per
    /// destination — silk gives every UDP flow its own session).
    pub async fn udp_session(self: &Arc<Self>) -> Result<VlessUdpSession> {
        Ok(VlessUdpSession {
            client: self.clone(),
            write: tokio::sync::Mutex::new(None),
            read: tokio::sync::Mutex::new(None),
        })
    }

    /// Underlying transport: TCP → (TLS) → (WS upgrade, ws network only).
    /// The `header`, when given, is merged into the first ws frame.
    async fn transport_with_header(&self, header: Vec<u8>) -> Result<BoxStream> {
        let tcp = self.dial().await?;
        let io: BoxStream = if self.tls {
            Box::new(self.wrap_tls(tcp).await?)
        } else {
            Box::new(tcp)
        };
        if self.network != "ws" {
            return Ok(io);
        }
        let ws = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws::WsStream::connect(io, self))
            .await
            .map_err(|_| anyhow!("vless ws handshake timed out after {}s", HANDSHAKE_TIMEOUT.as_secs()))?
            .context("vless ws handshake")?;
        Ok(Box::new(ws.with_header(header)))
    }

    /// Underlying transport: TCP → (TLS) → (WS upgrade).
    async fn transport(&self) -> Result<BoxStream> {
        self.transport_with_header(Vec::new()).await
    }

    async fn dial(&self) -> Result<TcpStream> {
        let sock = if self.server.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Err(e) = mark_global_control(sock.as_raw_fd()) {
            // Only expected in tests / before the eBPF marker is installed;
            // production always installs it before the outbound is built.
            tracing::warn!("vless: control mark unavailable, dialing unmarked: {e:#}");
        }
        let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, sock.connect(self.server))
            .await
            .map_err(|_| anyhow!("vless dial {} timeout", self.server))?
            .with_context(|| format!("vless dial {}", self.server))?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    async fn wrap_tls(&self, tcp: TcpStream) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let cfg = self
            .tls_config
            .as_ref()
            .context("vless tls enabled but no tls config")?;
        let name = ServerName::try_from(self.sni.clone())
            .map_err(|_| anyhow!("invalid vless sni {:?}", self.sni))?;
        let conn = TlsConnector::from(cfg.clone()).connect(name, tcp);
        tokio::time::timeout(HANDSHAKE_TIMEOUT, conn)
            .await
            .map_err(|_| anyhow!("vless tls handshake timed out after {}s", HANDSHAKE_TIMEOUT.as_secs()))?
            .context("vless tls handshake")
    }
}

/// Lazily established VLESS UDP stream (command=UDP). The relay gives every
/// (client, destination) pair its own session, so a single stream carrying
/// u16be-length framed datagrams in both directions is sufficient.
pub struct VlessUdpSession {
    client: Arc<VlessClient>,
    write: tokio::sync::Mutex<Option<tokio::io::WriteHalf<BoxStream>>>,
    read: tokio::sync::Mutex<Option<tokio::io::ReadHalf<BoxStream>>>,
}

impl VlessUdpSession {
    /// Send one datagram to `dst`. Opens the VLESS UDP stream on first use.
    pub async fn send(&self, payload: &[u8], dst: SocketAddr) -> Result<()> {
        let mut guard = self.write.lock().await;
        if guard.is_none() {
            let header = build_vless_header(&self.client.uuid, None, dst, VLESS_CMD_UDP);
            let mut io = self.client.transport().await?;
            io.write_all(&header).await.context("vless udp write request")?;
            read_vless_response(&mut io).await?;
            let (r, w) = tokio::io::split(io);
            *self.read.lock().await = Some(r);
            *guard = Some(w);
        }
        if payload.is_empty() || payload.len() > u16::MAX as usize {
            bail!("vless udp payload size out of range: {}", payload.len());
        }
        let w = guard.as_mut().unwrap();
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        w.write_all(&frame).await.context("vless udp write")
    }

    /// Receive one relayed datagram into `buf`, returning its length.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.read.lock().await;
            if let Some(r) = guard.as_mut() {
                let mut lenb = [0u8; 2];
                r.read_exact(&mut lenb).await.context("vless udp len")?;
                let n = u16::from_be_bytes(lenb) as usize;
                if n == 0 {
                    return Ok(0);
                }
                if n > buf.len() {
                    bail!("vless udp datagram {} exceeds buffer {}", n, buf.len());
                }
                r.read_exact(&mut buf[..n]).await.context("vless udp body")?;
                return Ok(n);
            }
            drop(guard);
            // The stream opens on the first send; wait for it.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        bail!("uuid must contain 32 hex digits, got {}", hex.len());
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("bad uuid byte {}", i))?;
    }
    Ok(out)
}

/// Build the VLESS request header. `domain` (a name the exit should resolve)
/// is sent as ATYP_DOMAIN instead of the bare IP.
fn build_vless_header(
    uuid: &[u8; 16],
    domain: Option<&str>,
    dst: SocketAddr,
    cmd: u8,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(22 + 260);
    buf.push(VLESS_VERSION);
    buf.extend_from_slice(uuid);
    buf.push(0); // addon len (no flow support)
    buf.push(cmd);
    buf.extend_from_slice(&dst.port().to_be_bytes());
    if let Some(d) = domain
        .filter(|d| !d.is_empty() && d.len() <= 255 && d.parse::<IpAddr>().is_err())
    {
        buf.push(ATYP_DOMAIN);
        buf.push(d.len() as u8);
        buf.extend_from_slice(d.as_bytes());
        return buf;
    }
    match dst.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf
}

/// Read the VLESS response header `[ver 1B][addon_len 1B][addon]`.
async fn read_vless_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let mut ver = [0u8; 1];
    r.read_exact(&mut ver)
        .await
        .context("vless read response version")?;
    if ver[0] != VLESS_VERSION {
        bail!("vless unexpected response version {}", ver[0]);
    }
    let mut alen = [0u8; 1];
    r.read_exact(&mut alen)
        .await
        .context("vless read addon len")?;
    if alen[0] > 0 {
        let mut addon = vec![0u8; alen[0] as usize];
        r.read_exact(&mut addon)
            .await
            .context("vless read addon")?;
    }
    Ok(())
}

/// Length of the VLESS response header at the start of `buf`, or None if
/// incomplete / invalid (ws path: skipped lazily from the first frame).
pub(crate) fn vless_response_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 || buf[0] != VLESS_VERSION {
        return None;
    }
    let n = 2 + buf[1] as usize;
    (buf.len() >= n).then_some(n)
}

#[derive(Debug)]
struct SkipVerify;

impl ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parsing() {
        let u = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u, [0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee]);
        assert!(parse_uuid("nope").is_err());
    }

    #[test]
    fn header_domain_and_ip() {
        let uuid = [7u8; 16];
        let h = build_vless_header(&uuid, Some("example.com"), "1.2.3.4:443".parse().unwrap(), VLESS_CMD_TCP);
        // ver + uuid + addon + cmd + port + atyp + len + name
        assert_eq!(h[0], 0);
        assert_eq!(&h[1..17], &uuid);
        assert_eq!(h[17], 0, "addon len");
        assert_eq!(h[18], VLESS_CMD_TCP);
        assert_eq!(&h[19..21], &443u16.to_be_bytes());
        assert_eq!(h[21], ATYP_DOMAIN);
        assert_eq!(h[22], 11);
        assert_eq!(&h[23..], b"example.com");

        // IP-looking "domain" falls through to the bare address.
        let h = build_vless_header(&uuid, Some("1.2.3.4"), "1.2.3.4:80".parse().unwrap(), VLESS_CMD_TCP);
        assert_eq!(h[21], ATYP_IPV4);
        assert_eq!(&h[22..], &[1, 2, 3, 4]);

        let h = build_vless_header(&uuid, None, "[::1]:80".parse().unwrap(), VLESS_CMD_UDP);
        assert_eq!(h[18], VLESS_CMD_UDP);
        assert_eq!(h[21], ATYP_IPV6);
    }

    #[test]
    fn response_len_parser() {
        assert_eq!(vless_response_len(&[0, 0]), Some(2));
        assert_eq!(vless_response_len(&[0, 3, 1, 2, 3]), Some(5));
        assert_eq!(vless_response_len(&[0, 3, 1]), None, "incomplete");
        assert_eq!(vless_response_len(&[1, 0]), None, "bad version");
        assert_eq!(vless_response_len(&[0]), None);
    }

    fn test_cfg(port: u16, network: &str, tls: bool) -> VlessConfig {
        VlessConfig {
            server: format!("127.0.0.1:{port}"),
            uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            network: network.into(),
            tls,
            sni: "example.com".into(),
            insecure: true,
            ws_path: "/ws".into(),
            ws_host: String::new(),
        }
    }

    /// VLESS over plain TCP: header written directly, response header read
    /// eagerly, payload relayed both ways. Header layout:
    /// ver(1)+uuid(16)+addon(1)+cmd(1)+port(2)+atyp(1)+len(1)+domain(11) = 34.
    #[tokio::test]
    async fn vless_tcp_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut s, _) = listener.accept().await.unwrap();
            // 34-byte VLESS request header; the payload ("hello") only
            // follows after the server's response header.
            let mut req = vec![0u8; 34];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0, "vless version");
            assert_eq!(
                &req[1..17],
                &[0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc,
                  0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee]
            );
            assert_eq!(req[17], 0, "addon len");
            assert_eq!(req[18], VLESS_CMD_TCP);
            assert_eq!(req[21], ATYP_DOMAIN);
            s.write_all(&[0u8, 0u8]).await.unwrap();
            s.write_all(b"world").await.unwrap();
            let mut payload = vec![0u8; 5];
            s.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"hello");
        });

        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = VlessClient::new(server_addr, &test_cfg(port, "tcp", false)).unwrap();
        let mut s = client
            .connect_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }

    /// VLESS over plain WS: header merged into the first (masked) frame,
    /// response header stripped from the first incoming frame.
    #[tokio::test]
    async fn vless_ws_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut s, _) = listener.accept().await.unwrap();
            // Read the upgrade request head.
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&req).to_lowercase();
            assert!(head.starts_with("get /ws http/1.1"), "head: {head}");
            assert!(head.contains("upgrade: websocket"), "head: {head}");
            assert!(head.contains("sec-websocket-key: "), "head: {head}");
            assert!(head.contains("host: example.com"), "head: {head}");
            s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: ignored-by-this-client\r\n\
                  \r\n",
            )
            .await
            .unwrap();

            // First client frame: VLESS header (34) + "hello" = 39 payload.
            let frame_len = 2 + 4 + 39; // FIN|opcode + mask|len7 + mask key
            let mut frame = vec![0u8; frame_len];
            s.read_exact(&mut frame).await.unwrap();
            let (op, fin, payload) = decode_client_frame(&frame);
            assert_eq!(op, 0x2, "binary");
            assert!(fin);
            assert_eq!(payload[0], 0, "vless version");
            assert_eq!(&payload[34..], b"hello");

            // Reply: unmasked binary frame with VLESS response header.
            let mut reply = vec![0x82u8, 7];
            reply.extend_from_slice(&[0u8, 0u8]);
            reply.extend_from_slice(b"world");
            s.write_all(&reply).await.unwrap();
        });

        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = VlessClient::new(server_addr, &test_cfg(port, "ws", false)).unwrap();
        let mut s = client
            .connect_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }

    /// Unmask a client frame the way a server would.
    fn decode_client_frame(frame: &[u8]) -> (u8, bool, Vec<u8>) {
        let opcode = frame[0] & 0x0f;
        let fin = frame[0] & 0x80 != 0;
        assert!(frame[1] & 0x80 != 0, "client frames must be masked");
        let len7 = (frame[1] & 0x7f) as usize;
        let (len, mut pos) = match len7 {
            126 => (u16::from_be_bytes([frame[2], frame[3]]) as usize, 4),
            127 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&frame[2..10]);
                (u64::from_be_bytes(b) as usize, 10)
            }
            l => (l, 2),
        };
        let key = [frame[pos], frame[pos + 1], frame[pos + 2], frame[pos + 3]];
        pos += 4;
        let payload: Vec<u8> = frame[pos..pos + len]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        (opcode, fin, payload)
    }

    /// TLS config paths build (SkipVerify / webpki roots); no handshake here.
    #[test]
    fn vless_tls_config_builds() {
        let server_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let c = VlessClient::new(server_addr, &test_cfg(1, "tcp", true)).unwrap();
        assert!(c.tls_config.is_some());
        // insecure=false also builds (webpki roots).
        let mut cfg = test_cfg(1, "tcp", true);
        cfg.insecure = false;
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert!(c.tls_config.is_some());
        // Plain tcp: no TLS config.
        let c = VlessClient::new(server_addr, &test_cfg(1, "tcp", false)).unwrap();
        assert!(c.tls_config.is_none());
        // ws forces http/1.1 ALPN.
        let c = VlessClient::new(server_addr, &test_cfg(1, "ws", true)).unwrap();
        assert_eq!(c.tls_config.unwrap().alpn_protocols, vec![b"http/1.1".to_vec()]);
        // Unknown network fails fast.
        assert!(VlessClient::new(server_addr, &test_cfg(1, "grpc", false)).is_err());
    }
}
