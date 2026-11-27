//! Native Rust port scanner: TCP connect scan + banner grabbing + light service detection.
//!
//! Replaces the external `nmap` dependency. No raw sockets, so no root/capabilities needed.
//! It does NOT do version-based CVE lookup (nmap's `vulners` script did); nuclei and the
//! enrichment layer cover that side.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use vs_core::{Finding, ScanOptions, Scanner, Severity, Target};

/// Commonly open / interesting TCP ports (curated; override with `PORTS`).
const DEFAULT_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 26, 53, 69, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 137, 139, 143, 161, 179, 389,
    427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025,
    1080, 1099, 1433, 1434, 1521, 1720, 1723, 1883, 2000, 2049, 2121, 2181, 2375, 2376, 3000, 3128, 3268, 3306,
    3389, 3690, 4000, 4369, 4443, 4444, 4567, 4848, 5000, 5001, 5060, 5432, 5555, 5601, 5672, 5900, 5984, 5985,
    5986, 6000, 6379, 6443, 6667, 7001, 7002, 7070, 7474, 8000, 8008, 8009, 8010, 8080, 8081, 8082, 8086, 8088,
    8090, 8161, 8443, 8444, 8500, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000,
    11211, 15672, 27017, 27018, 50000, 50070,
];

pub struct PortScan {
    pub ports: Vec<u16>,
    /// Max simultaneous connection attempts.
    pub concurrency: usize,
    pub connect_timeout: Duration,
    /// How long to wait for a banner the server sends by itself.
    pub banner_timeout: Duration,
    /// Refuse CIDR targets that expand to more hosts than this.
    pub max_hosts: usize,
}

impl Default for PortScan {
    fn default() -> Self {
        Self {
            ports: DEFAULT_PORTS.to_vec(),
            concurrency: 256,
            connect_timeout: Duration::from_millis(1500),
            banner_timeout: Duration::from_millis(800),
            max_hosts: 4096,
        }
    }
}

impl PortScan {
    /// Parse a port spec such as `22,80,8000-8100`. Port 0 and empty specs are rejected.
    pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
        let mut set = BTreeSet::new();
        for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (lo, hi) = match part.split_once('-') {
                Some((a, b)) => (a.trim().parse::<u16>(), b.trim().parse::<u16>()),
                None => (part.parse::<u16>(), part.parse::<u16>()),
            };
            let (lo, hi) = (lo.with_context(|| format!("bad port `{part}`"))?, hi.with_context(|| format!("bad port `{part}`"))?);
            if lo == 0 || lo > hi {
                bail!("bad port range `{part}`");
            }
            set.extend(lo..=hi);
        }
        if set.is_empty() {
            bail!("no ports given");
        }
        Ok(set.into_iter().collect())
    }

    async fn expand(&self, target: &Target) -> Result<Vec<IpAddr>> {
        match target {
            Target::Ip(ip) => Ok(vec![*ip]),
            Target::Cidr(net) => {
                let hosts: Vec<IpAddr> = net.hosts().take(self.max_hosts + 1).collect();
                if hosts.len() > self.max_hosts {
                    bail!("CIDR {net} expands to more than {} hosts", self.max_hosts);
                }
                Ok(hosts)
            }
            Target::Host(h) => {
                let mut ips: Vec<IpAddr> = tokio::net::lookup_host((h.as_str(), 0))
                    .await
                    .with_context(|| format!("cannot resolve {h}"))?
                    .map(|a| a.ip())
                    .collect();
                ips.sort();
                ips.dedup();
                if ips.is_empty() {
                    bail!("{h} has no address");
                }
                Ok(ips)
            }
        }
    }

    async fn scan_all(&self, target: &Target) -> Result<Vec<Finding>> {
        let ips = self.expand(target).await?;
        let mut addrs = Vec::with_capacity(ips.len() * self.ports.len());
        for &ip in &ips {
            addrs.extend(self.ports.iter().map(|&p| SocketAddr::new(ip, p)));
        }
        probe_all(addrs, self.concurrency, self.connect_timeout, self.banner_timeout).await
    }
}

/// Probe every address concurrently (bounded by `concurrency`); returns one finding per open port.
pub(crate) async fn probe_all(
    addrs: impl IntoIterator<Item = SocketAddr>,
    concurrency: usize,
    connect_to: Duration,
    banner_to: Duration,
) -> Result<Vec<Finding>> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = JoinSet::new();
    for addr in addrs {
        // Acquire before spawning so memory stays bounded for big scans.
        let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
        set.spawn(async move {
            let _permit = permit;
            probe(addr, connect_to, banner_to).await
        });
    }
    let mut findings = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Some(f) = res.context("scan task failed")? {
            findings.push(f);
        }
    }
    findings.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
    Ok(findings)
}

#[async_trait]
impl Scanner for PortScan {
    fn name(&self) -> &'static str {
        "portscan"
    }

    async fn run(&self, target: &Target, opts: &ScanOptions) -> Result<Vec<Finding>> {
        timeout(Duration::from_secs(opts.timeout_secs), self.scan_all(target))
            .await
            .map_err(|_| anyhow::anyhow!("portscan timed out after {}s", opts.timeout_secs))?
    }
}

/// Connect to one port; if open, grab a banner and build a finding.
async fn probe(addr: SocketAddr, connect_to: Duration, banner_to: Duration) -> Option<Finding> {
    let mut stream = timeout(connect_to, TcpStream::connect(addr)).await.ok()?.ok()?;
    let port = addr.port();
    let mut buf = vec![0u8; 1024];

    // 1) Many services (ssh, ftp, smtp, mysql...) speak first.
    let mut n = read_some(&mut stream, &mut buf, banner_to).await;
    // 2) Silent port: poke it with a harmless HTTP request.
    if n == 0 {
        let req = format!("HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: vuln-scanner\r\n\r\n", addr.ip());
        if timeout(banner_to, stream.write_all(req.as_bytes())).await.is_ok() {
            n = read_some(&mut stream, &mut buf, banner_to * 2).await;
        }
    }

    let (service, evidence) = identify(port, &buf[..n]);
    let host = addr.ip().to_string();
    let mut title = format!("Open port {port}/tcp");
    if let Some(s) = &service {
        title.push_str(&format!(" ({s})"));
    }
    Some(Finding {
        fingerprint: Finding::make_fingerprint(&host, Some(port), Some("tcp"), "open-port"),
        host,
        port: Some(port),
        protocol: Some("tcp".into()),
        service,
        title,
        severity: Severity::Info,
        cve: vec![],
        cvss: None,
        epss: None,
        kev: false,
        priority: 0.0,
        evidence,
        tool: "portscan".into(),
        fix_available: None,
        vendor_priority: None,
    })
}

async fn read_some(stream: &mut TcpStream, buf: &mut [u8], dur: Duration) -> usize {
    match timeout(dur, stream.read(buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    }
}

/// Guess `(service, evidence)` from the port number and whatever the server sent.
pub fn identify(port: u16, banner: &[u8]) -> (Option<String>, String) {
    let by_port = service_by_port(port).map(String::from);

    // MySQL/MariaDB handshake: [len:3][seq:1][proto=10][version\0 ...]
    if banner.len() > 6 && banner[3] == 0 && banner[4] == 10 {
        let ver: String = banner[5..]
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .filter(|c| c.is_ascii_graphic())
            .collect();
        if !ver.is_empty() && ver.starts_with(|c: char| c.is_ascii_digit()) {
            return (Some("mysql".into()), format!("MySQL {ver}"));
        }
    }

    let text = String::from_utf8_lossy(banner);
    let first = text.lines().next().unwrap_or("").trim();

    if let Some(rest) = first.strip_prefix("SSH-") {
        // "2.0-OpenSSH_8.2p1 Ubuntu-4" -> "OpenSSH 8.2p1"
        let soft = rest.split_once('-').map(|x| x.1).unwrap_or(rest);
        let soft = soft.split_whitespace().next().unwrap_or("").replacen('_', " ", 1);
        return (Some("ssh".into()), soft);
    }
    if first.starts_with("HTTP/") {
        let server = text
            .lines()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("server")).map(|(_, v)| v.trim()))
            .and_then(|v| v.split_whitespace().next())
            .map(|v| v.replacen('/', " ", 1))
            .unwrap_or_default();
        let svc = if matches!(port, 443 | 8443 | 4443 | 9443) { "https" } else { "http" };
        return (Some(svc.into()), server);
    }
    if let Some(rest) = first.strip_prefix("220") {
        let up = rest.to_ascii_uppercase();
        let svc = if up.contains("FTP") {
            "ftp"
        } else if up.contains("SMTP") || up.contains("ESMTP") {
            "smtp"
        } else {
            by_port.as_deref().unwrap_or("unknown")
        };
        return (Some(svc.into()), clean(rest));
    }
    if let Some(rest) = first.strip_prefix("+OK") {
        return (Some("pop3".into()), clean(rest));
    }
    if let Some(rest) = first.strip_prefix("* OK") {
        return (Some("imap".into()), clean(rest));
    }
    (by_port, clean(first))
}

/// Printable ASCII only, capped, so banners are safe to store and render.
fn clean(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(80).collect::<String>().trim().to_string()
}

fn service_by_port(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 | 2121 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 26 | 465 | 587 => "smtp",
        53 => "domain",
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8082 | 8088 | 8888 => "http",
        110 | 995 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 | 445 => "smb",
        143 | 993 => "imap",
        161 => "snmp",
        389 | 636 => "ldap",
        443 | 8443 => "https",
        1433 => "mssql",
        1521 => "oracle",
        1883 => "mqtt",
        2049 => "nfs",
        2375 | 2376 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        6379 => "redis",
        6443 => "kubernetes",
        9200 | 9300 => "elasticsearch",
        11211 => "memcached",
        27017 | 27018 => "mongodb",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_port_specs() {
        assert_eq!(PortScan::parse_ports("80, 22,8000-8002,22").unwrap(), vec![22, 80, 8000, 8001, 8002]);
        assert!(PortScan::parse_ports("").is_err());
        assert!(PortScan::parse_ports("0").is_err());
        assert!(PortScan::parse_ports("90-80").is_err());
        assert!(PortScan::parse_ports("70000").is_err());
        assert!(PortScan::parse_ports("abc").is_err());
    }

    #[test]
    fn identifies_banners() {
        let (s, e) = identify(2222, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n");
        assert_eq!((s.as_deref(), e.as_str()), (Some("ssh"), "OpenSSH 8.2p1"));

        let (s, e) = identify(80, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n");
        assert_eq!((s.as_deref(), e.as_str()), (Some("http"), "Apache 2.4.49"));

        let (s, _) = identify(2525, b"220 mail.example ESMTP Postfix\r\n");
        assert_eq!(s.as_deref(), Some("smtp"));

        let mut my = vec![0x4a, 0, 0, 0, 10];
        my.extend_from_slice(b"8.0.36-0ubuntu0\0rest");
        let (s, e) = identify(3306, &my);
        assert_eq!((s.as_deref(), e.as_str()), (Some("mysql"), "MySQL 8.0.36-0ubuntu0"));

        // Unknown banner falls back to the port table; control bytes are stripped.
        let (s, e) = identify(6379, b"\x01\x02weird\x00");
        assert_eq!((s.as_deref(), e.as_str()), (Some("redis"), "weird"));
        assert_eq!(identify(55555, b"").0, None);
    }

    #[tokio::test]
    async fn finds_open_port_with_banner_and_skips_closed() {
        let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = open.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if let Ok((mut s, _)) = open.accept().await {
                    let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
                }
            }
        });
        // Grab a port that is then closed again.
        let closed_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };

        let scanner = PortScan { ports: vec![open_port, closed_port], ..PortScan::default() };
        let t = Target::parse("127.0.0.1").unwrap();
        let f = scanner.run(&t, &ScanOptions::default()).await.unwrap();
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].port, Some(open_port));
        assert_eq!(f[0].service.as_deref(), Some("ssh"));
        assert_eq!(f[0].evidence, "OpenSSH 9.6");
        assert_eq!(f[0].tool, "portscan");
    }

    #[tokio::test]
    async fn rejects_oversized_cidr() {
        let scanner = PortScan { max_hosts: 16, ..PortScan::default() };
        let t = Target::parse("10.0.0.0/24").unwrap();
        assert!(scanner.run(&t, &ScanOptions::default()).await.is_err());
    }
}
