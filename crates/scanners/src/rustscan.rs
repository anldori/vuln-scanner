//! RustScan plugin (https://github.com/RustScan/RustScan).
//!
//! RustScan finds open ports very fast (all 65535 by default, greppable mode, no nmap).
//! Each open port is then banner-probed by our own code (`portscan::probe_all`) for
//! service/version evidence.

use crate::exec::run_capture;
use crate::portscan::{probe_all, PortScan};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use vs_core::{Finding, ScanOptions, Scanner, Target};

pub struct RustScan {
    pub binary: String,
    /// Port spec such as `1-1024` or `22,80,8000-8100`; `None` = all 65535 ports.
    pub ports: Option<Vec<u16>>,
    pub batch_size: u32,
    pub timeout_ms: u32,
}

impl Default for RustScan {
    fn default() -> Self {
        Self { binary: "rustscan".into(), ports: None, batch_size: 2000, timeout_ms: 1500 }
    }
}

impl RustScan {
    /// Argv for rustscan. The target is the *attached* value of `--addresses=`, so it can never
    /// be parsed as a separate option.
    pub fn build_args(&self, target: &Target) -> Vec<String> {
        let mut args: Vec<String> = vec![
            format!("--addresses={}", target.as_arg()),
            "--no-config".into(),
            "--no-banner".into(),
            "--greppable".into(),
            "--scripts=none".into(),
            format!("--batch-size={}", self.batch_size),
            format!("--timeout={}", self.timeout_ms),
        ];
        match &self.ports {
            None => args.push("--range=1-65535".into()),
            Some(p) if p.len() > 1 && p.windows(2).all(|w| w[1] == w[0] + 1) => {
                args.push(format!("--range={}-{}", p[0], p[p.len() - 1]))
            }
            Some(p) => args.push(format!("--ports={}", p.iter().map(u16::to_string).collect::<Vec<_>>().join(","))),
        }
        args
    }
}

#[async_trait]
impl Scanner for RustScan {
    fn name(&self) -> &'static str {
        "rustscan"
    }

    async fn run(&self, target: &Target, opts: &ScanOptions) -> Result<Vec<Finding>> {
        let started = std::time::Instant::now();
        opts.log("rustscan: scanning ports...");
        let out = run_capture(&self.binary, &self.build_args(target), opts.timeout_secs).await?;
        let addrs = parse_greppable(&out);
        opts.log(&format!("rustscan: {} open port(s) found; grabbing banners", addrs.len()));
        // Banner grabbing gets whatever time is left of the overall budget.
        let left = Duration::from_secs(opts.timeout_secs).saturating_sub(started.elapsed());
        let ps = PortScan::default();
        tokio::time::timeout(left, probe_all(addrs, ps.concurrency, ps.connect_timeout, ps.banner_timeout))
            .await
            .context("banner grabbing timed out")?
    }
}

/// Parse lines like `127.0.0.1 -> [22,80,443]`; anything else is ignored.
pub fn parse_greppable(out: &str) -> Vec<SocketAddr> {
    let mut v = Vec::new();
    for line in out.lines() {
        let Some((ip, ports)) = line.split_once(" -> ") else { continue };
        let Ok(ip) = ip.trim().parse::<IpAddr>() else { continue };
        let ports = ports.trim().trim_start_matches('[').trim_end_matches(']');
        v.extend(ports.split(',').filter_map(|p| p.trim().parse::<u16>().ok()).filter(|&p| p != 0).map(|p| SocketAddr::new(ip, p)));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_greppable_output() {
        let out = "Some noise\n127.0.0.1 -> [22,80,18080]\n::1 -> [443]\n10.0.0.1 -> []\nbad -> [1]\n";
        let a = parse_greppable(out);
        let s: Vec<String> = a.iter().map(|x| x.to_string()).collect();
        assert_eq!(s, ["127.0.0.1:22", "127.0.0.1:80", "127.0.0.1:18080", "[::1]:443"]);
    }

    #[test]
    fn target_is_attached_to_option() {
        let r = RustScan::default();
        let args = r.build_args(&Target::parse("10.0.0.5").unwrap());
        assert_eq!(args[0], "--addresses=10.0.0.5");
        assert!(args.contains(&"--range=1-65535".to_string()));
        let r = RustScan { ports: Some(vec![22, 80]), ..RustScan::default() };
        assert!(r.build_args(&Target::parse("10.0.0.5").unwrap()).contains(&"--ports=22,80".to_string()));
        let r = RustScan { ports: Some(vec![1, 2, 3]), ..RustScan::default() };
        assert!(r.build_args(&Target::parse("10.0.0.5").unwrap()).contains(&"--range=1-3".to_string()));
    }

    /// Needs the real `rustscan` binary: `cargo test -p vs-scanners -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_rustscan_finds_local_listener() {
        use tokio::io::AsyncWriteExt;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
            }
        });
        let r = RustScan { ports: Some(vec![port.saturating_sub(1).max(1), port]), ..RustScan::default() };
        let f = r.run(&Target::parse("127.0.0.1").unwrap(), &ScanOptions::default()).await.unwrap();
        let hit = f.iter().find(|x| x.port == Some(port)).expect("listener not found");
        assert_eq!(hit.service.as_deref(), Some("ssh"));
        assert_eq!(hit.evidence, "OpenSSH 9.6");
    }
}
