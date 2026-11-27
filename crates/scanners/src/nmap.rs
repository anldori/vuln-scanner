//! nmap plugin: runs `nmap -oX -` and converts the XML into [`Finding`]s.

use crate::exec::run_capture;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use vs_core::{Finding, ScanOptions, Scanner, Severity, Target};

pub struct Nmap {
    pub binary: String,
    /// Extra nmap NSE script categories, e.g. `vulners`. Fixed by us, never user input.
    pub scripts: Vec<String>,
}

impl Default for Nmap {
    fn default() -> Self {
        Self { binary: "nmap".into(), scripts: vec![] }
    }
}

impl Nmap {
    /// Argv for nmap. Target is placed after `--` so it can never be parsed as an option.
    pub fn build_args(&self, target: &Target) -> Vec<String> {
        let mut args: Vec<String> = ["-sV", "-T4", "--top-ports", "1000", "-oX", "-", "--no-stylesheet"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if !self.scripts.is_empty() {
            args.push(format!("--script={}", self.scripts.join(",")));
        }
        args.push("--".into());
        args.push(target.as_arg());
        args
    }
}

#[async_trait]
impl Scanner for Nmap {
    fn name(&self) -> &'static str {
        "nmap"
    }

    async fn run(&self, target: &Target, opts: &ScanOptions) -> Result<Vec<Finding>> {
        let out = run_capture(&self.binary, &self.build_args(target), opts.timeout_secs).await?;
        parse_xml(&out)
    }
}

// ---- XML model (only the parts we need) ----

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "host", default)]
    hosts: Vec<Host>,
}

#[derive(Debug, Deserialize)]
struct Host {
    status: Option<Status>,
    #[serde(rename = "address", default)]
    addresses: Vec<Address>,
    ports: Option<Ports>,
}

#[derive(Debug, Deserialize)]
struct Status {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct Address {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: String,
}

#[derive(Debug, Deserialize)]
struct Ports {
    #[serde(rename = "port", default)]
    ports: Vec<Port>,
}

#[derive(Debug, Deserialize)]
struct Port {
    #[serde(rename = "@protocol")]
    protocol: String,
    #[serde(rename = "@portid")]
    portid: u16,
    state: PortState,
    service: Option<Service>,
    #[serde(rename = "script", default)]
    scripts: Vec<Script>,
}

#[derive(Debug, Deserialize)]
struct PortState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct Service {
    #[serde(rename = "@name")]
    name: Option<String>,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Script {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@output")]
    output: Option<String>,
}

/// Parse nmap XML output into findings: one `open port` finding per open port,
/// plus one finding per CVE reported by the `vulners` script.
pub fn parse_xml(xml: &str) -> Result<Vec<Finding>> {
    let run: NmapRun = quick_xml::de::from_str(xml).context("invalid nmap XML")?;
    let mut findings = Vec::new();

    for host in run.hosts {
        if host.status.as_ref().map(|s| s.state.as_str()) != Some("up") {
            continue;
        }
        let Some(addr) = host
            .addresses
            .iter()
            .find(|a| a.addrtype.starts_with("ipv"))
            .or_else(|| host.addresses.first())
            .map(|a| a.addr.clone())
        else {
            continue;
        };
        let Some(ports) = host.ports else { continue };

        for p in ports.ports {
            if p.state.state != "open" {
                continue;
            }
            let svc_name = p.service.as_ref().and_then(|s| s.name.clone());
            let banner = p
                .service
                .as_ref()
                .map(|s| {
                    [s.product.as_deref(), s.version.as_deref()]
                        .iter()
                        .flatten()
                        .copied()
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();

            let proto = Some(p.protocol.as_str());
            let mut title = format!("Open port {}/{}", p.portid, p.protocol);
            if let Some(n) = &svc_name {
                title.push_str(&format!(" ({n})"));
            }
            findings.push(Finding {
                fingerprint: Finding::make_fingerprint(&addr, Some(p.portid), proto, "open-port"),
                host: addr.clone(),
                port: Some(p.portid),
                protocol: Some(p.protocol.clone()),
                service: svc_name.clone(),
                title,
                severity: Severity::Info,
                cve: vec![],
                cvss: None,
                epss: None,
                kev: false,
                priority: 0.0,
                evidence: banner.clone(),
                tool: "nmap".into(),
                fix_available: None,
                vendor_priority: None,
            });

            for script in p.scripts.iter().filter(|s| s.id == "vulners") {
                for (cve, score) in parse_vulners(script.output.as_deref().unwrap_or("")) {
                    findings.push(Finding {
                        fingerprint: Finding::make_fingerprint(&addr, Some(p.portid), proto, &cve),
                        host: addr.clone(),
                        port: Some(p.portid),
                        protocol: Some(p.protocol.clone()),
                        service: svc_name.clone(),
                        title: format!("{cve} affects {}", if banner.is_empty() { "service" } else { &banner }),
                        severity: score.map(Severity::from_cvss).unwrap_or(Severity::Medium),
                        cve: vec![cve],
                        cvss: score,
                        epss: None,
                        kev: false,
                        priority: 0.0,
                        evidence: banner.clone(),
                        tool: "nmap+vulners".into(),
                        fix_available: None,
                        vendor_priority: None,
                    });
                }
            }
        }
    }
    Ok(findings)
}

/// Lines look like `\tCVE-2021-41773\t7.5\thttps://vulners.com/cve/CVE-2021-41773`.
fn parse_vulners(output: &str) -> Vec<(String, Option<f32>)> {
    output
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let id = it.next()?;
            if !id.starts_with("CVE-") {
                return None;
            }
            let score = it.next().and_then(|s| s.parse::<f32>().ok());
            Some((id.to_string(), score))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../tests/fixtures/nmap_sample.xml");

    #[test]
    fn parses_open_ports_and_cves() {
        let f = parse_xml(SAMPLE).unwrap();
        // 22/tcp, 80/tcp open + 2 CVEs; closed 443 and open|filtered 53 and down host are skipped.
        assert_eq!(f.len(), 4, "{f:#?}");
        let ssh = f.iter().find(|x| x.port == Some(22)).unwrap();
        assert_eq!(ssh.host, "192.168.1.10");
        assert_eq!(ssh.evidence, "OpenSSH 8.2p1");
        assert_eq!(ssh.severity, Severity::Info);

        let crit = f.iter().find(|x| x.cve == ["CVE-2021-42013"]).unwrap();
        assert_eq!(crit.severity, Severity::Critical);
        assert_eq!(crit.cvss, Some(9.8));
        let high = f.iter().find(|x| x.cve == ["CVE-2021-41773"]).unwrap();
        assert_eq!(high.severity, Severity::High);
    }

    #[test]
    fn target_goes_after_double_dash() {
        let n = Nmap::default();
        let t = Target::parse("10.0.0.5").unwrap();
        let args = n.build_args(&t);
        let dd = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(dd, args.len() - 2);
        assert_eq!(args.last().unwrap(), "10.0.0.5");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_xml("not xml at all <<<").is_err());
    }
}
