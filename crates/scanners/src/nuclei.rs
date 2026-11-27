//! nuclei plugin: runs `nuclei -jsonl` and converts each match into a [`Finding`].

use crate::exec::run_capture;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use vs_core::{Finding, ScanOptions, Scanner, Severity, Target};

pub struct Nuclei {
    pub binary: String,
    /// Max requests per second sent by nuclei.
    pub rate_limit: u32,
}

impl Default for Nuclei {
    fn default() -> Self {
        Self { binary: "nuclei".into(), rate_limit: 50 }
    }
}

impl Nuclei {
    pub fn build_args(&self, target: &Target) -> Vec<String> {
        let mut a: Vec<String> = [
            "-jsonl",
            "-silent",
            "-nc",           // no colour
            "-duc",          // never self-update during a scan
            "-ni",           // no interactsh: do not talk to external OAST servers
            "-timeout", "10",
            "-retries", "1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        a.push("-rl".into());
        a.push(self.rate_limit.to_string());
        // Target is the value of `-u`, so it can never be parsed as another flag.
        a.push("-u".into());
        a.push(target.as_arg());
        a
    }
}

#[async_trait]
impl Scanner for Nuclei {
    fn name(&self) -> &'static str {
        "nuclei"
    }

    async fn run(&self, target: &Target, opts: &ScanOptions) -> Result<Vec<Finding>> {
        let out = run_capture(&self.binary, &self.build_args(target), opts.timeout_secs).await?;
        Ok(parse_jsonl(&out))
    }
}

fn severity_of(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

/// `classification.cve-id` is an array in current nuclei, a string in old templates, or null.
fn cve_ids(v: &Value) -> Vec<String> {
    let ids: Vec<&str> = match v {
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        Value::String(s) => s.split(',').map(str::trim).collect(),
        _ => vec![],
    };
    let mut out: Vec<String> = ids
        .into_iter()
        .map(|s| s.to_ascii_uppercase())
        .filter(|s| s.starts_with("CVE-"))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Split `scheme://host:port/path` or `host:port` into (host, port, scheme).
fn split_location(loc: &str) -> (String, Option<u16>, Option<String>) {
    let (scheme, rest) = match loc.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, loc),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // [v6]:port
        match stripped.split_once(']') {
            Some((h, p)) => (h.to_string(), p.strip_prefix(':').and_then(|p| p.parse().ok())),
            None => (authority.to_string(), None),
        }
    } else if authority.matches(':').count() == 1 {
        let (h, p) = authority.split_once(':').unwrap_or((authority, ""));
        (h.to_string(), p.parse().ok())
    } else {
        (authority.to_string(), None)
    };
    let port = port.or(match scheme.as_deref() {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    });
    (host, port, scheme)
}

/// Parse nuclei `-jsonl` output. Unparseable lines are skipped (nuclei may print stray text).
pub fn parse_jsonl(out: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in out.lines().map(str::trim).filter(|l| l.starts_with('{')) {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        let Some(template) = v["template-id"].as_str() else { continue };
        let info = &v["info"];

        let loc = v["matched-at"].as_str().or_else(|| v["host"].as_str()).unwrap_or("");
        let (loc_host, port, scheme) = split_location(loc);
        // Prefer the resolved IP so findings line up with nmap's; fall back to the name.
        let host = v["ip"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or(loc_host);
        if host.is_empty() {
            continue;
        }
        let proto = match v["type"].as_str() {
            Some("udp") => "udp",
            _ => "tcp",
        };
        let cves = cve_ids(&info["classification"]["cve-id"]);
        let cvss = info["classification"]["cvss-score"].as_f64().map(|f| f as f32).filter(|f| *f > 0.0);
        let mut severity = severity_of(info["severity"].as_str().unwrap_or("info"));
        if let Some(c) = cvss {
            severity = severity.max(Severity::from_cvss(c));
        }

        let name = info["name"].as_str().unwrap_or(template);
        let mut evidence = loc.to_string();
        if let Some(extra) = v["extracted-results"].as_array() {
            let joined: Vec<&str> = extra.iter().filter_map(Value::as_str).collect();
            if !joined.is_empty() {
                evidence.push_str(" → ");
                evidence.push_str(&joined.join(", "));
            }
        }

        findings.push(Finding {
            fingerprint: Finding::make_fingerprint(&host, port, Some(proto), template),
            host,
            port,
            protocol: Some(proto.to_string()),
            service: scheme,
            title: name.to_string(),
            severity,
            cve: cves,
            cvss,
            epss: None,
            kev: false,
            priority: 0.0,
            evidence,
            tool: "nuclei".into(),
            fix_available: None,
            vendor_priority: None,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../tests/fixtures/nuclei_sample.jsonl");

    #[test]
    fn parses_matches_and_skips_garbage() {
        let f = parse_jsonl(SAMPLE);
        assert_eq!(f.len(), 4, "{f:#?}");

        let info = &f[0];
        assert_eq!(info.severity, Severity::Info);
        assert_eq!(info.port, Some(80));
        assert!(info.evidence.contains("Apache/2.4.49"));

        let cve = &f[1];
        assert_eq!(cve.cve, ["CVE-2021-41773", "CVE-2021-42013"]);
        assert_eq!(cve.cvss, Some(7.5));
        assert_eq!(cve.severity, Severity::High);
        assert_eq!(cve.port, Some(8080));
        assert_eq!(cve.host, "192.168.1.10");

        let xfo = &f[2];
        assert_eq!(xfo.port, Some(443));
        assert!(xfo.cve.is_empty());
        assert_eq!(xfo.severity, Severity::Low);

        assert_eq!(f[3].port, Some(2222));
        assert_eq!(f[3].severity, Severity::Info); // "unknown" => info
    }

    #[test]
    fn fingerprints_differ_per_template() {
        let f = parse_jsonl(SAMPLE);
        assert_ne!(f[0].fingerprint, f[1].fingerprint);
    }

    #[test]
    fn target_is_value_of_u_flag() {
        let n = Nuclei::default();
        let args = n.build_args(&Target::parse("10.0.0.5").unwrap());
        let i = args.iter().position(|a| a == "-u").unwrap();
        assert_eq!(args[i + 1], "10.0.0.5");
        assert!(args.contains(&"-ni".to_string()));
    }

    #[test]
    fn split_location_cases() {
        assert_eq!(split_location("https://a.b/x"), ("a.b".into(), Some(443), Some("https".into())));
        assert_eq!(split_location("1.2.3.4:2222"), ("1.2.3.4".into(), Some(2222), None));
        assert_eq!(split_location("http://[::1]:8080/"), ("::1".into(), Some(8080), Some("http".into())));
    }
}
