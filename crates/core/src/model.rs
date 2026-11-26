use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Severity {
        match s {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Info,
        }
    }

    /// Map a CVSS base score to a severity (CVSS v3 qualitative scale).
    pub fn from_cvss(score: f32) -> Severity {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Queued,
    Running,
    Done,
    Failed,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Queued => "queued",
            ScanStatus::Running => "running",
            ScanStatus::Done => "done",
            ScanStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> ScanStatus {
        match s {
            "running" => ScanStatus::Running,
            "done" => ScanStatus::Done,
            "failed" => ScanStatus::Failed,
            _ => ScanStatus::Queued,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub target: String,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// A normalized result produced by any scanner plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub fingerprint: String,
    pub host: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub title: String,
    pub severity: Severity,
    pub cve: Vec<String>,
    pub cvss: Option<f32>,
    /// EPSS probability (0..1) that the CVE is exploited in the next 30 days.
    #[serde(default)]
    pub epss: Option<f32>,
    /// Listed in CISA's Known Exploited Vulnerabilities catalog.
    #[serde(default)]
    pub kev: bool,
    /// Risk-based score 0..100 combining CVSS, EPSS and KEV (see [`compute_priority`]).
    #[serde(default)]
    pub priority: f32,
    pub evidence: String,
    pub tool: String,
}

/// Enrichment data for a single CVE.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CveInfo {
    pub cvss: Option<f32>,
    pub epss: Option<f32>,
    pub kev: bool,
}

/// Risk score in 0..100: CVSS (50%) + EPSS (30%) + known-exploited bonus (20%).
/// Without a CVSS score the severity's typical value is used. Informational findings score 0.
pub fn compute_priority(severity: Severity, cvss: Option<f32>, epss: Option<f32>, kev: bool) -> f32 {
    if severity == Severity::Info && cvss.is_none() && epss.is_none() && !kev {
        return 0.0;
    }
    let base = cvss.unwrap_or(match severity {
        Severity::Info => 0.0,
        Severity::Low => 2.0,
        Severity::Medium => 5.0,
        Severity::High => 7.5,
        Severity::Critical => 9.5,
    });
    let score = base.clamp(0.0, 10.0) / 10.0 * 50.0
        + epss.unwrap_or(0.0).clamp(0.0, 1.0) * 30.0
        + if kev { 20.0 } else { 0.0 };
    (score * 10.0).round() / 10.0
}

impl Finding {
    /// Merge CVE enrichment into this finding and recompute its priority.
    /// Scanner-provided CVSS wins; KEV membership raises severity to at least High.
    pub fn apply_enrichment(&mut self, info: &std::collections::HashMap<String, CveInfo>) {
        let found: Vec<&CveInfo> = self.cve.iter().filter_map(|c| info.get(c)).collect();
        let max = |it: &mut dyn Iterator<Item = f32>| it.fold(None, |a: Option<f32>, v| Some(a.map_or(v, |x| x.max(v))));
        if self.cvss.is_none() {
            if let Some(c) = max(&mut found.iter().filter_map(|i| i.cvss)) {
                self.cvss = Some(c);
                self.severity = self.severity.max(Severity::from_cvss(c));
            }
        }
        if let Some(e) = max(&mut found.iter().filter_map(|i| i.epss)) {
            self.epss = Some(e);
        }
        if found.iter().any(|i| i.kev) {
            self.kev = true;
            self.severity = self.severity.max(Severity::High);
        }
        self.priority = compute_priority(self.severity, self.cvss, self.epss, self.kev);
    }

    /// Stable identity of a finding: same host/port/vuln across scans => same fingerprint.
    pub fn make_fingerprint(host: &str, port: Option<u16>, protocol: Option<&str>, vuln_id: &str) -> String {
        let mut h = Sha256::new();
        h.update(host.as_bytes());
        h.update([0]);
        h.update(port.map(|p| p.to_string()).unwrap_or_default().as_bytes());
        h.update([0]);
        h.update(protocol.unwrap_or("").as_bytes());
        h.update([0]);
        h.update(vuln_id.as_bytes());
        hex::encode(h.finalize())[..32].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let a = Finding::make_fingerprint("10.0.0.1", Some(22), Some("tcp"), "open-port");
        let b = Finding::make_fingerprint("10.0.0.1", Some(22), Some("tcp"), "open-port");
        let c = Finding::make_fingerprint("10.0.0.1", Some(23), Some("tcp"), "open-port");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    fn bare(cves: &[&str], sev: Severity, cvss: Option<f32>) -> Finding {
        Finding {
            fingerprint: "f".into(),
            host: "h".into(),
            port: None,
            protocol: None,
            service: None,
            title: "t".into(),
            severity: sev,
            cve: cves.iter().map(|c| c.to_string()).collect(),
            cvss,
            epss: None,
            kev: false,
            priority: 0.0,
            evidence: String::new(),
            tool: "t".into(),
        }
    }

    #[test]
    fn priority_formula() {
        assert_eq!(compute_priority(Severity::Info, None, None, false), 0.0);
        assert_eq!(compute_priority(Severity::Critical, Some(10.0), Some(1.0), true), 100.0);
        assert_eq!(compute_priority(Severity::High, Some(7.5), Some(0.1), false), 40.5);
        // severity fallback when CVSS is unknown
        assert_eq!(compute_priority(Severity::Medium, None, None, false), 25.0);
    }

    #[test]
    fn enrichment_applies_kev_epss_and_cvss() {
        let mut m = std::collections::HashMap::new();
        m.insert("CVE-1".to_string(), CveInfo { cvss: Some(9.8), epss: Some(0.9), kev: true });
        m.insert("CVE-2".to_string(), CveInfo { cvss: Some(5.0), epss: Some(0.95), kev: false });
        let mut f = bare(&["CVE-1", "CVE-2", "CVE-X"], Severity::Info, None);
        f.apply_enrichment(&m);
        assert_eq!(f.cvss, Some(9.8));
        assert_eq!(f.epss, Some(0.95));
        assert!(f.kev);
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.priority > 90.0);
    }

    #[test]
    fn scanner_cvss_is_not_overridden_but_kev_raises_severity() {
        let mut m = std::collections::HashMap::new();
        m.insert("CVE-1".to_string(), CveInfo { cvss: Some(9.8), epss: None, kev: true });
        let mut f = bare(&["CVE-1"], Severity::Low, Some(3.0));
        f.apply_enrichment(&m);
        assert_eq!(f.cvss, Some(3.0));
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn cvss_mapping() {
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
    }
}
