//! CVE enrichment: EPSS (exploit probability), CISA KEV (known exploited) and NVD (CVSS).
//!
//! Only CVE identifiers ever leave the machine - never targets, hosts or findings.
//! All lookups are best-effort: callers should treat errors as "no extra data".

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use vs_core::CveInfo;

pub const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
/// Official CISA mirror; www.cisa.gov itself rejects non-browser clients with 403.
pub const KEV_URL: &str = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";
pub const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

const KEV_TTL: Duration = Duration::from_secs(12 * 3600);

// ---------- parsers (pure, unit-tested) ----------

/// Parse an EPSS API response into `CVE -> probability`.
pub fn parse_epss(json: &str) -> Result<HashMap<String, f32>> {
    let v: Value = serde_json::from_str(json).context("invalid EPSS JSON")?;
    let mut m = HashMap::new();
    for row in v["data"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let (Some(cve), Some(score)) = (row["cve"].as_str(), row["epss"].as_str().and_then(|s| s.parse::<f32>().ok())) else {
            continue;
        };
        m.insert(cve.to_ascii_uppercase(), score);
    }
    Ok(m)
}

/// Parse the CISA KEV catalog into the set of CVE ids.
pub fn parse_kev(json: &str) -> Result<HashSet<String>> {
    let v: Value = serde_json::from_str(json).context("invalid KEV JSON")?;
    let list = v["vulnerabilities"].as_array().context("KEV JSON has no `vulnerabilities`")?;
    Ok(list
        .iter()
        .filter_map(|e| e["cveID"].as_str())
        .map(str::to_ascii_uppercase)
        .collect())
}

/// Best CVSS base score from an NVD 2.0 response (v4.0 > v3.1 > v3.0 > v2; Primary source first).
pub fn parse_nvd_cvss(json: &str) -> Result<Option<f32>> {
    let v: Value = serde_json::from_str(json).context("invalid NVD JSON")?;
    let Some(metrics) = v["vulnerabilities"].get(0).map(|x| &x["cve"]["metrics"]) else {
        return Ok(None);
    };
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let Some(list) = metrics[key].as_array() else { continue };
        let pick = list.iter().find(|m| m["type"] == "Primary").or_else(|| list.first());
        if let Some(score) = pick.and_then(|m| m["cvssData"]["baseScore"].as_f64()) {
            return Ok(Some(score as f32));
        }
    }
    Ok(None)
}

/// A CVE id we are willing to put in a URL.
fn valid_cve(s: &str) -> bool {
    let up = s.to_ascii_uppercase();
    let mut parts = up.split('-');
    parts.next() == Some("CVE")
        && parts.next().is_some_and(|y| y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_some_and(|n| n.len() >= 4 && n.len() <= 12 && n.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

// ---------- network ----------

pub struct Enricher {
    client: reqwest::Client,
    nvd_api_key: Option<String>,
    /// Max NVD lookups per `lookup` call (NVD allows 5 req/30s without a key).
    nvd_budget: usize,
    kev: Mutex<Option<(Instant, HashSet<String>)>>,
}

impl Enricher {
    pub fn new(nvd_api_key: Option<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("vuln-scanner/0.1")
            .timeout(Duration::from_secs(30))
            .build()?;
        let nvd_budget = if nvd_api_key.is_some() { 25 } else { 4 };
        Ok(Self { client, nvd_api_key, nvd_budget, kev: Mutex::new(None) })
    }

    async fn get_text(&self, url: &str) -> Result<String> {
        let r = self.client.get(url).send().await?.error_for_status()?;
        Ok(r.text().await?)
    }

    pub async fn fetch_epss(&self, cves: &[String]) -> Result<HashMap<String, f32>> {
        let mut out = HashMap::new();
        for chunk in cves.chunks(50) {
            let url = format!("{EPSS_URL}?cve={}", chunk.join(","));
            out.extend(parse_epss(&self.get_text(&url).await?)?);
        }
        Ok(out)
    }

    /// KEV set, cached in memory for 12h (the catalog is ~2 MB).
    pub async fn kev_set(&self) -> Result<HashSet<String>> {
        let mut guard = self.kev.lock().await;
        if let Some((at, set)) = guard.as_ref() {
            if at.elapsed() < KEV_TTL {
                return Ok(set.clone());
            }
        }
        let set = parse_kev(&self.get_text(KEV_URL).await?)?;
        *guard = Some((Instant::now(), set.clone()));
        Ok(set)
    }

    pub async fn fetch_nvd_cvss(&self, cve: &str) -> Result<Option<f32>> {
        let url = format!("{NVD_URL}?cveId={cve}");
        let mut req = self.client.get(url);
        if let Some(k) = &self.nvd_api_key {
            req = req.header("apiKey", k);
        }
        let body = req.send().await?.error_for_status()?.text().await?;
        parse_nvd_cvss(&body)
    }

    /// Look up `cves`. NVD (CVSS) is only queried for ids in `need_cvss`, within the budget.
    /// Returns what could be fetched plus human-readable warnings for what could not.
    pub async fn lookup(&self, cves: &[String], need_cvss: &[String]) -> (HashMap<String, CveInfo>, Vec<String>) {
        let mut warnings = Vec::new();
        let cves: Vec<String> = {
            let mut v: Vec<String> = cves.iter().map(|c| c.to_ascii_uppercase()).filter(|c| valid_cve(c)).collect();
            v.sort();
            v.dedup();
            v
        };
        let mut info: HashMap<String, CveInfo> = cves.iter().map(|c| (c.clone(), CveInfo::default())).collect();
        if cves.is_empty() {
            return (info, warnings);
        }

        match self.fetch_epss(&cves).await {
            Ok(m) => {
                for (c, s) in m {
                    if let Some(i) = info.get_mut(&c) {
                        i.epss = Some(s);
                    }
                }
            }
            Err(e) => warnings.push(format!("EPSS unavailable: {e:#}")),
        }
        match self.kev_set().await {
            Ok(kev) => {
                for (c, i) in info.iter_mut() {
                    i.kev = kev.contains(c);
                }
            }
            Err(e) => warnings.push(format!("KEV unavailable: {e:#}")),
        }

        let wanted: Vec<&String> = need_cvss.iter().filter(|c| info.contains_key(*c)).take(self.nvd_budget).collect();
        for (n, cve) in wanted.iter().enumerate() {
            if n > 0 && self.nvd_api_key.is_none() {
                tokio::time::sleep(Duration::from_millis(6500)).await; // stay under 5 req / 30 s
            }
            match self.fetch_nvd_cvss(cve).await {
                Ok(score) => {
                    if let Some(i) = info.get_mut(*cve) {
                        i.cvss = score;
                    }
                }
                Err(e) => {
                    warnings.push(format!("NVD unavailable: {e:#}"));
                    break;
                }
            }
        }
        (info, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epss_parse() {
        let j = r#"{"status":"OK","data":[{"cve":"CVE-2021-41773","epss":"0.999920000","percentile":"0.99992","date":"2026-11-25"},{"cve":"bad"}]}"#;
        let m = parse_epss(j).unwrap();
        assert_eq!(m.len(), 1);
        assert!((m["CVE-2021-41773"] - 0.99992).abs() < 1e-5);
        assert!(parse_epss("nope").is_err());
    }

    #[test]
    fn kev_parse() {
        let j = r#"{"count":2,"vulnerabilities":[{"cveID":"CVE-2021-41773"},{"cveID":"cve-2020-1"},{"x":1}]}"#;
        let s = parse_kev(j).unwrap();
        assert!(s.contains("CVE-2021-41773") && s.contains("CVE-2020-1") && s.len() == 2);
        assert!(parse_kev(r#"{"a":1}"#).is_err());
    }

    #[test]
    fn nvd_prefers_newest_primary() {
        let j = r#"{"vulnerabilities":[{"cve":{"metrics":{
            "cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":5.0}}],
            "cvssMetricV31":[
              {"type":"Secondary","cvssData":{"baseScore":7.5}},
              {"type":"Primary","cvssData":{"baseScore":9.8}}]}}}]}"#;
        assert_eq!(parse_nvd_cvss(j).unwrap(), Some(9.8));
        assert_eq!(parse_nvd_cvss(r#"{"vulnerabilities":[]}"#).unwrap(), None);
        assert_eq!(parse_nvd_cvss(r#"{"vulnerabilities":[{"cve":{"metrics":{}}}]}"#).unwrap(), None);
    }

    #[test]
    fn cve_validation_blocks_url_injection() {
        assert!(valid_cve("CVE-2021-41773"));
        assert!(valid_cve("cve-2024-1234567"));
        assert!(!valid_cve("CVE-2021-41773&x=1"));
        assert!(!valid_cve("CVE-21-1"));
        assert!(!valid_cve("../etc/passwd"));
    }

    /// Hits the real services: `cargo test -p vs-enrich -- --ignored`
    #[tokio::test]
    #[ignore = "needs network"]
    async fn live_lookup() {
        let en = Enricher::new(None).unwrap();
        let cve = "CVE-2021-41773".to_string();
        let (info, warnings) = en.lookup(std::slice::from_ref(&cve), std::slice::from_ref(&cve)).await;
        assert!(warnings.is_empty(), "{warnings:?}");
        let i = &info[&cve];
        assert_eq!(i.cvss, Some(9.8));
        assert!(i.epss.unwrap() > 0.9);
        assert!(i.kev);
    }
}
