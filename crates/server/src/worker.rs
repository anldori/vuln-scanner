use crate::db;
use anyhow::{bail, Result};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use vs_core::{CveInfo, Finding, ScanOptions, Scanner, Scope, Target};
use vs_enrich::Enricher;

pub struct Worker {
    pub pool: SqlitePool,
    pub scope: Scope,
    pub scanners: Vec<Box<dyn Scanner>>,
    /// `None` disables enrichment (offline / air-gapped use).
    pub enricher: Option<Enricher>,
}

impl Worker {
    /// Poll the queue and run scans one at a time.
    pub async fn run_loop(self) {
        loop {
            match db::claim_next(&self.pool).await {
                Ok(Some((id, target))) => {
                    tracing::info!(%id, %target, "scan started");
                    db::audit(&self.pool, "scan_started", &format!("{id} {target}")).await;
                    match self.run_one(&id, &target).await {
                        Ok((n, notes)) => {
                            tracing::info!(%id, findings = n, "scan done");
                            let note = notes.as_deref().unwrap_or("");
                            db::audit(&self.pool, "scan_done", &format!("{id} findings={n} {note}")).await;
                        }
                        Err(e) => {
                            tracing::warn!(%id, "scan failed: {e:#}");
                            db::audit(&self.pool, "scan_failed", &format!("{id} {e:#}")).await;
                            if let Err(e2) = db::fail_scan(&self.pool, &id, &format!("{e:#}")).await {
                                tracing::error!(%id, "could not record failure: {e2:#}");
                            }
                        }
                    }
                }
                Ok(None) => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(e) => {
                    tracing::error!("queue error: {e:#}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn run_one(&self, id: &str, target: &str) -> Result<(usize, Option<String>)> {
        // Re-validate at execution time (defence in depth: DB contents are not trusted).
        let target = Target::parse(target)?;
        self.scope.check(&target)?;

        let opts = ScanOptions::default();
        let mut notes: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();
        let mut succeeded = 0;

        for sc in &self.scanners {
            match sc.run(&target, &opts).await {
                Ok(f) => {
                    tracing::info!(%id, scanner = sc.name(), findings = f.len(), "scanner finished");
                    succeeded += 1;
                    findings.extend(f);
                }
                Err(e) => {
                    tracing::warn!(%id, scanner = sc.name(), "scanner failed: {e:#}");
                    errors.push(format!("{}: {e:#}", sc.name()));
                }
            }
        }
        if succeeded == 0 {
            bail!("all scanners failed: {}", errors.join("; "));
        }
        notes.extend(errors.into_iter().map(|e| format!("scanner failed - {e}")));

        let mut seen = HashSet::new();
        findings.retain(|f| seen.insert(f.fingerprint.clone()));

        if let Some(en) = &self.enricher {
            notes.extend(self.enrich(en, &mut findings).await);
        } else {
            // Still give every finding a baseline priority from its severity/CVSS.
            findings.iter_mut().for_each(|f| f.apply_enrichment(&HashMap::new()));
        }

        let n = findings.len();
        let notes = if notes.is_empty() { None } else { Some(notes.join(" | ")) };
        db::finish_scan(&self.pool, id, &findings, notes.as_deref()).await?;
        Ok((n, notes))
    }

    /// Best-effort enrichment; returns warnings, never fails the scan.
    async fn enrich(&self, en: &Enricher, findings: &mut [Finding]) -> Vec<String> {
        let mut cves: Vec<String> = findings.iter().flat_map(|f| f.cve.iter().cloned()).collect();
        cves.sort();
        cves.dedup();
        let need_cvss: HashSet<&String> = findings.iter().filter(|f| f.cvss.is_none()).flat_map(|f| f.cve.iter()).collect();

        let mut info: HashMap<String, CveInfo> = match db::cache_get(&self.pool, &cves, 24).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("cve cache read failed: {e:#}");
                HashMap::new()
            }
        };
        // A cached entry is only good enough if it has the CVSS we still need.
        info.retain(|c, i| i.cvss.is_some() || !need_cvss.contains(c));

        let misses: Vec<String> = cves.iter().filter(|c| !info.contains_key(*c)).cloned().collect();
        let mut warnings = Vec::new();
        if !misses.is_empty() {
            let miss_need: Vec<String> = misses.iter().filter(|c| need_cvss.contains(*c)).cloned().collect();
            let (fresh, w) = en.lookup(&misses, &miss_need).await;
            if w.is_empty() {
                if let Err(e) = db::cache_put(&self.pool, &fresh).await {
                    tracing::warn!("cve cache write failed: {e:#}");
                }
            }
            warnings = w;
            info.extend(fresh);
        }
        for f in findings.iter_mut() {
            f.apply_enrichment(&info);
        }
        warnings
    }
}
