use crate::creds::CredStore;
use crate::db;
use anyhow::{bail, Result};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use vs_core::{CveInfo, Finding, Progress, Scan, ScanOptions, Scanner, Scope, Target};
use vs_scanners::{with_ticker, Vuls};
use vs_enrich::Enricher;

/// Progress log of one scan: lines are queued here and written to `scan_events` by a task.
#[derive(Clone)]
struct Events(UnboundedSender<(&'static str, Option<String>, String)>);

impl Events {
    fn send(&self, level: &'static str, phase: Option<&str>, m: impl Into<String>) {
        let _ = self.0.send((level, phase.map(String::from), m.into()));
    }
    fn info(&self, m: impl Into<String>) {
        self.send("info", None, m);
    }
    fn phase(&self, phase: &str, m: impl Into<String>) {
        self.send("info", Some(phase), m);
    }
    fn warn(&self, m: impl Into<String>) {
        self.send("warn", None, m);
    }
    fn error(&self, m: impl Into<String>) {
        self.send("error", None, m);
    }
}

pub struct Worker {
    pub pool: SqlitePool,
    pub scope: Scope,
    pub scanners: Vec<Box<dyn Scanner>>,
    /// `None` disables enrichment (offline / air-gapped use).
    pub enricher: Option<Enricher>,
    /// Authenticated scanner, used only for deep scans.
    pub vuls: Option<Vuls>,
    pub creds: CredStore,
}

impl Worker {
    /// Poll the queue and run scans one at a time.
    pub async fn run_loop(self) {
        loop {
            match db::claim_next(&self.pool).await {
                Ok(Some(scan)) => {
                    let (id, target) = (scan.id.clone(), scan.target.clone());
                    // Never log secrets: only user/port of a deep scan.
                    let deep = match (scan.deep, &scan.ssh_user) {
                        (true, Some(u)) => format!(" deep user={u} port={} auth={}", scan.ssh_port.unwrap_or(22), scan.ssh_auth.as_deref().unwrap_or("key")),
                        _ => String::new(),
                    };
                    tracing::info!(%id, %target, deep = scan.deep, "scan started");
                    db::audit(&self.pool, "scan_started", &format!("{id} {target}{deep}")).await;
                    match self.run_one(&scan).await {
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

    async fn run_one(&self, scan: &Scan) -> Result<(usize, Option<String>)> {
        let (tx, mut rx) = unbounded_channel::<(&'static str, Option<String>, String)>();
        let (pool, sid) = (self.pool.clone(), scan.id.clone());
        let writer = tokio::spawn(async move {
            while let Some((level, phase, msg)) = rx.recv().await {
                db::add_event(&pool, &sid, level, phase.as_deref(), &msg).await;
            }
        });
        let ev = Events(tx);
        let res = self.run_inner(scan, &ev).await;
        match &res {
            Ok((n, _)) => ev.info(format!("Scan finished: {n} finding(s)")),
            Err(e) => ev.error(format!("Scan failed: {e:#}")),
        }
        drop(ev);
        let _ = writer.await; // flush every queued line before the scan is reported finished
        res
    }

    async fn run_inner(&self, scan: &Scan, ev: &Events) -> Result<(usize, Option<String>)> {
        let id = scan.id.as_str();
        // Take the secret out of the store first so it is gone on every path (error, scope reject...).
        let ssh = if scan.deep { self.creds.take(id) } else { None };
        // Re-validate at execution time (defence in depth: DB contents are not trusted).
        let target = Target::parse(&scan.target)?;
        self.scope.check(&target)?;

        let progress = {
            let ev = ev.clone();
            Progress::new(move |level, phase, m| match level {
                "error" => ev.send("error", phase, m),
                "warn" => ev.send("warn", phase, m),
                _ => ev.send("info", phase, m),
            })
        };
        let opts = ScanOptions { progress: Some(progress), ..ScanOptions::default() };
        ev.info(format!("Scan started: {}{}", scan.target, if scan.deep { " (deep scan)" } else { "" }));
        let mut notes: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();
        let mut succeeded = 0;

        if scan.deep {
            // Authenticated scan goes first so a bad login shows up within seconds. Credentials are consumed
            // here and dropped (zeroized) right after.
            let res = match (&self.vuls, ssh) {
                (None, _) => {
                    let m = "Vuls is not available on this server";
                    ev.send("error", Some("connect"), m);
                    Err(anyhow::anyhow!(m))
                }
                (_, None) => {
                    let m = "SSH credentials are no longer available (server restarted?); submit the scan again";
                    ev.send("error", Some("connect"), m);
                    Err(anyhow::anyhow!(m))
                }
                (Some(v), Some(creds)) => {
                    let deep_opts = ScanOptions { ssh: Some(creds), ..opts.clone() };
                    v.run(&target, &deep_opts).await // Vuls reports its own progress and heartbeats
                }
            };
            match res {
                Ok(f) => {
                    tracing::info!(%id, scanner = "vuls", findings = f.len(), "scanner finished");
                    ev.phase("vuls", format!("vuls: finished, {} finding(s)", f.len()));
                    succeeded += 1;
                    findings.extend(f);
                }
                Err(e) => {
                    tracing::warn!(%id, scanner = "vuls", "scanner failed: {e:#}");
                    // Vuls has already reported the failure on its own phase.
                    errors.push(format!("vuls (deep scan): {e:#}"));
                }
            }
        }
        ev.phase("scan", "Network scan: starting scanners");
        for sc in &self.scanners {
            let name = sc.name();
            ev.phase("scan", format!("{name}: started"));
            let t0 = std::time::Instant::now();
            // Heartbeat so a long scanner never looks stuck.
            let res = with_ticker(Duration::from_secs(20), sc.run(&target, &opts), |el| {
                ev.phase("scan", format!("{name}: still running ({}s)", el.as_secs()))
            })
            .await;
            match res {
                Ok(f) => {
                    tracing::info!(%id, scanner = name, findings = f.len(), "scanner finished");
                    ev.phase("scan", format!("{name}: finished, {} finding(s) in {}s", f.len(), t0.elapsed().as_secs()));
                    succeeded += 1;
                    findings.extend(f);
                }
                Err(e) => {
                    tracing::warn!(%id, scanner = name, "scanner failed: {e:#}");
                    ev.warn(format!("{name}: failed: {e:#}"));
                    errors.push(format!("{name}: {e:#}"));
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
            let n_cve = findings.iter().flat_map(|f| f.cve.iter()).collect::<HashSet<_>>().len();
            ev.phase("enrich", format!("Enriching {n_cve} CVE(s) (EPSS / KEV / NVD)..."));
            let w = with_ticker(Duration::from_secs(20), self.enrich(en, &mut findings), |el| {
                ev.phase("enrich", format!("Enrichment still running ({}s)", el.as_secs()))
            })
            .await;
            w.iter().for_each(|m| ev.warn(format!("enrichment: {m}")));
            notes.extend(w);
        } else {
            // Still give every finding a baseline priority from its severity/CVSS.
            findings.iter_mut().for_each(|f| f.apply_enrichment(&HashMap::new()));
        }

        let n = findings.len();
        ev.phase("save", format!("Saving {n} finding(s)"));
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
