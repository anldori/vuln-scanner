use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;
use std::collections::HashMap;
use vs_core::{CveInfo, Finding, Scan, ScanStatus, Severity};

pub async fn connect(url: &str) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new().max_connections(5).connect_with(opts).await?;
    sqlx::raw_sql(include_str!("../../../migrations/001_init.sql"))
        .execute(&pool)
        .await?;
    Ok(pool)
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).map(|d| d.with_timezone(&Utc)).unwrap_or_default()
}

fn row_to_scan(r: &sqlx::sqlite::SqliteRow) -> Scan {
    Scan {
        id: r.get("id"),
        target: r.get("target"),
        status: ScanStatus::parse(r.get::<String, _>("status").as_str()),
        created_at: parse_ts(&r.get::<String, _>("created_at")),
        finished_at: r.get::<Option<String>, _>("finished_at").map(|s| parse_ts(&s)),
        error: r.get("error"),
    }
}

pub async fn audit(pool: &SqlitePool, action: &str, detail: &str) {
    let res = sqlx::query("INSERT INTO audit_log (ts, action, detail) VALUES (?, ?, ?)")
        .bind(Utc::now().to_rfc3339())
        .bind(action)
        .bind(detail)
        .execute(pool)
        .await;
    if let Err(e) = res {
        tracing::error!("audit log write failed: {e}");
    }
}

pub async fn create_scan(pool: &SqlitePool, id: &str, target: &str) -> Result<()> {
    sqlx::query("INSERT INTO scans (id, target, status, created_at) VALUES (?, ?, 'queued', ?)")
        .bind(id)
        .bind(target)
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_scans(pool: &SqlitePool) -> Result<Vec<Scan>> {
    let rows = sqlx::query("SELECT * FROM scans ORDER BY created_at DESC LIMIT 200")
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_scan).collect())
}

pub async fn get_scan(pool: &SqlitePool, id: &str) -> Result<Option<Scan>> {
    let row = sqlx::query("SELECT * FROM scans WHERE id = ?").bind(id).fetch_optional(pool).await?;
    Ok(row.as_ref().map(row_to_scan))
}

pub async fn get_findings(pool: &SqlitePool, scan_id: &str) -> Result<Vec<Finding>> {
    let rows = sqlx::query("SELECT * FROM findings WHERE scan_id = ?").bind(scan_id).fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|r| Finding {
            fingerprint: r.get("fingerprint"),
            host: r.get("host"),
            port: r.get::<Option<i64>, _>("port").and_then(|p| u16::try_from(p).ok()),
            protocol: r.get("protocol"),
            service: r.get("service"),
            title: r.get("title"),
            severity: Severity::parse(r.get::<String, _>("severity").as_str()),
            cve: serde_json::from_str(&r.get::<String, _>("cve")).unwrap_or_default(),
            cvss: r.get::<Option<f64>, _>("cvss").map(|c| c as f32),
            epss: r.get::<Option<f64>, _>("epss").map(|c| c as f32),
            kev: r.get::<i64, _>("kev") != 0,
            priority: r.get::<f64, _>("priority") as f32,
            evidence: r.get("evidence"),
            tool: r.get("tool"),
        })
        .collect())
}

/// Atomically claim the oldest queued scan.
pub async fn claim_next(pool: &SqlitePool) -> Result<Option<(String, String)>> {
    let row = sqlx::query(
        "UPDATE scans SET status = 'running' \
         WHERE id = (SELECT id FROM scans WHERE status = 'queued' ORDER BY created_at LIMIT 1) \
         RETURNING id, target",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.get("id"), r.get("target"))))
}

/// Mark a scan done. `notes` (e.g. a scanner or enrichment warning) is kept in `error`.
pub async fn finish_scan(pool: &SqlitePool, id: &str, findings: &[Finding], notes: Option<&str>) -> Result<()> {
    let mut tx = pool.begin().await?;
    for f in findings {
        sqlx::query(
            "INSERT OR IGNORE INTO findings \
             (scan_id, fingerprint, host, port, protocol, service, title, severity, cve, cvss, epss, kev, priority, evidence, tool) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(&f.fingerprint)
        .bind(&f.host)
        .bind(f.port.map(i64::from))
        .bind(&f.protocol)
        .bind(&f.service)
        .bind(&f.title)
        .bind(f.severity.as_str())
        .bind(serde_json::to_string(&f.cve)?)
        .bind(f.cvss.map(f64::from))
        .bind(f.epss.map(f64::from))
        .bind(i64::from(f.kev))
        .bind(f64::from(f.priority))
        .bind(&f.evidence)
        .bind(&f.tool)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE scans SET status = 'done', finished_at = ?, error = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(notes)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn fail_scan(pool: &SqlitePool, id: &str, error: &str) -> Result<()> {
    sqlx::query("UPDATE scans SET status = 'failed', finished_at = ?, error = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(error)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Scans left in `running` by a previous process can never complete.
pub async fn fail_interrupted(pool: &SqlitePool) -> Result<u64> {
    let r = sqlx::query(
        "UPDATE scans SET status = 'failed', finished_at = ?, error = 'interrupted by server restart' WHERE status = 'running'",
    )
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Cached CVE info younger than `max_age_hours`.
pub async fn cache_get(pool: &SqlitePool, cves: &[String], max_age_hours: i64) -> Result<HashMap<String, CveInfo>> {
    let cutoff = (Utc::now() - chrono::Duration::hours(max_age_hours)).to_rfc3339();
    let mut out = HashMap::new();
    for cve in cves {
        let row = sqlx::query("SELECT cvss, epss, kev FROM cve_cache WHERE cve = ? AND fetched_at >= ?")
            .bind(cve)
            .bind(&cutoff)
            .fetch_optional(pool)
            .await?;
        if let Some(r) = row {
            out.insert(
                cve.clone(),
                CveInfo {
                    cvss: r.get::<Option<f64>, _>("cvss").map(|c| c as f32),
                    epss: r.get::<Option<f64>, _>("epss").map(|c| c as f32),
                    kev: r.get::<i64, _>("kev") != 0,
                },
            );
        }
    }
    Ok(out)
}

pub async fn cache_put(pool: &SqlitePool, entries: &HashMap<String, CveInfo>) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    for (cve, i) in entries {
        sqlx::query("INSERT OR REPLACE INTO cve_cache (cve, cvss, epss, kev, fetched_at) VALUES (?, ?, ?, ?, ?)")
            .bind(cve)
            .bind(i.cvss.map(f64::from))
            .bind(i.epss.map(f64::from))
            .bind(i64::from(i.kev))
            .bind(&now)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// `scan_id -> [critical, high, medium, low, info]` finding counts for all scans.
pub async fn severity_counts(pool: &SqlitePool) -> Result<HashMap<String, [i64; 5]>> {
    let rows = sqlx::query("SELECT scan_id, severity, COUNT(*) AS n FROM findings GROUP BY scan_id, severity")
        .fetch_all(pool)
        .await?;
    let mut m: HashMap<String, [i64; 5]> = HashMap::new();
    for r in rows {
        let slot = match r.get::<String, _>("severity").as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };
        m.entry(r.get("scan_id")).or_default()[slot] = r.get("n");
    }
    Ok(m)
}
