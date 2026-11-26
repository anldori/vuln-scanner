mod db;
mod web;
mod worker;

use anyhow::{Context, Result};
use vs_core::{Scanner, Scope};
use vs_enrich::Enricher;
use vs_scanners::{is_available, Nmap, Nuclei};
use worker::Worker;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://vuln-scanner.db".into());
    // Safe default: loopback only. Widen explicitly with e.g. SCOPE="127.0.0.0/8,192.168.56.0/24".
    let scope_str = std::env::var("SCOPE").unwrap_or_else(|_| "127.0.0.0/8,::1".into());
    let scope = Scope::parse_list(&scope_str).context("invalid SCOPE")?;
    let nmap_scripts: Vec<String> = std::env::var("NMAP_SCRIPTS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    // SCANNERS selects and orders plugins; missing binaries are skipped with a warning.
    let wanted = std::env::var("SCANNERS").unwrap_or_else(|_| "nmap,nuclei".into());
    let mut scanners: Vec<Box<dyn Scanner>> = Vec::new();
    for name in wanted.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (bin, sc): (String, Box<dyn Scanner>) = match name {
            "nmap" => {
                let binary = std::env::var("NMAP_BIN").unwrap_or_else(|_| "nmap".into());
                (binary.clone(), Box::new(Nmap { binary, scripts: nmap_scripts.clone() }))
            }
            "nuclei" => {
                let binary = std::env::var("NUCLEI_BIN").unwrap_or_else(|_| "nuclei".into());
                (binary.clone(), Box::new(Nuclei { binary, ..Nuclei::default() }))
            }
            other => anyhow::bail!("unknown scanner `{other}` in SCANNERS (known: nmap, nuclei)"),
        };
        if is_available(&bin) {
            scanners.push(sc);
        } else {
            tracing::warn!("scanner `{name}` disabled: `{bin}` not found (run ./install.sh)");
        }
    }
    if scanners.is_empty() {
        anyhow::bail!("no usable scanner found; run ./install.sh to install nmap and nuclei");
    }
    let names: Vec<&str> = scanners.iter().map(|s| s.name()).collect();

    let enricher = if std::env::var("ENRICH").map(|v| v == "0").unwrap_or(false) {
        tracing::info!("CVE enrichment disabled (ENRICH=0)");
        None
    } else {
        Some(Enricher::new(std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty()))?)
    };

    let pool = db::connect(&db_url).await?;
    let n = db::fail_interrupted(&pool).await?;
    if n > 0 {
        tracing::warn!("marked {n} interrupted scan(s) as failed");
    }

    let worker = Worker { pool: pool.clone(), scope: scope.clone(), scanners, enricher };
    tokio::spawn(worker.run_loop());

    let app = web::router(web::AppState { pool, scope });
    let listener = tokio::net::TcpListener::bind(&bind).await.with_context(|| format!("bind {bind}"))?;
    tracing::info!("listening on http://{bind} (scope: {scope_str}, scanners: {})", names.join(","));
    axum::serve(listener, app).await?;
    Ok(())
}
