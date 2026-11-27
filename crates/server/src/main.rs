mod creds;
mod db;
mod newscan;
mod web;
mod worker;

use anyhow::{Context, Result};
use creds::CredStore;
use std::path::PathBuf;
use vs_core::{Scanner, Scope};
use vs_enrich::Enricher;
use vs_scanners::{is_available, Nmap, Nuclei, PortScan, RustScan, Vuls};
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
    let wanted = std::env::var("SCANNERS").unwrap_or_else(|_| "rustscan,nuclei".into());
    let mut scanners: Vec<Box<dyn Scanner>> = Vec::new();
    for name in wanted.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (bin, sc): (Option<String>, Box<dyn Scanner>) = match name {
            "rustscan" => {
                // RustScan finds open ports, our code grabs banners. PORTS narrows the range (default: all).
                let binary = std::env::var("RUSTSCAN_BIN").unwrap_or_else(|_| "rustscan".into());
                let mut rs = RustScan { binary: binary.clone(), ..RustScan::default() };
                if let Some(spec) = std::env::var("PORTS").ok().filter(|v| !v.trim().is_empty()) {
                    rs.ports = Some(PortScan::parse_ports(&spec).context("invalid PORTS")?);
                }
                (Some(binary), Box::new(rs))
            }
            "portscan" => {
                // Native scanner: no external binary. PORTS e.g. "22,80,8000-8100" overrides the default list.
                let mut ps = PortScan::default();
                if let Some(spec) = std::env::var("PORTS").ok().filter(|v| !v.trim().is_empty()) {
                    ps.ports = PortScan::parse_ports(&spec).context("invalid PORTS")?;
                }
                (None, Box::new(ps))
            }
            "nmap" => {
                let binary = std::env::var("NMAP_BIN").unwrap_or_else(|_| "nmap".into());
                (Some(binary.clone()), Box::new(Nmap { binary, scripts: nmap_scripts.clone() }))
            }
            "nuclei" => {
                let binary = std::env::var("NUCLEI_BIN").unwrap_or_else(|_| "nuclei".into());
                (Some(binary.clone()), Box::new(Nuclei { binary, ..Nuclei::default() }))
            }
            other => anyhow::bail!("unknown scanner `{other}` in SCANNERS (known: rustscan, portscan, nmap, nuclei)"),
        };
        match bin {
            Some(b) if !is_available(&b) => {
                tracing::warn!("scanner `{name}` disabled: `{b}` not found (run ./install.sh)");
            }
            _ => scanners.push(sc),
        }
    }
    if scanners.is_empty() {
        anyhow::bail!("no usable scanner found; run ./install.sh to install nuclei");
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

    // Deep scan (Vuls + SSH credentials). Credentials travel over plain HTTP and the UI has no auth
    // yet, so it is only offered when bound to loopback.
    let vuls_bin = std::env::var("VULS_BIN").unwrap_or_else(|_| "vuls".into());
    let vuls_db = std::env::var("VULS_DB").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share/vuln-scanner/vuls.db")
    });
    let loopback = bind.parse::<std::net::SocketAddr>().map(|a| a.ip().is_loopback()).unwrap_or(bind.starts_with("localhost:"));
    let deep_off: Option<String> = if !loopback {
        Some("Deep scan is disabled: it sends SSH credentials, and the UI has no login yet, so it only works when BIND is a loopback address.".into())
    } else if !is_available(&vuls_bin) {
        Some(format!("Deep scan is disabled: `{vuls_bin}` not found (run ./install.sh)."))
    } else if !is_available("ssh") || !is_available("ssh-keyscan") || !is_available("ssh-keygen") {
        Some("Deep scan is disabled: the OpenSSH client (ssh, ssh-keyscan, ssh-keygen) is required.".into())
    } else {
        None
    };
    let vuls = deep_off.is_none().then(|| {
        let mut v = Vuls::new(vuls_bin, vuls_db);
        v.skip_db_update = std::env::var("VULS_SKIP_DB_UPDATE").map(|x| x == "1").unwrap_or(false);
        v
    });
    if let Some(r) = &deep_off {
        tracing::info!("{r}");
    }

    let creds = CredStore::default();
    let worker = Worker { pool: pool.clone(), scope: scope.clone(), scanners, enricher, vuls, creds: creds.clone() };
    tokio::spawn(worker.run_loop());

    let app = web::router(web::AppState { pool, scope, creds, deep_off });
    let listener = tokio::net::TcpListener::bind(&bind).await.with_context(|| format!("bind {bind}"))?;
    tracing::info!("listening on http://{bind} (scope: {scope_str}, scanners: {})", names.join(","));
    axum::serve(listener, app).await?;
    Ok(())
}
