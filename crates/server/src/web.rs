use crate::db;
use axum::extract::{Form, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sqlx::SqlitePool;
use vs_core::{Scan, ScanStatus, Scope, Target};
use vs_report::{esc, STYLE};

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub scope: Scope,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/scans", post(create_scan))
        .route("/scans/{id}", get(scan_page))
        .route("/scans/{id}/report/{fmt}", get(report))
        .route("/api/scans", get(api_list))
        .route("/api/scans/{id}", get(api_get))
        .with_state(state)
}

// ---- errors ----

pub struct AppError(StatusCode, String);

impl AppError {
    fn bad_request(msg: impl ToString) -> Self {
        AppError(StatusCode::BAD_REQUEST, msg.to_string())
    }
    fn not_found() -> Self {
        AppError(StatusCode::NOT_FOUND, "not found".into())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("internal error: {e:#}");
        AppError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Html(page("Error", &format!("<a class=\"crumb\" href=\"/\">&larr; Back</a><h1>{}</h1><div class=\"notice err\">{}</div>", self.0, esc(&self.1))))).into_response()
    }
}

// ---- html helpers ----

fn page(title: &str, body: &str) -> String {
    page_with_head(title, "", body)
}

fn page_with_head(title: &str, head: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{} · Vuln Scanner</title>{head}<style>{STYLE}</style></head><body>\
         <header class=\"top\"><div class=\"in\"><a class=\"brand\" href=\"/\"><span class=\"logo\"></span>Vuln Scanner</a>\
         <span class=\"muted\">nmap · nuclei · EPSS · KEV</span></div></header>\
         <main class=\"wrap\">{body}</main></body></html>",
        esc(title)
    )
}

fn status_label(s: ScanStatus) -> &'static str {
    s.as_str()
}

fn count_chips(c: &[i64; 5]) -> String {
    let names = ["critical", "high", "medium", "low", "info"];
    let chips: String = names
        .iter()
        .zip(c)
        .filter(|(_, n)| **n > 0)
        .map(|(s, n)| format!("<span class=\"chip {s}\" title=\"{s}\">{n}</span>"))
        .collect();
    if chips.is_empty() {
        "<span class=\"muted\">-</span>".into()
    } else {
        format!("<div class=\"chips\">{chips}</div>")
    }
}

// ---- handlers ----

async fn index(State(st): State<AppState>) -> Result<Html<String>, AppError> {
    let scans = db::list_scans(&st.pool).await?;
    let counts = db::severity_counts(&st.pool).await?;
    let mut b = format!(
        "<h1>New scan</h1><p class=\"sub\">Scan a host, IP or CIDR. Scope: <code>{scope}</code></p>\
         <form class=\"card pad\" method=\"post\" action=\"/scans\"><div class=\"hero\">\
         <input name=\"target\" required autofocus autocomplete=\"off\" placeholder=\"127.0.0.1  ·  192.168.1.0/24  ·  host.lab\" aria-label=\"Target\">\
         <button class=\"btn\">Start scan</button></div></form>\
         <h2>Recent scans</h2>",
        scope = esc(&st.scope.describe()),
    );
    if scans.is_empty() {
        b.push_str("<div class=\"card empty\">No scans yet. Start one above.</div>");
    } else {
        b.push_str("<div class=\"card tablewrap\"><table><thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Started</th><th></th></tr></thead><tbody>");
        for s in &scans {
            let c = counts.get(&s.id).copied().unwrap_or_default();
            b.push_str(&format!(
                "<tr><td><a class=\"mono\" href=\"/scans/{id}\">{target}</a></td><td>{status}</td><td>{chips}</td>\
                 <td class=\"muted\">{when}</td><td><a href=\"/scans/{id}\">Open &rarr;</a></td></tr>",
                id = esc(&s.id),
                target = esc(&s.target),
                status = vs_report::status_pill(status_label(s.status)),
                chips = count_chips(&c),
                when = s.created_at.format("%Y-%m-%d %H:%M"),
            ));
        }
        b.push_str("</tbody></table></div>");
    }
    Ok(Html(page("Scans", &b)))
}

#[derive(Deserialize)]
struct NewScan {
    target: String,
}

/// Reject cross-site form posts: a browser-sent Origin must match the Host we were addressed as.
fn check_origin(headers: &HeaderMap) -> Result<(), AppError> {
    let Some(origin) = headers.get(header::ORIGIN) else { return Ok(()) };
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let origin = origin.to_str().unwrap_or("");
    let origin_host = origin.split_once("://").map(|(_, h)| h).unwrap_or(origin);
    if origin_host == host {
        Ok(())
    } else {
        Err(AppError(StatusCode::FORBIDDEN, "cross-origin request rejected".into()))
    }
}

async fn create_scan(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<NewScan>) -> Result<Redirect, AppError> {
    check_origin(&headers)?;
    let target = Target::parse(&f.target).map_err(AppError::bad_request)?;
    if let Err(e) = st.scope.check(&target) {
        db::audit(&st.pool, "scan_rejected", &format!("{} ({e})", target.as_arg())).await;
        return Err(AppError::bad_request(format!(
            "{}: {e}. Allowed scope: {}. To scan it, restart the server with SCOPE=\"<current scope>,{}\".",
            target.as_arg(),
            st.scope.describe(),
            target.as_arg()
        )));
    }
    let id = uuid::Uuid::new_v4().to_string();
    db::create_scan(&st.pool, &id, &target.as_arg()).await?;
    db::audit(&st.pool, "scan_queued", &format!("{id} {}", target.as_arg())).await;
    Ok(Redirect::to(&format!("/scans/{id}")))
}

async fn load(st: &AppState, id: &str) -> Result<Scan, AppError> {
    db::get_scan(&st.pool, id).await?.ok_or_else(AppError::not_found)
}

async fn scan_page(State(st): State<AppState>, Path(id): Path<String>) -> Result<Html<String>, AppError> {
    let scan = load(&st, &id).await?;
    let findings = db::get_findings(&st.pool, &id).await?;
    let active = matches!(scan.status, ScanStatus::Queued | ScanStatus::Running);
    let head = if active { "<meta http-equiv=\"refresh\" content=\"3\">" } else { "" };
    let eid = esc(&id);

    let mut b = format!(
        "<a class=\"crumb\" href=\"/\">&larr; All scans</a>\
         <h1><span class=\"mono\">{}</span> {}</h1><p class=\"sub\">Started {} UTC{}</p>",
        esc(&scan.target),
        vs_report::status_pill(status_label(scan.status)),
        scan.created_at.format("%Y-%m-%d %H:%M:%S"),
        scan.finished_at.map(|t| format!(" · finished {}", t.format("%H:%M:%S"))).unwrap_or_default(),
    );
    if active {
        b.push_str("<div class=\"notice\">Scan in progress. This page refreshes automatically.</div>");
    }
    if let Some(e) = &scan.error {
        let (label, cls) = if scan.status == ScanStatus::Failed { ("Error", " err") } else { ("Notes", "") };
        b.push_str(&format!("<div class=\"notice{cls}\"><b>{label}:</b> {}</div>", esc(e)));
    }

    let counts = vs_report::severity_counts(&findings);
    b.push_str("<div class=\"stats\">");
    for (s, n) in vs_report::SEVERITIES.iter().zip(counts) {
        b.push_str(&format!("<button type=\"button\" class=\"stat {0}\" data-f=\"{0}\"><b>{1}</b><span>{0}</span></button>", s.as_str(), n));
    }
    b.push_str("</div><div class=\"toolbar\"><span class=\"muted\" id=\"shown\"></span><span class=\"grow\"></span>");
    if scan.status == ScanStatus::Done {
        b.push_str(&format!(
            "<a class=\"btn ghost\" href=\"/scans/{eid}/report/html\">HTML</a>\
             <a class=\"btn ghost\" href=\"/scans/{eid}/report/json\">JSON</a>\
             <a class=\"btn ghost\" href=\"/scans/{eid}/report/csv\">CSV</a>"
        ));
    }
    b.push_str("</div>");

    if findings.is_empty() {
        let msg = if active { "Waiting for results..." } else { "No findings." };
        b.push_str(&format!("<div class=\"card empty\">{msg}</div>"));
    } else {
        b.push_str("<div class=\"card tablewrap\"><table id=\"ft\"><thead>");
        b.push_str(vs_report::TABLE_HEAD);
        b.push_str("</thead><tbody>");
        b.push_str(&vs_report::finding_rows(&findings));
        b.push_str("</tbody></table></div>");
        b.push_str(FILTER_JS);
    }
    Ok(Html(page_with_head("Scan", head, &b)))
}

/// Click a severity card to filter rows; click again to clear.
const FILTER_JS: &str = r#"<script>
(function(){var on=null,rows=[].slice.call(document.querySelectorAll('#ft tbody tr')),
cards=[].slice.call(document.querySelectorAll('.stat')),lab=document.getElementById('shown');
function apply(){var n=0;rows.forEach(function(r){var s=!on||r.dataset.sev===on;r.style.display=s?'':'none';if(s)n++});
cards.forEach(function(c){c.classList.toggle('on',c.dataset.f===on)});
lab.textContent=n+' of '+rows.length+' findings'+(on?' ('+on+')':'')}
cards.forEach(function(c){c.addEventListener('click',function(){on=on===c.dataset.f?null:c.dataset.f;apply()})});apply()})();
</script>"#;

async fn report(State(st): State<AppState>, Path((id, fmt)): Path<(String, String)>) -> Result<Response, AppError> {
    let scan = load(&st, &id).await?;
    let findings = db::get_findings(&st.pool, &id).await?;
    let (ctype, body, ext) = match fmt.as_str() {
        "json" => ("application/json", vs_report::to_json(&scan, &findings), "json"),
        "csv" => ("text/csv; charset=utf-8", vs_report::to_csv(&findings), "csv"),
        "html" => ("text/html; charset=utf-8", vs_report::to_html(&scan, &findings), "html"),
        _ => return Err(AppError::not_found()),
    };
    let disp = format!("attachment; filename=\"scan-{}.{ext}\"", scan.id);
    Ok(([(header::CONTENT_TYPE, ctype.to_string()), (header::CONTENT_DISPOSITION, disp)], body).into_response())
}

async fn api_list(State(st): State<AppState>) -> Result<Json<Vec<Scan>>, AppError> {
    Ok(Json(db::list_scans(&st.pool).await?))
}

async fn api_get(State(st): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>, AppError> {
    let scan = load(&st, &id).await?;
    let findings = db::get_findings(&st.pool, &id).await?;
    Ok(Json(serde_json::json!({ "scan": scan, "findings": vs_report::sorted(&findings) })))
}
