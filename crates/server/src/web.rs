use crate::creds::CredStore;
use crate::db;
use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sqlx::SqlitePool;
use vs_core::{Scan, ScanStatus, Scope, SshCreds, Target};
use vs_report::{esc, STYLE};

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub scope: Scope,
    pub creds: CredStore,
    /// `Some(reason)` when deep scans are unavailable.
    pub deep_off: Option<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/scans", post(create_scan))
        .route("/scans/{id}", get(scan_page))
        .route("/scans/{id}/report/{fmt}", get(report))
        .route("/api/scans", get(api_list))
        .route("/api/scans/{id}", get(api_get))
        .route("/api/scans/{id}/events", get(api_events))
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
         <span class=\"muted\">portscan · nuclei · EPSS · KEV</span></div></header>\
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
         <form class=\"card pad\" method=\"post\" action=\"/scans\" autocomplete=\"off\"><div class=\"hero\">\
         <input name=\"target\" required autofocus autocomplete=\"off\" placeholder=\"127.0.0.1  ·  192.168.1.0/24  ·  host.lab\" aria-label=\"Target\">\
         <button class=\"btn\">Start scan</button></div>{deep}</form>\
         <h2>Recent scans</h2>",
        scope = esc(&st.scope.describe()),
        deep = deep_form(&st),
    );
    if scans.is_empty() {
        b.push_str("<div class=\"card empty\">No scans yet. Start one above.</div>");
    } else {
        b.push_str("<div class=\"card tablewrap\"><table><thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Started</th><th></th></tr></thead><tbody>");
        for s in &scans {
            let c = counts.get(&s.id).copied().unwrap_or_default();
            b.push_str(&format!(
                "<tr><td><a class=\"mono\" href=\"/scans/{id}\">{target}</a>{deep}</td><td>{status}</td><td>{chips}</td>\
                 <td class=\"muted\">{when}</td><td><a href=\"/scans/{id}\">Open &rarr;</a></td></tr>",
                id = esc(&s.id),
                target = esc(&s.target),
                deep = if s.deep { " <span class=\"muted\">· deep</span>" } else { "" },
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
    /// Checkbox: present ("on") when deep scan is requested.
    #[serde(default)]
    deep: Option<String>,
    #[serde(default)]
    ssh_user: String,
    #[serde(default)]
    ssh_port: String,
    /// `key` (default) or `password`.
    #[serde(default)]
    ssh_auth: String,
    #[serde(default)]
    ssh_password: String,
    #[serde(default)]
    ssh_key: String,
    #[serde(default)]
    ssh_passphrase: String,
}

/// Deep-scan part of the new-scan form. Secrets are never rendered back.
fn deep_form(st: &AppState) -> String {
    let (disabled, note) = match &st.deep_off {
        Some(reason) => (" disabled", format!("<div class=\"muted\" style=\"margin-top:8px\">{}</div>", esc(reason))),
        None => ("", String::new()),
    };
    format!(
        "<div style=\"margin-top:14px\"><label><input type=\"checkbox\" name=\"deep\" id=\"deep\"{disabled}> \
         <b>Deep scan with Vuls</b> <span class=\"muted\">(log in over SSH and check installed packages for CVEs)</span></label>{note}\
         <div id=\"deepbox\" hidden style=\"margin-top:10px;display:grid;gap:8px;max-width:640px\">\
         <div style=\"display:flex;gap:8px\">\
         <input name=\"ssh_user\" placeholder=\"SSH user\" autocomplete=\"off\" maxlength=\"32\" aria-label=\"SSH user\" style=\"flex:2\">\
         <input name=\"ssh_port\" placeholder=\"Port (22)\" inputmode=\"numeric\" autocomplete=\"off\" maxlength=\"5\" aria-label=\"SSH port\" style=\"flex:1\">\
         <select name=\"ssh_auth\" id=\"sshauth\" aria-label=\"Authentication\" style=\"flex:2\"><option value=\"key\">Private key</option><option value=\"password\">Password</option></select></div>\
         <div id=\"authkey\" style=\"display:grid;gap:8px\">\
         <textarea name=\"ssh_key\" rows=\"6\" spellcheck=\"false\" autocomplete=\"off\" maxlength=\"16384\" \
         placeholder=\"-----BEGIN OPENSSH PRIVATE KEY-----&#10;...\" aria-label=\"SSH private key\" style=\"font-family:monospace\"></textarea>\
         <input type=\"password\" name=\"ssh_passphrase\" placeholder=\"Key passphrase (only if the key is encrypted)\" autocomplete=\"new-password\" maxlength=\"256\" aria-label=\"Key passphrase\"></div>\
         <div id=\"authpw\" hidden><input type=\"password\" name=\"ssh_password\" placeholder=\"SSH password\" autocomplete=\"new-password\" maxlength=\"256\" aria-label=\"SSH password\" style=\"width:100%\"></div>\
         <div class=\"muted\">Secrets are kept in memory only for this scan, never stored or logged. The first deep scan on a new machine downloads the Vuls vulnerability DB (~15 GB).</div></div></div>\
         <script>(function(){{var c=document.getElementById('deep'),b=document.getElementById('deepbox');\
         var m=document.getElementById('sshauth'),k=document.getElementById('authkey'),w=document.getElementById('authpw');\
         function f(){{b.hidden=!c.checked;var p=m.value==='password';k.hidden=p;w.hidden=!p}}c.addEventListener('change',f);m.addEventListener('change',f);f()}})();</script>"
    )
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
    if f.deep.is_none() {
        db::create_scan(&st.pool, &id, &target.as_arg(), None).await?;
        db::audit(&st.pool, "scan_queued", &format!("{id} {}", target.as_arg())).await;
        return Ok(Redirect::to(&format!("/scans/{id}")));
    }

    // ---- deep scan ----
    if let Some(reason) = &st.deep_off {
        return Err(AppError::bad_request(reason));
    }
    if matches!(target, Target::Cidr(_)) {
        return Err(AppError::bad_request("Deep scan works on a single host or IP, not a CIDR range."));
    }
    let port = match f.ssh_port.trim() {
        "" => 22,
        p => p.parse::<u16>().map_err(|_| AppError::bad_request("invalid SSH port"))?,
    };
    // Error messages never echo the submitted values.
    let creds = match f.ssh_auth.as_str() {
        "password" => SshCreds::password(&f.ssh_user, port, &f.ssh_password),
        "" | "key" => SshCreds::key(&f.ssh_user, port, &f.ssh_key, Some(f.ssh_passphrase.as_str())),
        _ => Err("unknown authentication method".into()),
    }
    .map_err(AppError::bad_request)?;
    let (user, port, method) = (creds.user.clone(), creds.port, creds.method());
    // Store the secret BEFORE the scan becomes claimable, and discard it if queueing fails.
    st.creds.put(&id, creds);
    if let Err(e) = db::create_scan(&st.pool, &id, &target.as_arg(), Some(db::DeepInfo { user: &user, port, auth: method })).await {
        st.creds.take(&id);
        return Err(e.into());
    }
    db::audit(&st.pool, "scan_queued", &format!("{id} {} deep user={user} port={port} auth={method}", target.as_arg())).await;
    Ok(Redirect::to(&format!("/scans/{id}")))
}

async fn load(st: &AppState, id: &str) -> Result<Scan, AppError> {
    db::get_scan(&st.pool, id).await?.ok_or_else(AppError::not_found)
}

async fn scan_page(State(st): State<AppState>, Path(id): Path<String>) -> Result<Html<String>, AppError> {
    let scan = load(&st, &id).await?;
    let findings = db::get_findings(&st.pool, &id).await?;
    let active = matches!(scan.status, ScanStatus::Queued | ScanStatus::Running);
    // Live log polling replaces the old full-page refresh; keep a refresh only for browsers without JS.
    let head = if active { "<noscript><meta http-equiv=\"refresh\" content=\"5\"></noscript>" } else { "" };
    let eid = esc(&id);

    let mut b = format!(
        "<a class=\"crumb\" href=\"/\">&larr; All scans</a>\
         <h1><span class=\"mono\">{}</span> {}</h1><p class=\"sub\">Started {} UTC{}</p>",
        esc(&scan.target),
        vs_report::status_pill(status_label(scan.status)),
        scan.created_at.format("%Y-%m-%d %H:%M:%S"),
        scan.finished_at.map(|t| format!(" · finished {}", t.format("%H:%M:%S"))).unwrap_or_default()
            + &match (scan.deep, &scan.ssh_user) {
                (true, Some(u)) => format!(
                    " · deep scan as {}:{} ({})",
                    esc(u),
                    scan.ssh_port.unwrap_or(22),
                    esc(scan.ssh_auth.as_deref().unwrap_or("key"))
                ),
                _ => String::new(),
            },
    );
    if active {
        b.push_str("<div class=\"notice\">Scan in progress. Live log below; the page reloads when the scan ends.</div>");
    }
    if let Some(e) = &scan.error {
        let (label, cls) = if scan.status == ScanStatus::Failed { ("Error", " err") } else { ("Notes", "") };
        b.push_str(&format!("<div class=\"notice{cls}\"><b>{label}:</b> {}</div>", esc(e)));
    }

    b.push_str(&log_panel(&st, &id, active).await?);

    let counts = vs_report::severity_counts(&findings);
    b.push_str("<div class=\"stats\">");
    for (s, n) in vs_report::SEVERITIES.iter().zip(counts) {
        b.push_str(&format!("<button type=\"button\" class=\"stat {0}\" data-f=\"{0}\"><b>{1}</b><span>{0}</span></button>", s.as_str(), n));
    }
    b.push_str("</div><div class=\"toolbar\"><span class=\"muted\" id=\"shown\"></span><span class=\"grow\"></span>");
    let unfixed = findings.iter().filter(|f| f.fix_available == Some(false)).count();
    let fixable = findings.iter().filter(|f| f.fix_available == Some(true)).count();
    if unfixed > 0 {
        // Pre-checked only when it leaves something to show (on fully patched hosts every CVE is "unfixed").
        let checked = if fixable > 0 { " checked" } else { "" };
        b.push_str(&format!(
            "<label class=\"muted\" title=\"Vulnerabilities with no vendor fix yet\"><input type=\"checkbox\" id=\"hidefix\"{checked}> Hide unfixed ({unfixed})</label>"
        ));
    }
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

/// Progress log of a scan: rendered server-side from stored events, then polled while the scan is active.
async fn log_panel(st: &AppState, id: &str, active: bool) -> Result<String, AppError> {
    let events = db::get_events(&st.pool, id, 0).await?;
    if events.is_empty() && !active {
        return Ok(String::new());
    }
    let last = events.last().map(|e| e.id).unwrap_or(0);
    let mut lines = String::new();
    for e in &events {
        lines.push_str(&format!(
            "<div class=\"ev-{lvl}\"><span class=\"muted\">{t}</span> {m}</div>",
            lvl = esc(&e.level),
            t = esc(e.ts.get(11..19).unwrap_or("")),
            m = esc(&e.message),
        ));
    }
    let script = if active {
        format!(
            "<script>(function(){{var id={id_js},last={last},log=document.getElementById('log'),idle=document.getElementById('idle'),\
             lastAt=Date.now();function add(e){{var d=document.createElement('div');d.className='ev-'+e.level;\
             var t=document.createElement('span');t.className='muted';t.textContent=e.ts.slice(11,19)+' ';d.appendChild(t);\
             d.appendChild(document.createTextNode(e.message));log.appendChild(d)}}\
             function tick(){{fetch('/api/scans/'+id+'/events?after='+last,{{cache:'no-store'}}).then(function(r){{return r.json()}}).then(function(j){{\
             var near=log.scrollHeight-log.scrollTop-log.clientHeight<40;\
             j.events.forEach(function(e){{add(e);last=e.id;lastAt=Date.now()}});if(near)log.scrollTop=log.scrollHeight;\
             if(j.status==='done'||j.status==='failed'){{setTimeout(function(){{location.reload()}},500);return}}\
             setTimeout(tick,2000)}}).catch(function(){{setTimeout(tick,4000)}})}}\
             setInterval(function(){{var s=Math.round((Date.now()-lastAt)/1000);idle.textContent='last activity '+s+'s ago';\
             idle.className=s>90?'muted idle-warn':'muted'}},1000);log.scrollTop=log.scrollHeight;tick()}})();</script>",
            id_js = serde_json::to_string(id).unwrap_or_else(|_| "\"\"".into()),
        )
    } else {
        String::new()
    };
    Ok(format!(
        "<style>#log{{max-height:260px;overflow:auto;font:.82rem/1.5 ui-monospace,monospace;padding:10px 14px}}\
         .ev-warn{{color:#b7791f}}.ev-error{{color:#c53030}}.idle-warn{{color:#c53030;font-weight:600}}</style>\
         <div class=\"card\" style=\"margin-bottom:14px\"><div class=\"toolbar\" style=\"padding:8px 14px 0\"><b>Progress log</b>\
         <span class=\"grow\"></span><span class=\"muted\" id=\"idle\"></span></div><div id=\"log\">{lines}</div></div>{script}"
    ))
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    after: i64,
}

async fn api_events(State(st): State<AppState>, Path(id): Path<String>, Query(q): Query<EventsQuery>) -> Result<Json<serde_json::Value>, AppError> {
    let scan = load(&st, &id).await?;
    let events = db::get_events(&st.pool, &id, q.after).await?;
    Ok(Json(serde_json::json!({ "status": scan.status, "events": events })))
}

/// Click a severity card to filter rows; click again to clear. The "Hide unfixed" checkbox drops
/// findings that have no vendor fix, and the cards count only what is not hidden.
const FILTER_JS: &str = r#"<script>
(function(){var on=null,rows=[].slice.call(document.querySelectorAll('#ft tbody tr')),
cards=[].slice.call(document.querySelectorAll('.stat')),lab=document.getElementById('shown'),hf=document.getElementById('hidefix');
function apply(){var n=0,tot=0,cnt={};rows.forEach(function(r){var v=!(hf&&hf.checked&&r.dataset.fix==='0');
if(v){tot++;cnt[r.dataset.sev]=(cnt[r.dataset.sev]||0)+1}
var s=v&&(!on||r.dataset.sev===on);r.style.display=s?'':'none';if(s)n++});
cards.forEach(function(c){c.classList.toggle('on',c.dataset.f===on);c.querySelector('b').textContent=cnt[c.dataset.f]||0});
lab.textContent=n+' of '+tot+' findings'+(on?' ('+on+')':'')+(tot<rows.length?' · '+(rows.length-tot)+' unfixed hidden':'')}
cards.forEach(function(c){c.addEventListener('click',function(){on=on===c.dataset.f?null:c.dataset.f;apply()})});
if(hf)hf.addEventListener('change',apply);apply()})();
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
