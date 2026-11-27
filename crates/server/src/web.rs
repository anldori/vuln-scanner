use crate::creds::CredStore;
use crate::db;
use crate::newscan;
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
        .route("/scans/new", get(new_scan_page))
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

#[derive(Deserialize)]
struct IndexQuery {
    queued: Option<usize>,
}

async fn index(State(st): State<AppState>, Query(q): Query<IndexQuery>) -> Result<Html<String>, AppError> {
    let queued = q.queued;
    let scans = db::list_scans(&st.pool).await?;
    let counts = db::severity_counts(&st.pool).await?;
    let mut b = format!(
        "<div class=\"toolbar\" style=\"margin-top:.2rem\"><div><h1 style=\"margin:0\">Scans</h1>\
         <p class=\"sub\" style=\"margin:.2rem 0 0\">Scope: <code>{scope}</code></p></div><span class=\"grow\"></span>\
         <a class=\"btn\" href=\"/scans/new\">+ New scan</a></div>",
        scope = esc(&st.scope.describe()),
    );
    if let Some(n) = queued.filter(|n| *n > 0) {
        b.push_str(&format!("<div class=\"notice\">Queued {n} scans. They run one after another; open one to follow its progress.</div>"));
    }
    b.push_str("<h2>Recent scans</h2>");
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
    /// Several hosts: newline / comma / space separated. `target` is the legacy single-host field.
    #[serde(default)]
    targets: String,
    #[serde(default)]
    target: String,
    /// `basic` (default) or `deep`. The legacy `deep=on` checkbox is still honoured.
    #[serde(default)]
    scan_type: String,
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

async fn new_scan_page(State(st): State<AppState>) -> Html<String> {
    let v = newscan::FormValues { ssh_auth: "key".into(), ..Default::default() };
    Html(page("New scan", &newscan::form_html(&v, &st.deep_off, &st.scope.describe(), None)))
}

/// Validation failure: show the form again with what was typed (never the secrets).
fn form_error(st: &AppState, v: newscan::FormValues, msg: impl AsRef<str>) -> Response {
    let body = newscan::form_html(&v, &st.deep_off, &st.scope.describe(), Some(msg.as_ref()));
    (StatusCode::BAD_REQUEST, Html(page("New scan", &body))).into_response()
}

async fn create_scan(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<NewScan>) -> Result<Response, AppError> {
    check_origin(&headers)?;
    let deep = f.scan_type == "deep" || f.deep.is_some();
    let raw_targets = if f.targets.trim().is_empty() { f.target.clone() } else { f.targets.clone() };
    let vals = newscan::FormValues {
        targets: raw_targets.clone(),
        deep,
        ssh_user: f.ssh_user.clone(),
        ssh_port: f.ssh_port.clone(),
        ssh_auth: if f.ssh_auth.is_empty() { "key".into() } else { f.ssh_auth.clone() },
    };

    // ---- hosts: validate all before queueing any ----
    let names = newscan::split_targets(&raw_targets);
    if names.is_empty() {
        return Ok(form_error(&st, vals, "Enter at least one host."));
    }
    if names.len() > newscan::MAX_HOSTS {
        return Ok(form_error(&st, vals, format!("Too many hosts ({}); the limit is {} per submission.", names.len(), newscan::MAX_HOSTS)));
    }
    let mut targets = Vec::new();
    let mut problems = Vec::new();
    let mut out_of_scope = false;
    for n in &names {
        match Target::parse(n) {
            Err(e) => problems.push(format!("{n}: {e}")),
            Ok(t) => {
                if let Err(e) = st.scope.check(&t) {
                    db::audit(&st.pool, "scan_rejected", &format!("{} ({e})", t.as_arg())).await;
                    out_of_scope = true;
                    problems.push(format!("{n}: {e}"));
                } else if deep && matches!(t, Target::Cidr(_)) {
                    problems.push(format!("{n}: deep scan works on a single host or IP, not a CIDR range"));
                } else {
                    targets.push(t);
                }
            }
        }
    }
    if !problems.is_empty() {
        return Ok(form_error(
            &st,
            vals,
            if out_of_scope {
                format!(
                    "{}. Allowed scope: {}. To allow more, restart the server with SCOPE=\"<current scope>,<target>\".",
                    problems.join("; "),
                    st.scope.describe()
                )
            } else {
                problems.join("; ")
            },
        ));
    }

    // ---- deep scan login ----
    let creds = if deep {
        if let Some(reason) = &st.deep_off {
            return Ok(form_error(&st, vals, reason));
        }
        let port = match f.ssh_port.trim() {
            "" => Ok(22),
            p => p.parse::<u16>().map_err(|_| "invalid SSH port".to_string()),
        };
        // Error messages never echo the submitted values.
        let c = port.and_then(|port| match f.ssh_auth.as_str() {
            "password" => SshCreds::password(&f.ssh_user, port, &f.ssh_password),
            "" | "key" => SshCreds::key(&f.ssh_user, port, &f.ssh_key, Some(f.ssh_passphrase.as_str())),
            _ => Err("unknown authentication method".into()),
        });
        match c {
            Ok(c) => Some(c),
            Err(e) => return Ok(form_error(&st, vals, e)),
        }
    } else {
        None
    };

    // ---- queue one scan per host ----
    let mut ids = Vec::new();
    for t in &targets {
        let id = uuid::Uuid::new_v4().to_string();
        match &creds {
            None => {
                db::create_scan(&st.pool, &id, &t.as_arg(), None).await?;
                db::audit(&st.pool, "scan_queued", &format!("{id} {}", t.as_arg())).await;
            }
            Some(c) => {
                // Store the secret BEFORE the scan becomes claimable, and discard it if queueing fails.
                st.creds.put(&id, c.clone());
                let info = db::DeepInfo { user: &c.user, port: c.port, auth: c.method() };
                if let Err(e) = db::create_scan(&st.pool, &id, &t.as_arg(), Some(info)).await {
                    st.creds.take(&id);
                    return Err(e.into());
                }
                db::audit(&st.pool, "scan_queued", &format!("{id} {} deep user={} port={} auth={}", t.as_arg(), c.user, c.port, c.method())).await;
            }
        }
        ids.push(id);
    }
    Ok(match ids.as_slice() {
        [one] => Redirect::to(&format!("/scans/{one}")).into_response(),
        _ => Redirect::to(&format!("/?queued={}", ids.len())).into_response(),
    })
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

    b.push_str(&log_panel(&st, &scan, active).await?);

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

/// Progress of a scan: a phase stepper plus the event log. Initial content comes from the DB; while the
/// scan is active the browser polls for new events and reloads the page once the scan ends.
async fn log_panel(st: &AppState, scan: &Scan, active: bool) -> Result<String, AppError> {
    let id = scan.id.as_str();
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
    // JSON inside <script>: "<" is escaped so no event text can close the tag.
    let init = serde_json::json!({
        "id": id, "last": last, "deep": scan.deep, "status": scan.status, "events": events,
    })
    .to_string()
    .replace('<', "\\u003c");
    let poll = if active { "true" } else { "false" };
    Ok(format!(
        r##"<style>
#log{{max-height:280px;overflow:auto;font:.82rem/1.55 ui-monospace,monospace;padding:10px 14px}}
.ev-warn{{color:var(--medium)}}.ev-error{{color:var(--fail)}}.idle-warn{{color:var(--fail);font-weight:600}}
.steps{{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}}
.step{{display:flex;align-items:center;gap:.45rem;padding:.35rem .8rem .35rem .45rem;border-radius:999px;border:1px solid var(--line);background:var(--card);font-size:.85rem;color:var(--muted)}}
.step b{{width:1.45rem;height:1.45rem;border-radius:50%;display:grid;place-items:center;font-size:.72rem;background:var(--bg);border:1px solid var(--line)}}
.step.done{{color:var(--fg)}}.step.done b{{background:var(--ok);border-color:var(--ok);color:#fff}}
.step.active{{color:var(--fg);border-color:var(--run)}}.step.active b{{background:var(--run);border-color:var(--run);color:#fff;animation:pulse 1s infinite}}
.step.fail{{color:var(--fail);border-color:var(--fail)}}.step.fail b{{background:var(--fail);border-color:var(--fail);color:#fff}}
.step.skip{{opacity:.5;text-decoration:line-through}}
</style>
<div class="steps" id="steps" aria-label="Scan phases"></div>
<div class="card" style="margin-bottom:14px"><div class="toolbar" style="padding:8px 14px 0;margin:0"><b>Progress log</b>
<span class="grow"></span><span class="muted" id="idle"></span></div><div id="log">{lines}</div></div>
<script>(function(){{
var S={init},POLL={poll},log=document.getElementById('log'),idle=document.getElementById('idle'),box=document.getElementById('steps'),lastAt=Date.now();
var ORDER=S.deep?[['connect','Check connection'],['vuls','Vulnerability scan'],['scan','Network scan'],['enrich','Enrich'],['save','Save']]
 :[['scan','Network scan'],['enrich','Enrich'],['save','Save']];
function steps(){{
 var seen={{}},fail={{}},cur=null,fin=S.status==='done'||S.status==='failed';
 S.events.forEach(function(e){{if(e.phase){{seen[e.phase]=1;cur=e.phase;if(e.level==='error')fail[e.phase]=1}}}});
 box.textContent='';
 ORDER.forEach(function(p,i){{
  var k=p[0],st=fail[k]?'fail':fin?(seen[k]?'done':'skip'):k===cur?'active':seen[k]?'done':'pending';
  var d=document.createElement('div');d.className='step '+st;
  var n=document.createElement('b');n.textContent=st==='done'?'✓':st==='fail'?'!':String(i+1);
  d.appendChild(n);d.appendChild(document.createTextNode(p[1]));box.appendChild(d)}})}}
function add(e){{var d=document.createElement('div');d.className='ev-'+e.level;
 var t=document.createElement('span');t.className='muted';t.textContent=e.ts.slice(11,19)+' ';
 d.appendChild(t);d.appendChild(document.createTextNode(e.message));log.appendChild(d)}}
steps();log.scrollTop=log.scrollHeight;
if(POLL){{
 setInterval(function(){{var s=Math.round((Date.now()-lastAt)/1000);idle.textContent='last activity '+s+'s ago';idle.className=s>90?'muted idle-warn':'muted'}},1000);
 (function tick(){{fetch('/api/scans/'+S.id+'/events?after='+S.last,{{cache:'no-store'}}).then(function(r){{return r.json()}}).then(function(j){{
  var near=log.scrollHeight-log.scrollTop-log.clientHeight<40;
  j.events.forEach(function(e){{add(e);S.events.push(e);S.last=e.id;lastAt=Date.now()}});
  S.status=j.status;steps();if(near)log.scrollTop=log.scrollHeight;
  if(j.status==='done'||j.status==='failed'){{setTimeout(function(){{location.reload()}},600);return}}
  setTimeout(tick,2000)}}).catch(function(){{setTimeout(tick,4000)}})}})()
}}
}})();</script>"##
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
