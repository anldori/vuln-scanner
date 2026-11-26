//! Report generation: JSON, CSV and a self-contained HTML page.

use vs_core::{Finding, Scan, Severity};

/// Escape text for safe inclusion in HTML (findings contain remote-controlled banners!).
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// Findings sorted most severe first, then highest priority, then host/port.
pub fn sorted(findings: &[Finding]) -> Vec<&Finding> {
    let mut v: Vec<&Finding> = findings.iter().collect();
    v.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.priority.total_cmp(&a.priority))
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.port.cmp(&b.port))
    });
    v
}

pub fn to_json(scan: &Scan, findings: &[Finding]) -> String {
    let v = serde_json::json!({ "scan": scan, "findings": sorted(findings) });
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into())
}

/// CSV field with quoting plus protection against spreadsheet formula injection.
fn csv_field(s: &str) -> String {
    let mut s = s.to_string();
    if matches!(s.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r')) {
        s.insert(0, '\'');
    }
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn to_csv(findings: &[Finding]) -> String {
    let mut out = String::from("severity,priority,host,port,protocol,service,title,cve,cvss,epss,kev,evidence,tool\n");
    for f in sorted(findings) {
        let cols = [
            f.severity.as_str().to_string(),
            format!("{:.1}", f.priority),
            f.host.clone(),
            f.port.map(|p| p.to_string()).unwrap_or_default(),
            f.protocol.clone().unwrap_or_default(),
            f.service.clone().unwrap_or_default(),
            f.title.clone(),
            f.cve.join(" "),
            f.cvss.map(|c| format!("{c:.1}")).unwrap_or_default(),
            f.epss.map(|e| format!("{e:.4}")).unwrap_or_default(),
            if f.kev { "yes".to_string() } else { String::new() },
            f.evidence.clone(),
            f.tool.clone(),
        ];
        out.push_str(&cols.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

pub const STYLE: &str = r#"
:root{--bg:#f5f6fa;--card:#fff;--fg:#1c2230;--muted:#6b7487;--line:#e4e7ee;--accent:#5b5bf0;--accent-fg:#fff;
--critical:#c1121f;--high:#e8590c;--medium:#e0a100;--low:#2f9e44;--info:#5c7a99;--ok:#2f9e44;--run:#1c7ed6;--fail:#c1121f;
--shadow:0 1px 2px rgba(20,25,40,.06),0 4px 14px rgba(20,25,40,.05)}
@media (prefers-color-scheme:dark){:root{--bg:#0e1118;--card:#171b25;--fg:#e6e9f2;--muted:#8e98ad;--line:#262c3a;--accent:#7c7cff;--accent-fg:#0e1118;
--critical:#ff5d6c;--high:#ff8a3d;--medium:#f4c542;--low:#51cf66;--info:#7f9cc0;--ok:#51cf66;--run:#4dabf7;--fail:#ff5d6c;--shadow:0 1px 2px rgba(0,0,0,.4)}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}
.top{background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.top .in{max-width:1200px;margin:0 auto;padding:.8rem 1.25rem;display:flex;align-items:center;gap:.7rem}
.brand{font-weight:700;font-size:1.1rem;color:var(--fg)!important;display:flex;align-items:center;gap:.5rem}
.logo{width:26px;height:26px;border-radius:8px;background:linear-gradient(135deg,var(--accent),#c026d3);display:inline-block}
.wrap{max-width:1200px;margin:0 auto;padding:1.5rem 1.25rem 3rem}
h1{font-size:1.6rem;margin:.2rem 0 .3rem}h2{font-size:1.05rem;margin:2rem 0 .8rem}
.muted{color:var(--muted)}.sub{color:var(--muted);margin:0 0 1.2rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}
.pad{padding:1.1rem 1.25rem}
.hero{display:flex;gap:.7rem;flex-wrap:wrap}
.hero input{flex:1;min-width:220px;font:inherit;padding:.7rem .9rem;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}
.hero input:focus{outline:2px solid var(--accent);border-color:transparent}
.btn{font:inherit;font-weight:600;border:0;border-radius:10px;padding:.7rem 1.2rem;background:var(--accent);color:var(--accent-fg);cursor:pointer;display:inline-block}
.btn:hover{filter:brightness(1.08);text-decoration:none}
.btn.ghost{background:transparent;color:var(--fg);border:1px solid var(--line);padding:.45rem .8rem;font-size:.85rem}
.btn.ghost:hover{background:var(--bg)}
.hint{font-size:.85rem;color:var(--muted);margin:.6rem 0 0}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);text-align:left;padding:.7rem 1rem;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:.75rem 1rem;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:color-mix(in srgb,var(--accent) 5%,transparent)}
.empty{padding:2.2rem;text-align:center;color:var(--muted)}
.pill{display:inline-flex;align-items:center;gap:.4rem;font-size:.75rem;font-weight:600;padding:.15rem .6rem;border-radius:999px;border:1px solid currentColor;white-space:nowrap}
.pill::before{content:"";width:.5rem;height:.5rem;border-radius:50%;background:currentColor}
.pill.done{color:var(--ok)}.pill.failed{color:var(--fail)}
.pill.running,.pill.queued{color:var(--run)}.pill.running::before{animation:pulse 1s infinite}
@keyframes pulse{50%{opacity:.25}}
.sev{display:inline-block;font-size:.68rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:.12rem .5rem;border-radius:6px;color:#fff;min-width:4.6rem;text-align:center}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium);color:#241a00}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:.8rem;margin:1.2rem 0}
@media(max-width:700px){.stats{grid-template-columns:repeat(3,1fr)}}
.stat{padding:.9rem 1rem;border-radius:12px;background:var(--card);border:1px solid var(--line);border-top:4px solid var(--c);cursor:pointer;text-align:left;font:inherit;color:inherit}
.stat b{display:block;font-size:1.7rem;line-height:1.1}.stat span{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.stat.on{outline:2px solid var(--c)}
.stat.critical{--c:var(--critical)}.stat.high{--c:var(--high)}.stat.medium{--c:var(--medium)}.stat.low{--c:var(--low)}.stat.info{--c:var(--info)}
.chips{display:flex;gap:.3rem;flex-wrap:wrap}
.chip{font-size:.72rem;font-weight:700;padding:.05rem .45rem;border-radius:6px;color:#fff;background:var(--c)}
.chip.critical{--c:var(--critical)}.chip.high{--c:var(--high)}.chip.medium{--c:var(--medium);color:#241a00}.chip.low{--c:var(--low)}.chip.info{--c:var(--info)}
.bar{display:block;width:84px;height:6px;border-radius:99px;background:var(--line);overflow:hidden;margin-top:.35rem}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--medium),var(--critical))}
.ft{font-weight:600}.ev{color:var(--muted);font-size:.82rem;word-break:break-word;margin-top:.15rem}
.tag{font-size:.68rem;color:var(--muted);border:1px solid var(--line);border-radius:5px;padding:0 .35rem;margin-left:.35rem;font-weight:500}
.cve{display:inline-block;font-size:.76rem;font-family:ui-monospace,monospace;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:0 .4rem;margin:0 .25rem .25rem 0}
.kev{display:inline-block;font-size:.68rem;font-weight:800;background:var(--critical);color:#fff;border-radius:6px;padding:.05rem .4rem;margin-left:.3rem}
.toolbar{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin:1.4rem 0 .8rem}
.toolbar .grow{flex:1}
.notice{border-left:4px solid var(--medium);padding:.7rem 1rem;margin:.8rem 0;border-radius:8px;background:var(--card);border:1px solid var(--line);border-left-width:4px;font-size:.88rem}
.notice.err{border-left-color:var(--fail)}
.crumb{font-size:.85rem;margin-bottom:.5rem;display:inline-block}
"#;

pub fn sev_badge(s: Severity) -> String {
    format!("<span class=\"sev {0}\">{0}</span>", s.as_str())
}

pub fn status_pill(status: &str) -> String {
    format!("<span class=\"pill {0}\">{0}</span>", esc(status))
}

fn is_cve_id(s: &str) -> bool {
    let mut p = s.split('-');
    p.next() == Some("CVE")
        && p.next().is_some_and(|y| y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()))
        && p.next().is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && p.next().is_none()
}

/// CVE ids as chips linking to NVD (only well-formed ids become links).
pub fn cve_chips(cves: &[String]) -> String {
    cves.iter()
        .map(|c| {
            if is_cve_id(c) {
                format!("<a class=\"cve\" href=\"https://nvd.nist.gov/vuln/detail/{0}\" target=\"_blank\" rel=\"noopener noreferrer\">{0}</a>", esc(c))
            } else {
                format!("<span class=\"cve\">{}</span>", esc(c))
            }
        })
        .collect()
}

pub fn epss_cell(f: &Finding) -> String {
    f.epss.map(|e| format!("{:.1}%", e * 100.0)).unwrap_or_default()
}

pub fn kev_cell(f: &Finding) -> &'static str {
    if f.kev {
        "<span class=\"kev\" title=\"CISA Known Exploited Vulnerability\">KEV</span>"
    } else {
        ""
    }
}

/// `<tr>` rows for the findings table (shared by the web UI and the HTML report).
pub fn finding_rows(findings: &[Finding]) -> String {
    let mut h = String::new();
    for f in sorted(findings) {
        let target = match f.port {
            Some(p) => format!("{}:{}", esc(&f.host), p),
            None => esc(&f.host),
        };
        let svc = match (&f.protocol, &f.service) {
            (Some(p), Some(s)) => format!("{}/{}", esc(p), esc(s)),
            (Some(p), None) => esc(p),
            (None, Some(s)) => esc(s),
            _ => String::new(),
        };
        let ev = if f.evidence.is_empty() { String::new() } else { format!("<div class=\"ev\">{}</div>", esc(&f.evidence)) };
        let scores = {
            let mut v = Vec::new();
            if let Some(c) = f.cvss {
                v.push(format!("CVSS <b>{c:.1}</b>"));
            }
            if f.epss.is_some() {
                v.push(format!("EPSS <b>{}</b>", epss_cell(f)));
            }
            format!("{}{}", v.join("<br>"), kev_cell(f))
        };
        h.push_str(&format!(
            "<tr data-sev=\"{sev}\"><td>{badge}<span class=\"bar\" title=\"priority {p:.1}/100\"><i style=\"width:{w:.0}%\"></i></span></td>\
             <td><span class=\"mono\">{target}</span><div class=\"ev\">{svc}</div></td>\
             <td><span class=\"ft\">{title}</span><span class=\"tag\">{tool}</span>{ev}</td>\
             <td>{cves}</td><td>{scores}</td></tr>",
            sev = f.severity.as_str(),
            badge = sev_badge(f.severity),
            p = f.priority,
            w = f.priority.clamp(0.0, 100.0),
            title = esc(&f.title),
            tool = esc(&f.tool),
            cves = cve_chips(&f.cve),
        ));
    }
    h
}

pub const TABLE_HEAD: &str = "<tr><th>Risk</th><th>Target</th><th>Finding</th><th>CVE</th><th>Scores</th></tr>";

pub fn severity_counts(findings: &[Finding]) -> [usize; 5] {
    let mut c = [0; 5];
    for f in findings {
        c[match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }] += 1;
    }
    c
}

pub const SEVERITIES: [Severity; 5] = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];

/// Self-contained HTML report (no external resources).
pub fn to_html(scan: &Scan, findings: &[Finding]) -> String {
    let counts = severity_counts(findings);
    let mut h = String::new();
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Scan report</title>");
    h.push_str(&format!("<style>{STYLE}</style></head><body><div class=\"wrap\">"));
    h.push_str(&format!(
        "<h1>Vulnerability scan report</h1><p class=\"sub\">Target <code>{}</code> &middot; {} &middot; started {} &middot; id <code>{}</code></p>",
        esc(&scan.target),
        status_pill(scan.status.as_str()),
        scan.created_at.format("%Y-%m-%d %H:%M UTC"),
        esc(&scan.id)
    ));
    h.push_str("<div class=\"stats\">");
    for (s, n) in SEVERITIES.iter().zip(counts) {
        h.push_str(&format!("<div class=\"stat {0}\"><b>{1}</b><span>{0}</span></div>", s.as_str(), n));
    }
    h.push_str("</div><div class=\"card tablewrap\"><table><thead>");
    h.push_str(TABLE_HEAD);
    h.push_str("</thead><tbody>");
    h.push_str(&finding_rows(findings));
    h.push_str("</tbody></table></div></div></body></html>");
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vs_core::ScanStatus;

    fn finding(title: &str, sev: Severity) -> Finding {
        Finding {
            fingerprint: "x".into(),
            host: "10.0.0.1".into(),
            port: Some(80),
            protocol: Some("tcp".into()),
            service: Some("http".into()),
            title: title.into(),
            severity: sev,
            cve: vec!["CVE-2021-1".into()],
            cvss: Some(7.5),
            epss: Some(0.5),
            kev: true,
            priority: 60.0,
            evidence: "Apache, 2.4".into(),
            tool: "nmap".into(),
        }
    }

    fn scan() -> Scan {
        Scan {
            id: "abc".into(),
            target: "10.0.0.1".into(),
            status: ScanStatus::Done,
            created_at: Utc::now(),
            finished_at: None,
            error: None,
        }
    }

    #[test]
    fn html_escapes_remote_content() {
        let html = to_html(&scan(), &[finding("<script>alert(1)</script>", Severity::High)]);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn csv_quotes_and_neutralises_formulas() {
        let csv = to_csv(&[finding("=HYPERLINK(\"x\")", Severity::Low)]);
        assert!(csv.contains("\"'=HYPERLINK(\"\"x\"\")\""), "{csv}");
        assert!(csv.contains("\"Apache, 2.4\""));
        assert!(csv.contains(",0.5000,yes,"), "{csv}");
    }

    #[test]
    fn sorted_most_severe_first() {
        let fs = [finding("a", Severity::Low), finding("b", Severity::Critical)];
        assert_eq!(sorted(&fs)[0].title, "b");
        let mut hi = finding("hi", Severity::High);
        hi.priority = 90.0;
        let lo = finding("lo", Severity::High);
        let fs = [lo, hi];
        assert_eq!(sorted(&fs)[0].title, "hi");
    }
}
