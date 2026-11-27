//! "New scan" page: several hosts, scan type (basic / deep) and, for deep scans, SSH login details.

use vs_report::esc;

pub const MAX_HOSTS: usize = 50;

/// Non-secret form values that are shown again after a validation error.
#[derive(Default, Clone)]
pub struct FormValues {
    pub targets: String,
    pub deep: bool,
    pub ssh_user: String,
    pub ssh_port: String,
    pub ssh_auth: String,
}

/// Split a free-form host list (newlines, spaces, commas, semicolons) into unique entries, in order.
pub fn split_targets(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    text.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert(s.to_ascii_lowercase()))
        .map(String::from)
        .collect()
}

const CSS: &str = r##"<style>
.nsf{display:grid;gap:1.2rem;max-width:760px}
.nsf label.lbl{font-weight:600;display:block;margin-bottom:.35rem}
.nsf textarea,.nsf input[type=text],.nsf input[type=password],.nsf select{width:100%;font:inherit;padding:.65rem .8rem;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}
.nsf textarea:focus,.nsf input:focus,.nsf select:focus{outline:2px solid var(--accent);border-color:transparent}
.nsf textarea.mono{font-family:ui-monospace,monospace;font-size:.88rem}
.types{display:grid;grid-template-columns:1fr 1fr;gap:.8rem}
@media(max-width:640px){.types{grid-template-columns:1fr}}
.type{display:block;position:relative;border:1.5px solid var(--line);border-radius:12px;padding:.9rem 1rem;cursor:pointer;background:var(--card)}
.type input{position:absolute;opacity:0;pointer-events:none}
.type b{display:block;margin-bottom:.2rem}.type span{color:var(--muted);font-size:.86rem}
.type:has(input:checked){border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
.type:has(input:disabled){opacity:.55;cursor:not-allowed}
.type:has(input:focus-visible){outline:2px solid var(--accent)}
.deepbox{border:1px dashed var(--line);border-radius:12px;padding:1rem 1.1rem;display:grid;gap:.8rem}
.deepbox[hidden],.nsf [hidden]{display:none}
.row{display:flex;gap:.7rem;flex-wrap:wrap}.row>*{flex:1;min-width:140px}
.flow{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;font-size:.82rem;color:var(--muted)}
.flow i{font-style:normal;border:1px solid var(--line);border-radius:999px;padding:.1rem .6rem;background:var(--bg)}
.count{font-size:.85rem;color:var(--muted)}
.btn[disabled]{opacity:.5;cursor:not-allowed}
</style>"##;

const JS: &str = r##"<script>
(function(){
var f=document.getElementById('nsf'),t=document.getElementById('targets'),cnt=document.getElementById('count'),
 box=document.getElementById('deepbox'),auth=document.getElementById('sshauth'),
 kb=document.getElementById('authkey'),pb=document.getElementById('authpw'),btn=document.getElementById('go');
function hosts(){var s={},n=0;t.value.split(/[\s,;]+/).forEach(function(x){x=x.toLowerCase();if(x&&!s[x]){s[x]=1;n++}});return n}
function deep(){var r=f.querySelector('input[name=scan_type]:checked');return !!r&&r.value==='deep'}
function sync(){
 var n=hosts(),d=deep();
 cnt.textContent=n+(n===1?' host':' hosts')+(n>MAXH?' (max '+MAXH+')':'');
 box.hidden=!d;
 var pw=auth.value==='password';kb.hidden=pw;pb.hidden=!pw;
 // only the visible deep fields are required
 [].forEach.call(box.querySelectorAll('[data-req]'),function(el){el.required=d&&!el.closest('[hidden]')});
 btn.disabled=n===0||n>MAXH;
}
['input','change'].forEach(function(ev){f.addEventListener(ev,sync)});
f.addEventListener('submit',function(){btn.disabled=true;btn.textContent='Starting...'});
sync();
})();
</script>"##;

/// The full "New scan" form. Secrets are never rendered back.
pub fn form_html(v: &FormValues, deep_off: &Option<String>, scope: &str, error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"notice err\">{}</div>", esc(e))).unwrap_or_default();
    let secret_note = if error.is_some() && v.deep {
        "<div class=\"notice\">For safety the password / private key is never shown again; please enter it again.</div>"
    } else {
        ""
    };
    let (deep_disabled, deep_note) = match deep_off {
        Some(reason) => (" disabled", format!("<div class=\"hint\">{}</div>", esc(reason))),
        None => ("", String::new()),
    };
    let (basic_chk, deep_chk) = if v.deep && deep_off.is_none() { ("", " checked") } else { (" checked", "") };
    let auth_pw = v.ssh_auth == "password";
    format!(
        r##"<a class="crumb" href="/">&larr; All scans</a>
<h1>New scan</h1>
<p class="sub">Scope: <code>{scope}</code></p>
{err}{secret_note}
<form id="nsf" class="card pad nsf" method="post" action="/scans" autocomplete="off">
 <div>
  <label class="lbl" for="targets">Hosts</label>
  <textarea id="targets" name="targets" class="mono" rows="5" required autofocus spellcheck="false"
   placeholder="192.168.231.132&#10;10.0.0.5, 10.0.0.6&#10;host.lab&#10;192.168.1.0/24   (CIDR: basic scan only)">{targets}</textarea>
  <div class="hint">One per line, or separated by commas / spaces. Each host becomes its own scan. <span class="count" id="count"></span></div>
 </div>
 <div>
  <span class="lbl" style="font-weight:600;display:block;margin-bottom:.35rem">Scan type</span>
  <div class="types">
   <label class="type"><input type="radio" name="scan_type" value="basic"{basic_chk}><b>Basic</b>
    <span>Network scan: open ports and services (RustScan), web checks (nuclei), CVE enrichment.</span></label>
   <label class="type"><input type="radio" name="scan_type" value="deep"{deep_chk}{deep_disabled}><b>Deep</b>
    <span>Basic + SSH login with Vuls: installed OS packages matched against the vulnerability DB.</span></label>
  </div>
  {deep_note}
 </div>
 <div id="deepbox" class="deepbox" hidden>
  <div class="flow"><i>1 Check connection</i>&rarr;<i>2 Collect packages</i>&rarr;<i>3 Match CVEs</i>&rarr;<i>4 Network scan</i>&rarr;<i>5 Enrich &amp; save</i></div>
  <div class="row">
   <div><label class="lbl" for="ssh_user">SSH user</label>
    <input id="ssh_user" type="text" name="ssh_user" data-req autocomplete="off" maxlength="32" value="{user}"></div>
   <div><label class="lbl" for="ssh_port">Port</label>
    <input id="ssh_port" type="text" name="ssh_port" inputmode="numeric" autocomplete="off" maxlength="5" placeholder="22" value="{port}"></div>
   <div><label class="lbl" for="sshauth">Authentication</label>
    <select id="sshauth" name="ssh_auth"><option value="key"{key_sel}>Private key</option><option value="password"{pw_sel}>Password</option></select></div>
  </div>
  <div id="authkey">
   <label class="lbl" for="ssh_key">Private key</label>
   <textarea id="ssh_key" name="ssh_key" class="mono" rows="6" data-req spellcheck="false" autocomplete="off" maxlength="16384"
    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."></textarea>
   <input type="password" name="ssh_passphrase" style="margin-top:.5rem" autocomplete="new-password" maxlength="256"
    placeholder="Key passphrase (only if the key is encrypted)" aria-label="Key passphrase">
  </div>
  <div id="authpw" hidden>
   <label class="lbl" for="ssh_password">Password</label>
   <input id="ssh_password" type="password" name="ssh_password" data-req autocomplete="new-password" maxlength="256">
  </div>
  <div class="hint">Deep scan works on single hosts (no CIDR). Credentials are used for this scan only, kept in memory, never stored or logged.
   The first deep scan on a machine downloads the Vuls vulnerability DB (~15 GB).</div>
 </div>
 <div><button id="go" class="btn" type="submit">Start scan</button></div>
</form>
<script>var MAXH={max};</script>{CSS}{JS}"##,
        scope = esc(scope),
        targets = esc(&v.targets),
        user = esc(&v.ssh_user),
        port = esc(&v.ssh_port),
        key_sel = if auth_pw { "" } else { " selected" },
        pw_sel = if auth_pw { " selected" } else { "" },
        max = MAX_HOSTS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_dedupes_hosts() {
        let t = split_targets("10.0.0.1, 10.0.0.2\n host.lab ;10.0.0.1\r\nHOST.lab  \n\n");
        assert_eq!(t, ["10.0.0.1", "10.0.0.2", "host.lab"]);
        assert!(split_targets(" \n , ").is_empty());
    }

    #[test]
    fn form_escapes_values_and_never_prints_secrets() {
        let v = FormValues { targets: "<script>x</script>".into(), deep: true, ssh_user: "a\"b".into(), ..Default::default() };
        let h = form_html(&v, &None, "any", Some("bad <b>"));
        assert!(!h.contains("<script>x</script>") && !h.contains("a\"b\""));
        assert!(h.contains("&lt;b&gt;") && h.contains("never shown again"));
        let off = form_html(&v, &Some("no vuls".into()), "any", None);
        assert!(off.contains("value=\"deep\" disabled") && off.contains("no vuls"));
    }
}
