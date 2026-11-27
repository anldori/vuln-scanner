//! Vuls plugin (https://github.com/future-architect/vuls): authenticated "deep" scan of a host
//! over SSH. Reads installed packages and matches them against Vuls' vulnerability DB.
//!
//! Secrets: the private key is written to a private (0700) temp dir with mode 0600 and removed
//! when the scan ends, including on timeout or error (the dir is owned by the running future).
//! Nothing secret ever appears in argv.

use crate::exec::{run_capture, run_capture_env, which};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use vs_core::{Finding, ScanOptions, Scanner, Severity, SshAuth, SshCreds, Target};

/// Name of the single server entry in the generated config; also the results file name.
const SERVER: &str = "target";
const MAX_REPORT_BYTES: u64 = 512 * 1024 * 1024;

pub struct Vuls {
    pub binary: String,
    /// Vuls vulnerability DB (`[vuls2] Path`). It is large (~15 GB) and is fetched on first use.
    pub db_path: PathBuf,
    /// Skip the DB update check (offline use, or when the DB is refreshed out of band).
    pub skip_db_update: bool,
    /// Budget for `vuls report`, which downloads/updates the DB (the first run is slow).
    pub report_timeout_secs: u64,
}

impl Vuls {
    pub fn new(binary: String, db_path: PathBuf) -> Self {
        Self { binary, db_path, skip_db_update: false, report_timeout_secs: 3600 }
    }
}

// ---- config.toml (built with a serializer, never string formatting, to prevent TOML injection) ----

#[derive(Serialize)]
struct Config {
    vuls2: Vuls2,
    servers: BTreeMap<String, Server>,
}

#[derive(Serialize)]
struct Vuls2 {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "SkipUpdate")]
    skip_update: bool,
}

#[derive(Serialize)]
struct Server {
    host: String,
    port: String,
    user: String,
    #[serde(rename = "keyPath", skip_serializing_if = "Option::is_none")]
    key_path: Option<String>,
    #[serde(rename = "sshConfigPath")]
    ssh_config_path: String,
    #[serde(rename = "scanMode")]
    scan_mode: Vec<String>,
}

fn build_config(host: &str, creds: &SshCreds, key: Option<&Path>, ssh_config: &Path, db: &Path, skip_update: bool) -> Result<String> {
    let path = |p: &Path| p.to_str().map(String::from).ok_or_else(|| anyhow!("non-UTF-8 path"));
    let server = Server {
        host: host.to_string(),
        port: creds.port.to_string(),
        user: creds.user.clone(),
        key_path: key.map(path).transpose()?,
        ssh_config_path: path(ssh_config)?,
        scan_mode: vec!["fast".into()], // no root needed
    };
    let cfg = Config {
        vuls2: Vuls2 { path: path(db)?, skip_update },
        servers: BTreeMap::from([(SERVER.to_string(), server)]),
    };
    toml::to_string(&cfg).context("serialize vuls config")
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

fn write_exec(path: &Path, content: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).open(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

/// Vuls hard-codes `-o PasswordAuthentication=no` (and possibly BatchMode) on its ssh command line,
/// which beats ssh_config. This `ssh` wrapper, placed first on the child's PATH, drops those two
/// options so ssh can ask `SSH_ASKPASS` for a password / key passphrase.
fn ssh_shim(real_ssh: &Path) -> Result<String> {
    let real = real_ssh.to_str().filter(|s| !s.contains(['\'', '\n'])).context("unsupported ssh path")?;
    Ok(format!(
        r#"#!/bin/sh
n=$#; i=0
while [ $i -lt $n ]; do
  a=$1; shift; i=$((i+1))
  if [ "$a" = "-o" ] && [ $i -lt $n ]; then
    b=$1; shift; i=$((i+1))
    case "$b" in PasswordAuthentication=*|BatchMode=*) ;; *) set -- "$@" "$a" "$b" ;; esac
  else
    case "$a" in -oPasswordAuthentication=*|-oBatchMode=*) ;; *) set -- "$@" "$a" ;; esac
  fi
done
exec '{real}' "$@"
"#
    ))
}

/// Never let a secret leak through an error message (stderr tails come from external tools).
fn redact(msg: String, secrets: &[&str]) -> String {
    secrets.iter().filter(|s| !s.is_empty()).fold(msg, |m, s| m.replace(s, "<redacted>"))
}

#[async_trait]
impl Scanner for Vuls {
    fn name(&self) -> &'static str {
        "vuls"
    }

    async fn run(&self, target: &Target, opts: &ScanOptions) -> Result<Vec<Finding>> {
        let creds = opts.ssh.as_ref().context("deep scan needs SSH credentials")?;
        self.run_inner(target, opts, creds).await.map_err(|e| {
            let secrets: Vec<&str> = match &creds.auth {
                SshAuth::Password(p) => vec![p.as_str()],
                SshAuth::Key { private_key, passphrase } => vec![private_key.as_str(), passphrase.as_deref().unwrap_or("")],
            };
            anyhow!(redact(format!("{e:#}"), &secrets))
        })
    }
}

impl Vuls {
    async fn run_inner(&self, target: &Target, opts: &ScanOptions, creds: &SshCreds) -> Result<Vec<Finding>> {
        // Re-validate (defence in depth): user/port/key end up in files and argv.
        match &creds.auth {
            SshAuth::Password(p) => SshCreds::password(&creds.user, creds.port, p),
            SshAuth::Key { private_key, passphrase } => SshCreds::key(&creds.user, creds.port, private_key, passphrase.as_deref()),
        }
        .map_err(|e| anyhow!(e))?;
        let host = match target {
            Target::Ip(_) | Target::Host(_) => target.as_arg(),
            Target::Cidr(_) => bail!("deep scan supports a single host, not a CIDR range"),
        };

        // Dropped on every exit path (error, timeout, cancellation) => key and secret files are deleted.
        let dir = tempfile::Builder::new().prefix("vs-vuls-").tempdir().context("create temp dir")?;
        let d = dir.path();
        let (key, known_hosts, ssh_config, cfg_path) =
            (d.join("id_key"), d.join("known_hosts"), d.join("ssh_config"), d.join("config.toml"));
        let (results, logs, cache) = (d.join("results"), d.join("log"), d.join("cache.db"));
        std::fs::create_dir(&results)?;
        std::fs::create_dir(&logs)?;

        // What ssh must be asked for through SSH_ASKPASS: the password, or the key's passphrase.
        let (key_pem, secret): (Option<&str>, Option<&str>) = match &creds.auth {
            SshAuth::Password(p) => (None, Some(p)),
            SshAuth::Key { private_key, passphrase } => (Some(private_key), passphrase.as_deref()),
        };
        let mut env: Vec<(String, String)> = Vec::new();
        let mut auth_opts = String::new();
        if let Some(pem) = key_pem {
            write_private(&key, pem)?;
            auth_opts.push_str("  IdentitiesOnly yes\n");
        } else {
            auth_opts.push_str("  PreferredAuthentications password,keyboard-interactive\n  PubkeyAuthentication no\n");
        }
        if let Some(secret) = secret {
            let (secret_file, askpass, bin) = (d.join("secret"), d.join("askpass.sh"), d.join("bin"));
            write_private(&secret_file, secret)?;
            write_exec(&askpass, &format!("#!/bin/sh\nexec cat '{}'\n", secret_file.display()))?;
            std::fs::create_dir(&bin)?;
            write_exec(&bin.join("ssh"), &ssh_shim(&which("ssh").context("`ssh` not found on PATH")?)?)?;
            let old_path = std::env::var("PATH").unwrap_or_default();
            env.push(("PATH".into(), format!("{}:{old_path}", bin.display())));
            env.push(("SSH_ASKPASS".into(), askpass.display().to_string()));
            env.push(("SSH_ASKPASS_REQUIRE".into(), "force".into())); // use askpass even when a tty exists
            auth_opts.push_str("  NumberOfPasswordPrompts 1\n"); // a wrong password must not be retried
        } else {
            auth_opts.push_str("  BatchMode yes\n");
        }

        if key_pem.is_some() {
            // Fail early and clearly on a broken key or a missing/wrong passphrase.
            let key_s = key.to_str().context("temp path")?.to_string();
            let args: Vec<String> = if secret.is_some() {
                vec!["-y".into(), "-f".into(), key_s]
            } else {
                vec!["-y".into(), "-P".into(), String::new(), "-f".into(), key_s]
            };
            run_capture_env("ssh-keygen", &args, 20, &env).await.map_err(|_| {
                if secret.is_some() {
                    anyhow!("SSH private key is invalid or the passphrase is wrong")
                } else {
                    anyhow!("SSH private key is invalid or passphrase-protected (enter its passphrase)")
                }
            })?;
        }

        // Pin the host key for this scan only (trust-on-first-use against the scoped target).
        let scan = run_capture(
            "ssh-keyscan",
            &["-T".into(), "5".into(), "-p".into(), creds.port.to_string(), "--".into(), host.clone()],
            30,
        )
        .await
        .with_context(|| format!("ssh-keyscan {host}:{}", creds.port))?;
        if !scan.lines().any(|l| !l.starts_with('#') && !l.trim().is_empty()) {
            bail!("no SSH host key from {host}:{} (is sshd reachable?)", creds.port);
        }
        write_private(&known_hosts, &scan)?;
        write_private(&ssh_config, &format!("Host *\n  UserKnownHostsFile \"{}\"\n{auth_opts}", known_hosts.display()))?;
        let key_opt = key_pem.map(|_| key.as_path());
        write_private(&cfg_path, &build_config(&host, creds, key_opt, &ssh_config, &self.db_path, self.skip_db_update)?)?;

        let common = |sub: &str| -> Vec<String> {
            vec![
                sub.into(),
                format!("-config={}", cfg_path.display()),
                format!("-results-dir={}", results.display()),
                format!("-log-dir={}", logs.display()),
            ]
        };
        let mut scan_args = common("scan");
        scan_args.extend([format!("-cachedb-path={}", cache.display()), "-quiet".into(), SERVER.into()]);
        run_capture_env(&self.binary, &scan_args, opts.timeout_secs, &env).await.context(
            "vuls scan failed (check the SSH user, password/key and that the account can log in over SSH)",
        )?;

        let mut report_args = common("report");
        report_args.extend(
            ["-format-json", "-to-localfile", "-no-progress", "-quiet", "-trivy-skip-db-update", "-trivy-skip-java-db-update"]
                .map(String::from),
        );
        run_capture_env(&self.binary, &report_args, self.report_timeout_secs, &env).await.context("vuls report")?;

        let json = read_result(&results)?;
        parse_report(&json, &host)
    }
}

/// `vuls report -to-localfile` rewrites `results/<datetime>/target.json` in place.
fn read_result(results: &Path) -> Result<String> {
    let mut best: Option<PathBuf> = None;
    for e in std::fs::read_dir(results)? {
        let p = e?.path().join(format!("{SERVER}.json"));
        if p.is_file() && best.as_ref().is_none_or(|b| p > *b) {
            best = Some(p);
        }
    }
    let p = best.context("vuls produced no result file")?;
    if std::fs::metadata(&p)?.len() > MAX_REPORT_BYTES {
        bail!("vuls result is too large");
    }
    Ok(std::fs::read_to_string(p)?)
}

// ---- report JSON (only the fields we need) ----

#[derive(Deserialize)]
struct Report {
    #[serde(rename = "scannedCves", default)]
    cves: HashMap<String, Cve>,
    #[serde(default)]
    packages: HashMap<String, Pkg>,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct Cve {
    #[serde(rename = "affectedPackages", default)]
    affected: Vec<Affected>,
    #[serde(rename = "cveContents", default)]
    contents: HashMap<String, Vec<Content>>,
}

#[derive(Deserialize)]
struct Affected {
    name: String,
    #[serde(rename = "notFixedYet", default)]
    not_fixed: bool,
    #[serde(rename = "fixedIn", default)]
    fixed_in: String,
    /// Distro triage state for unfixed CVEs, e.g. `needed`, `pending`, `deferred`.
    #[serde(rename = "fixState", default)]
    fix_state: String,
}

#[derive(Deserialize, Default)]
struct Content {
    #[serde(rename = "cvss3Score", default)]
    cvss3: f64,
    #[serde(rename = "cvss2Score", default)]
    cvss2: f64,
}

#[derive(Deserialize)]
struct Pkg {
    #[serde(default)]
    version: String,
}

/// Best CVSS: NVD v3, else any source's v3, else NVD v2, else any v2.
fn best_score(contents: &HashMap<String, Vec<Content>>) -> Option<f32> {
    let max = |srcs: Vec<&Vec<Content>>, f: fn(&Content) -> f64| {
        srcs.into_iter().flatten().map(f).fold(0.0_f64, f64::max)
    };
    let nvd: Vec<_> = contents.get("nvd").into_iter().collect();
    let all: Vec<_> = contents.values().collect();
    let v3n = max(nvd.clone(), |c| c.cvss3);
    let v3 = max(all.clone(), |c| c.cvss3);
    let v2n = max(nvd, |c| c.cvss2);
    let v2 = max(all, |c| c.cvss2);
    [v3n, v3, v2n, v2].into_iter().find(|s| *s > 0.0).map(|s| s as f32)
}

/// One finding per CVE per host, listing the affected packages as evidence.
pub fn parse_report(json: &str, host: &str) -> Result<Vec<Finding>> {
    let r: Report = serde_json::from_str(json).context("invalid vuls report JSON")?;
    if !r.errors.is_empty() {
        let e: String = r.errors.join("; ").chars().take(300).collect();
        bail!("vuls reported errors: {e}");
    }
    let mut ids: Vec<&String> = r.cves.keys().collect();
    ids.sort();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let c = &r.cves[id];
        let mut aff: Vec<&Affected> = c.affected.iter().collect();
        aff.sort_by(|a, b| a.name.cmp(&b.name));
        let desc = |a: &Affected| {
            let ver = r.packages.get(&a.name).map(|p| p.version.as_str()).filter(|v| !v.is_empty());
            let mut s = a.name.clone();
            if let Some(v) = ver {
                s.push(' ');
                s.push_str(v);
            }
            if !a.fixed_in.is_empty() {
                s.push_str(&format!(" (fixed in {})", a.fixed_in));
            } else if a.not_fixed {
                if a.fix_state.is_empty() {
                    s.push_str(" (no fix yet)");
                } else {
                    s.push_str(&format!(" (no fix yet: {})", a.fix_state));
                }
            }
            s
        };
        let shown: Vec<String> = aff.iter().take(8).map(|a| desc(a)).collect();
        let more = aff.len().saturating_sub(8);
        let mut evidence = shown.join("; ");
        if more > 0 {
            evidence.push_str(&format!("; +{more} more"));
        }
        let first = aff.first().map(|a| a.name.as_str()).unwrap_or("system packages");
        let title = if aff.len() > 1 { format!("{id} affects {first} +{} more", aff.len() - 1) } else { format!("{id} affects {first}") };
        let cvss = best_score(&c.contents);
        out.push(Finding {
            fingerprint: Finding::make_fingerprint(host, None, None, &format!("vuls:{id}")),
            host: host.to_string(),
            port: None,
            protocol: None,
            service: Some("os-package".into()),
            title,
            severity: cvss.map(Severity::from_cvss).unwrap_or(Severity::Medium),
            cve: vec![id.clone()],
            cvss,
            epss: None,
            kev: false,
            priority: 0.0,
            evidence,
            tool: "vuls".into(),
            fix_available: Some(aff.iter().any(|a| !a.not_fixed)),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../tests/fixtures/vuls_sample.json");

    fn creds() -> SshCreds {
        SshCreds::key("deploy", 2222, "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----", None).unwrap()
    }

    #[test]
    fn parses_cves_into_findings() {
        let f = parse_report(SAMPLE, "10.0.0.5").unwrap();
        assert_eq!(f.len(), 3, "{f:#?}");
        let crit = f.iter().find(|x| x.cve == ["CVE-2023-45927"]).unwrap();
        assert_eq!(crit.severity, Severity::Critical);
        assert!(crit.cvss.unwrap() >= 9.0);
        assert!(crit.evidence.contains("(fixed in 9.9.9-1)"), "{}", crit.evidence);
        assert_eq!(crit.tool, "vuls");
        assert_eq!(crit.host, "10.0.0.5");
        let v2only = f.iter().find(|x| x.cve == ["CVE-2013-4739"]).unwrap();
        assert_eq!((v2only.cvss, v2only.severity), (Some(4.9), Severity::Medium)); // falls back to CVSS v2
        assert!(v2only.evidence.contains("no fix yet"));
        let none = parse_report(r#"{"scannedCves":{"CVE-1-1":{"cveID":"CVE-1-1","affectedPackages":[{"name":"p"}]}}}"#, "h").unwrap();
        assert_eq!((none[0].cvss, none[0].severity), (None, Severity::Medium));
        // Same CVE on the same host keeps the same fingerprint across scans.
        let again = parse_report(SAMPLE, "10.0.0.5").unwrap();
        assert_eq!(f[0].fingerprint, again[0].fingerprint);
    }

    #[test]
    fn report_errors_fail_the_scan() {
        let e = parse_report(r#"{"errors":["ssh: handshake failed"],"scannedCves":{}}"#, "h").unwrap_err();
        assert!(e.to_string().contains("handshake failed"));
        assert!(parse_report("not json", "h").is_err());
    }

    #[test]
    fn config_is_valid_toml_and_injection_proof() {
        let c = creds();
        let t = build_config("h\"\n[evil]\nx=1", &c, Some(Path::new("/t/k")), Path::new("/t/c"), Path::new("/db"), false).unwrap();
        let v: toml::Table = toml::from_str(&t).unwrap();
        assert!(v.get("evil").is_none(), "{t}");
        let s = &v["servers"][SERVER];
        assert_eq!(s["port"].as_str(), Some("2222"));
        assert_eq!(s["user"].as_str(), Some("deploy"));
        assert_eq!(s["keyPath"].as_str(), Some("/t/k"));
        assert_eq!(s["host"].as_str(), Some("h\"\n[evil]\nx=1"));
        assert!(!t.contains("AAAA"), "key material must not be in config");
    }

    #[test]
    fn password_config_has_no_key_path() {
        let c = SshCreds::password("tester", 22, "hunter2").unwrap();
        let t = build_config("10.0.0.5", &c, None, Path::new("/t/c"), Path::new("/db"), true).unwrap();
        assert!(!t.contains("keyPath") && !t.contains("hunter2"), "{t}");
        assert!(t.contains("SkipUpdate = true"));
    }

    #[test]
    fn shim_drops_only_the_two_options_and_redaction_works() {
        let sh = ssh_shim(Path::new("/usr/bin/ssh")).unwrap();
        assert!(sh.contains("exec '/usr/bin/ssh'") && sh.contains("PasswordAuthentication=*"));
        assert!(ssh_shim(Path::new("/tmp/it's/ssh")).is_err());
        assert_eq!(redact("bad hunter2 here".into(), &["hunter2", ""]), "bad <redacted> here");
    }

    #[tokio::test]
    async fn rejects_cidr_and_missing_creds() {
        let v = Vuls::new("vuls".into(), "/nonexistent/vuls.db".into());
        let cidr = Target::parse("10.0.0.0/24").unwrap();
        let with = ScanOptions { ssh: Some(creds()), ..ScanOptions::default() };
        assert!(v.run(&cidr, &with).await.unwrap_err().to_string().contains("CIDR"));
        let ip = Target::parse("10.0.0.5").unwrap();
        assert!(v.run(&ip, &ScanOptions::default()).await.is_err());
    }
}
