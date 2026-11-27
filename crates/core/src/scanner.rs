use crate::{Finding, Target};
use async_trait::async_trait;

/// How to authenticate to the target over SSH.
#[derive(Clone)]
pub enum SshAuth {
    Password(String),
    /// Private key in PEM/OpenSSH format; `passphrase` when the key is encrypted.
    Key { private_key: String, passphrase: Option<String> },
}

/// SSH login for authenticated ("deep") scans. Held in memory only: never serialized,
/// never logged (`Debug` is redacted) and wiped from memory on drop.
#[derive(Clone)]
pub struct SshCreds {
    pub user: String,
    pub port: u16,
    pub auth: SshAuth,
}

fn check_user_port(user: &str, port: u16) -> Result<String, String> {
    let user = user.trim();
    let ok_user = !user.is_empty()
        && user.len() <= 32
        && user.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !ok_user {
        return Err("invalid SSH user (letters, digits, _ . - only; max 32)".into());
    }
    if port == 0 {
        return Err("invalid SSH port".into());
    }
    Ok(user.to_string())
}

/// Passwords and passphrases are handed to ssh through a file, so one line, no NULs.
fn check_secret(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 256 || s.contains(['\0', '\n', '\r']) {
        return Err(format!("invalid {what} (1-256 characters, single line)"));
    }
    Ok(())
}

impl SshCreds {
    pub fn password(user: &str, port: u16, password: &str) -> Result<Self, String> {
        let user = check_user_port(user, port)?;
        check_secret("password", password)?;
        Ok(Self { user, port, auth: SshAuth::Password(password.to_string()) })
    }

    /// Validate and normalize an untrusted private key (and optional passphrase).
    pub fn key(user: &str, port: u16, private_key: &str, passphrase: Option<&str>) -> Result<Self, String> {
        let user = check_user_port(user, port)?;
        let mut key = private_key.replace("\r\n", "\n").replace('\r', "\n").trim().to_string();
        if key.len() > 16 * 1024 || key.contains('\0') {
            return Err("private key is too large or contains invalid bytes".into());
        }
        if !key.starts_with("-----BEGIN ") || !key.contains("PRIVATE KEY-----") {
            return Err("not a PEM/OpenSSH private key (expected -----BEGIN ... PRIVATE KEY-----)".into());
        }
        let passphrase = passphrase.filter(|p| !p.is_empty());
        if let Some(p) = passphrase {
            check_secret("passphrase", p)?;
        }
        key.push('\n');
        Ok(Self { user, port, auth: SshAuth::Key { private_key: key, passphrase: passphrase.map(String::from) } })
    }

    /// Non-secret label for audit logs and the UI.
    pub fn method(&self) -> &'static str {
        match &self.auth {
            SshAuth::Password(_) => "password",
            SshAuth::Key { passphrase: None, .. } => "key",
            SshAuth::Key { passphrase: Some(_), .. } => "key+passphrase",
        }
    }
}

impl std::fmt::Debug for SshCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshCreds")
            .field("user", &self.user)
            .field("port", &self.port)
            .field("auth", &self.method())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for SshCreds {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match &mut self.auth {
            SshAuth::Password(p) => p.zeroize(),
            SshAuth::Key { private_key, passphrase } => {
                private_key.zeroize();
                if let Some(p) = passphrase {
                    p.zeroize();
                }
            }
        }
    }
}

/// Sink for human-readable progress lines shown live in the web UI. Messages must never
/// contain secrets.
#[derive(Clone)]
pub struct Progress(std::sync::Arc<ProgressFn>);

type ProgressFn = dyn Fn(&str, Option<&str>, &str) + Send + Sync;

impl Progress {
    /// `f(level, phase, message)`; level is `info`, `warn` or `error`.
    pub fn new(f: impl Fn(&str, Option<&str>, &str) + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(f))
    }
}

impl std::fmt::Debug for Progress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Progress")
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub timeout_secs: u64,
    /// Present only for deep scans.
    pub ssh: Option<SshCreds>,
    pub progress: Option<Progress>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { timeout_secs: 900, ssh: None, progress: None }
    }
}

impl ScanOptions {
    fn emit(&self, level: &str, phase: Option<&str>, msg: &str) {
        if let Some(p) = &self.progress {
            (p.0)(level, phase, msg);
        }
    }

    /// Report a progress line (no-op when nobody listens).
    pub fn log(&self, msg: &str) {
        self.emit("info", None, msg);
    }

    /// Progress line that also marks the start/continuation of a named phase (shown as a step in the UI).
    pub fn phase(&self, phase: &str, msg: &str) {
        self.emit("info", Some(phase), msg);
    }

    /// Error line belonging to a phase; the UI marks that phase as failed.
    pub fn fail(&self, phase: &str, msg: &str) {
        self.emit("error", Some(phase), msg);
    }
}

/// Plugin interface. Each external tool (nmap, nuclei, vuls, ...) implements this.
#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;

    /// `target` has already been validated and scope-checked by the caller.
    async fn run(&self, target: &Target, opts: &ScanOptions) -> anyhow::Result<Vec<Finding>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nAAAA\r\n-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn validates_and_normalizes_keys() {
        let c = SshCreds::key(" deploy ", 22, KEY, Some("")).unwrap();
        assert_eq!((c.user.as_str(), c.method()), ("deploy", "key")); // empty passphrase = none
        let SshAuth::Key { private_key, .. } = &c.auth else { panic!() };
        assert!(!private_key.contains('\r') && private_key.ends_with("-----\n"));
        for bad in ["", "-oProxyCommand=x", "a b", "a\"b", "x;y"] {
            assert!(SshCreds::key(bad, 22, KEY, None).is_err(), "{bad}");
        }
        assert!(SshCreds::key("u", 0, KEY, None).is_err());
        assert!(SshCreds::key("u", 22, "hello", None).is_err());
        assert!(SshCreds::key("u", 22, &format!("{KEY}{}", "A".repeat(20000)), None).is_err());
        assert!(SshCreds::key("u", 22, KEY, Some("a\nb")).is_err());
        assert_eq!(SshCreds::key("u", 22, KEY, Some("pp")).unwrap().method(), "key+passphrase");
    }

    #[test]
    fn validates_passwords() {
        assert_eq!(SshCreds::password("root", 22, "p@ss w0rd!").unwrap().method(), "password");
        for bad in ["", "a\nb", "a\0b", &"x".repeat(300)] {
            assert!(SshCreds::password("u", 22, bad).is_err());
        }
        assert!(SshCreds::password("-x", 22, "pw").is_err());
    }

    #[test]
    fn debug_never_prints_secrets() {
        for c in [SshCreds::key("u", 22, KEY, Some("hunter2")).unwrap(), SshCreds::password("u", 22, "hunter2").unwrap()] {
            let s = format!("{:?} {:?}", c, ScanOptions { timeout_secs: 1, ssh: Some(c.clone()), progress: None });
            assert!(!s.contains("AAAA") && !s.contains("hunter2") && s.contains("redacted"), "{s}");
        }
    }
}
