//! Shared helper to run an external tool safely: no shell, no stdin, hard timeout.

use anyhow::{anyhow, bail, Context, Result};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// Run `binary` with `args` (argv, never a shell string) and return its stdout.
/// The process is killed if it exceeds `timeout_secs`. Non-zero exit is an error.
pub async fn run_capture(binary: &str, args: &[String], timeout_secs: u64) -> Result<String> {
    run_capture_env(binary, args, timeout_secs, &[]).await
}

/// Like [`run_capture`], with extra environment variables for the child (e.g. `SSH_ASKPASS`).
pub async fn run_capture_env(binary: &str, args: &[String], timeout_secs: u64, env: &[(String, String)]) -> Result<String> {
    let mut child = Command::new(binary)
        .args(args)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start `{binary}` (is it installed? run ./install.sh)"))?;

    let mut stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let mut stderr = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;

    let work = async {
        let mut out = String::new();
        let mut err = String::new();
        let (r1, r2) = tokio::join!(stdout.read_to_string(&mut out), stderr.read_to_string(&mut err));
        r1?;
        r2?;
        let status = child.wait().await?;
        anyhow::Ok((status, out, err))
    };

    let (status, out, err) = tokio::time::timeout(Duration::from_secs(timeout_secs), work)
        .await
        .map_err(|_| anyhow!("`{binary}` timed out after {timeout_secs}s"))??;

    if !status.success() {
        let tail: String = err.trim().chars().rev().take(500).collect::<Vec<_>>().into_iter().rev().collect();
        bail!("`{binary}` exited with {status}: {tail}");
    }
    Ok(out)
}

/// True if `binary` is an existing file path or is found on `PATH`.
pub fn is_available(binary: &str) -> bool {
    if binary.contains('/') {
        return std::path::Path::new(binary).is_file();
    }
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(binary).is_file()))
        .unwrap_or(false)
}

/// Absolute path of `binary` as found on `PATH`.
pub fn which(binary: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(binary)).find(|p| p.is_file())
}
