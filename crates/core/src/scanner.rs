use crate::{Finding, Target};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub timeout_secs: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { timeout_secs: 900 }
    }
}

/// Plugin interface. Each external tool (nmap, nuclei, vuls, ...) implements this.
#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;

    /// `target` has already been validated and scope-checked by the caller.
    async fn run(&self, target: &Target, opts: &ScanOptions) -> anyhow::Result<Vec<Finding>>;
}
