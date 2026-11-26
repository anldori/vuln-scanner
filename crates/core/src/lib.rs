//! Core domain model, scanner trait and target/scope validation.

pub mod model;
pub mod scanner;
pub mod target;

pub use model::{compute_priority, CveInfo, Finding, Scan, ScanStatus, Severity};
pub use scanner::{ScanOptions, Scanner};
pub use target::{Scope, Target, TargetError};
