//! VHDX forensic integrity analyser and in-memory repair tool.
//!
//! Depends on the `vhdx` crate for container parsing. Exports `VhdxIntegrity`,
//! `VhdxRepair`, and all anomaly/severity types.
//!
//! # Layer
//! FORENSIC AUDIT — equivalent role to `ewf-forensic` for E01 images.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod integrity;
pub mod repair;

// Re-export the reader so callers don't need two crates for basic use.
pub use integrity::{AnalysisSummary, Severity, VhdxIntegrity, VhdxIntegrityAnomaly};
pub use vhdx::{header::crc32c, Result, VhdxError, VhdxReader, FILE_MAGIC};

/// Return references to all anomalies whose severity is at or above `min`.
pub fn anomalies_at_least(
    anomalies: &[VhdxIntegrityAnomaly],
    min: Severity,
) -> Vec<&VhdxIntegrityAnomaly> {
    anomalies.iter().filter(|a| a.severity() >= min).collect()
}
pub use repair::{CannotRepair, RepairAction, RepairReport, VhdxRepair};
