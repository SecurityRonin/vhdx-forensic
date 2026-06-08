#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Compatibility tests against the log2timeline/dfvfs reference VHDX corpus.
//!
//! These images were created by the dfvfs toolchain — NOT by vhdx-forensic.
//! That satisfies the doer-checker principle: an independent tool created the
//! data; we verify our analyser handles it without false positives or panics.
//!
//! See tests/data/SOURCES.md for provenance, source URLs, and checksums.

use std::io::Read;
use vhdx_forensic::{anomalies_at_least, Severity, VhdxIntegrity, VhdxReader};

fn data(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("test data missing: {}", path.display()))
}

// ── ext2.vhdx — QEMU v5.2-generated, ext2 filesystem, 512-byte sectors ───────

#[test]
fn dfvfs_ext2_vhdx_opens() {
    VhdxReader::from_bytes(data("ext2.vhdx")).expect("QEMU ext2.vhdx must open successfully");
}

#[test]
fn dfvfs_ext2_vhdx_virtual_disk_size() {
    let reader = VhdxReader::from_bytes(data("ext2.vhdx")).expect("must open");
    // Cross-validated with: qemu-img info ext2.vhdx → virtual size: 4 MiB (4194304 bytes)
    assert_eq!(
        reader.virtual_disk_size(),
        4 * 1024 * 1024,
        "virtual_disk_size must be 4 MiB"
    );
}

#[test]
fn dfvfs_ext2_vhdx_sector_0_readable() {
    let mut reader = VhdxReader::from_bytes(data("ext2.vhdx")).expect("must open");
    let mut buf = [0u8; 512];
    reader
        .read_exact(&mut buf)
        .expect("sector 0 must be readable without error");
}

#[test]
fn dfvfs_ext2_vhdx_no_error_anomalies() {
    let issues = VhdxIntegrity::new(&data("ext2.vhdx")).analyse();
    let errors = anomalies_at_least(&issues, Severity::High);
    assert!(
        errors.is_empty(),
        "QEMU ext2.vhdx must have no Error/Critical anomalies, got: {errors:#?}"
    );
}

#[test]
fn dfvfs_ext2_vhdx_ghost_data_clean() {
    let ghost = VhdxIntegrity::new(&data("ext2.vhdx")).check_bat_ghost_data();
    assert!(
        ghost.is_empty(),
        "QEMU ext2.vhdx must have no ghost-data anomalies, got: {ghost:#?}"
    );
}

// ── fat-parent.vhdx — FAT filesystem, standalone parent disk ──────────────────

#[test]
fn dfvfs_fat_parent_vhdx_opens() {
    VhdxReader::from_bytes(data("fat-parent.vhdx"))
        .expect("fat-parent.vhdx must open successfully");
}

#[test]
fn dfvfs_fat_parent_vhdx_virtual_disk_size() {
    let reader = VhdxReader::from_bytes(data("fat-parent.vhdx")).expect("must open");
    // Cross-validated with: qemu-img info fat-parent.vhdx → virtual size: 4 MiB (4194304 bytes)
    assert_eq!(
        reader.virtual_disk_size(),
        4 * 1024 * 1024,
        "virtual_disk_size must be 4 MiB"
    );
}

#[test]
fn dfvfs_fat_parent_vhdx_sector_0_readable() {
    let mut reader = VhdxReader::from_bytes(data("fat-parent.vhdx")).expect("must open");
    let mut buf = [0u8; 512];
    reader
        .read_exact(&mut buf)
        .expect("sector 0 must be readable without error");
}

#[test]
fn dfvfs_fat_parent_vhdx_no_error_anomalies() {
    let issues = VhdxIntegrity::new(&data("fat-parent.vhdx")).analyse();
    let errors = anomalies_at_least(&issues, Severity::High);
    assert!(
        errors.is_empty(),
        "fat-parent.vhdx must have no Error/Critical anomalies, got: {errors:#?}"
    );
}

// ── fat-differential.vhdx — differencing disk that references fat-parent.vhdx ─
//
// VhdxReader refuses differencing disks (DifferencingNotSupported) — correct,
// because logical reads require the parent chain which is not available locally.
// VhdxIntegrity works on raw bytes and can still analyse structural integrity.
// Differencing disks emit DifferencingDisk (Warning) — expected and correct.
// The test asserts no ERROR-or-above findings, not zero total findings.

#[test]
fn dfvfs_fat_differential_vhdx_reader_refuses_without_parent() {
    let result = VhdxReader::from_bytes(data("fat-differential.vhdx"));
    assert!(
        result.is_err(),
        "VhdxReader must refuse a differencing disk — logical reads require the parent chain"
    );
}

#[test]
fn dfvfs_fat_differential_vhdx_no_error_anomalies() {
    let issues = VhdxIntegrity::new(&data("fat-differential.vhdx")).analyse();
    let errors = anomalies_at_least(&issues, Severity::High);
    assert!(
        errors.is_empty(),
        "fat-differential.vhdx must have no Error/Critical anomalies, got: {errors:#?}"
    );
}

#[test]
fn dfvfs_fat_differential_vhdx_emits_differencing_disk_warning() {
    use vhdx_forensic::VhdxIntegrityAnomaly;
    let issues = VhdxIntegrity::new(&data("fat-differential.vhdx")).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::DifferencingDisk)),
        "fat-differential.vhdx must be identified as a differencing disk"
    );
}

// ── ext2.vhd — legacy VHD format must be rejected (not VHDX) ─────────────────

#[test]
fn dfvfs_ext2_vhd_is_rejected() {
    assert!(
        VhdxReader::from_bytes(data("ext2.vhd")).is_err(),
        "VHD file must be rejected — it is not a VHDX container"
    );
}
