//! Compatibility tests against the log2timeline/dfvfs reference VHDX corpus.
//!
//! Download fixtures first:
//!   scripts/fetch-fixtures.sh
//!
//! Tests skip gracefully when fixtures are absent so CI stays green without them.

use std::io::Read;
use vhdx_forensic::{anomalies_at_least, Severity, VhdxIntegrity, VhdxReader};

fn fixture(name: &str) -> Option<Vec<u8>> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    if path.exists() {
        Some(std::fs::read(path).expect("fixture read failed"))
    } else {
        eprintln!("SKIP: fixture '{name}' not present — run scripts/fetch-fixtures.sh");
        None
    }
}

// ── QEMU-generated ext2.vhdx (from dfvfs test corpus) ────────────────────────

#[test]
fn dfvfs_ext2_vhdx_opens() {
    let Some(data) = fixture("ext2.vhdx") else { return };
    VhdxReader::from_bytes(data).expect("QEMU ext2.vhdx must open successfully");
}

#[test]
fn dfvfs_ext2_vhdx_virtual_disk_size_nonzero() {
    let Some(data) = fixture("ext2.vhdx") else { return };
    let reader = VhdxReader::from_bytes(data).expect("must open");
    assert!(reader.virtual_disk_size() > 0, "virtual_disk_size must be > 0");
}

#[test]
fn dfvfs_ext2_vhdx_sector_0_readable() {
    let Some(data) = fixture("ext2.vhdx") else { return };
    let mut reader = VhdxReader::from_bytes(data).expect("must open");
    let mut buf = [0u8; 512];
    reader.read_exact(&mut buf).expect("sector 0 must be readable without error");
}

#[test]
fn dfvfs_ext2_vhdx_no_error_anomalies() {
    let Some(data) = fixture("ext2.vhdx") else { return };
    let issues = VhdxIntegrity::new(&data).analyse();
    let errors = anomalies_at_least(&issues, Severity::Error);
    assert!(
        errors.is_empty(),
        "QEMU ext2.vhdx must have no Error/Critical anomalies, got: {errors:#?}"
    );
}

#[test]
fn dfvfs_ext2_vhdx_integrity_ghost_data_clean() {
    let Some(data) = fixture("ext2.vhdx") else { return };
    let ghost = VhdxIntegrity::new(&data).check_bat_ghost_data();
    assert!(
        ghost.is_empty(),
        "QEMU ext2.vhdx must have no ghost-data anomalies, got: {ghost:#?}"
    );
}

// ── Legacy VHD (ext2.vhd) must be cleanly rejected ───────────────────────────

#[test]
fn dfvfs_ext2_vhd_is_rejected() {
    let Some(data) = fixture("ext2.vhd") else { return };
    assert!(
        VhdxReader::from_bytes(data).is_err(),
        "VHD file must be rejected — it is not a VHDX container"
    );
}
