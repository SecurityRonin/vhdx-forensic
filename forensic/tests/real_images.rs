#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Ground-truth validation: zero false positives on real VHDX images,
//! and detection capability via injection into known-good real images.
//!
//! Zero-FP tests prove our analyser does not flag valid structure as anomalous.
//! Field-value tests cross-validate our parser against an independent tool
//! (qemu-img) — if we agree on VirtualDiskSize, our metadata parsing is correct.
//! Injection tests prove our analyser detects specific corruptions in real images
//! (not just in builder-generated ones, eliminating shared-blind-spot risk).
//!
//! Injection offsets follow MS-VHDX §2.0 (all are spec-mandated, not parser-derived):
//!   File identifier:  bytes [0x0000_0000..0x0000_0200]  magic "vhdxfile" at [0..8]
//!   Header 1:         bytes [0x0001_0000..0x0002_0000]  CRC at [0x1_0004..0x1_0008]
//!   Header 2:         bytes [0x0002_0000..0x0003_0000]
//!   Region table 1:   bytes [0x0003_0000..0x0004_0000]  signature "regi" at [0x3_0000..0x3_0004]
//!   Region table 2:   bytes [0x0004_0000..0x0005_0000]
//!
//! See tests/data/SOURCES.md for image provenance, checksums, and tool versions.

use vhdx_forensic::{anomalies_at_least, Severity, VhdxIntegrity, VhdxIntegrityAnomaly, VhdxReader};

fn data(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("test data missing: {}", path.display()))
}

// ── QEMU 11.0.0 — dynamic, empty (no filesystem written) ─────────────────────

#[test]
fn qemu_empty_dynamic_opens() {
    VhdxReader::from_bytes(data("qemu_empty_dynamic.vhdx"))
        .expect("qemu_empty_dynamic.vhdx must open successfully");
}

#[test]
fn qemu_empty_dynamic_virtual_disk_size() {
    let reader = VhdxReader::from_bytes(data("qemu_empty_dynamic.vhdx")).expect("must open");
    // Cross-validated with: qemu-img info qemu_empty_dynamic.vhdx → virtual size: 16 MiB
    assert_eq!(reader.virtual_disk_size(), 16 * 1024 * 1024, "virtual_disk_size must be 16 MiB");
}

#[test]
fn qemu_empty_dynamic_no_error_anomalies() {
    let issues = VhdxIntegrity::new(&data("qemu_empty_dynamic.vhdx")).analyse();
    let errors = anomalies_at_least(&issues, Severity::High);
    assert!(
        errors.is_empty(),
        "qemu_empty_dynamic.vhdx must have no Error/Critical anomalies, got: {errors:#?}"
    );
}

// ── QEMU 11.0.0 — fixed provisioning (all blocks preallocated) ───────────────

#[test]
fn qemu_fixed_opens() {
    VhdxReader::from_bytes(data("qemu_fixed.vhdx"))
        .expect("qemu_fixed.vhdx must open successfully");
}

#[test]
fn qemu_fixed_virtual_disk_size() {
    let reader = VhdxReader::from_bytes(data("qemu_fixed.vhdx")).expect("must open");
    // Cross-validated with: qemu-img create -o subformat=fixed ... 8M → size=8388608
    assert_eq!(reader.virtual_disk_size(), 8 * 1024 * 1024, "virtual_disk_size must be 8 MiB");
}

#[test]
fn qemu_fixed_no_error_anomalies() {
    let issues = VhdxIntegrity::new(&data("qemu_fixed.vhdx")).analyse();
    let errors = anomalies_at_least(&issues, Severity::High);
    assert!(
        errors.is_empty(),
        "qemu_fixed.vhdx must have no Error/Critical anomalies, got: {errors:#?}"
    );
}

// ── Detection capability: injection into real images ─────────────────────────
//
// These tests use a QEMU-generated image as the base — NOT a builder-generated
// one — so the test setup is independent of our code. The spec-mandated byte
// offsets are used directly (no parser involvement), then we verify that our
// analyser detects the injected corruption.

#[test]
fn detect_bad_magic_in_real_image() {
    let mut image = data("qemu_empty_dynamic.vhdx");
    // Overwrite the 8-byte file identifier ("vhdxfile\0\0\0\0\0\0\0\0" at bytes 0..8)
    image[0..8].fill(0xFF);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(a, VhdxIntegrityAnomaly::BadMagic { .. })),
        "BadMagic must be detected after corrupting file magic bytes [0..8]"
    );
}

#[test]
fn detect_header_crc_mismatch_in_real_image() {
    let mut image = data("qemu_empty_dynamic.vhdx");
    // Flip a bit in header 1 payload at offset 0x1_0010 (past the CRC field at 0x1_0004..0x1_0008),
    // making the stored CRC inconsistent with the modified content.
    image[0x0001_0010] ^= 0x01;
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(a, VhdxIntegrityAnomaly::HeaderChecksumMismatch { .. })),
        "HeaderChecksumMismatch must be detected after corrupting header 1 payload"
    );
}

#[test]
fn detect_region_table_crc_mismatch_in_real_image() {
    let mut image = data("qemu_empty_dynamic.vhdx");
    // Overwrite the region table 1 "regi" signature at bytes [0x3_0000..0x3_0004].
    // The CRC covers the entire 65 536-byte region table block, so replacing the
    // signature bytes causes RegionTableChecksumMismatch for copy 1.
    image[0x0003_0000..0x0003_0004].fill(0xFF);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(a, VhdxIntegrityAnomaly::RegionTableChecksumMismatch { .. }
            | VhdxIntegrityAnomaly::BothRegionTableCopiesInvalid)),
        "Region table corruption must be detected after overwriting the 'regi' signature"
    );
}

#[test]
fn detect_container_truncated_in_real_image() {
    let image = data("qemu_empty_dynamic.vhdx");
    // Truncate to 256 KiB — below the 320 KiB minimum structural size (5 × 64 KiB blocks).
    let truncated = &image[..256 * 1024];
    let issues = VhdxIntegrity::new(truncated).analyse();
    assert!(
        issues.iter().any(|a| matches!(a, VhdxIntegrityAnomaly::ContainerTruncated { .. })),
        "ContainerTruncated must be detected when file is smaller than 320 KiB"
    );
}
