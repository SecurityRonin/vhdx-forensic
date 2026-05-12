//! RED: integrity detection tests — all must FAIL until GREEN implementation.
//!
//! Each test builds a VHDX image (or crafts a raw buffer) with one specific
//! anomaly injected and asserts that VhdxIntegrity::analyse() detects it.
//!
//! Helper `recompute_header_crc` / `recompute_rt_crc` allow patching a field
//! while keeping the CRC valid — so only ONE anomaly fires per test.

mod builder;

use vhdx_forensic::{crc32c, Severity, VhdxIntegrity, VhdxIntegrityAnomaly};

// ── CRC helper ───────────────────────────────────────────────────────────────

/// Recompute and write the CRC32C for a 4096-byte header block (CRC at offset 4).
fn recompute_header_crc(buf: &mut [u8], header_off: usize) {
    buf[header_off + 4..header_off + 8].fill(0);
    let crc = crc32c(&buf[header_off..header_off + 4096]);
    buf[header_off + 4..header_off + 8].copy_from_slice(&crc.to_le_bytes());
}

/// Recompute and write the CRC32C for a 65536-byte region table block (CRC at offset 4).
fn recompute_rt_crc(buf: &mut [u8], rt_off: usize) {
    buf[rt_off + 4..rt_off + 8].fill(0);
    let mut block = buf[rt_off..rt_off + 65536].to_vec();
    block[4..8].fill(0);
    let crc = crc32c(&block);
    buf[rt_off + 4..rt_off + 8].copy_from_slice(&crc.to_le_bytes());
}

const H1: usize = 0x0001_0000; // header 1 offset (64 KB)
const H2: usize = 0x0002_0000; // header 2 offset (128 KB)
const RT1: usize = 0x0003_0000; // region table 1 offset (192 KB)
const RT2: usize = 0x0004_0000; // region table 2 offset (256 KB)

// ── Test 1: clean image has no anomalies ─────────────────────────────────────

#[test]
fn clean_image_has_no_anomalies() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.is_empty(),
        "clean image should produce zero findings, got: {issues:#?}"
    );
}

// ── Test 2: bad file magic ────────────────────────────────────────────────────

#[test]
fn bad_magic_detected() {
    let mut image = vec![0u8; 0x0025_0000];
    image[0..8].copy_from_slice(b"notvalid");
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::BadMagic { .. })),
        "expected BadMagic, got: {issues:#?}"
    );
}

// ── Test 3: truncated container ───────────────────────────────────────────────

#[test]
fn truncated_container_detected() {
    let image = vec![0u8; 512]; // way too small
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::ContainerTruncated { .. })),
        "expected ContainerTruncated, got: {issues:#?}"
    );
}

// ── Test 4: header 1 CRC mismatch ────────────────────────────────────────────
//
// Flip a byte in header 1's body (NOT the CRC field) → CRC computed from
// the new bytes will disagree with the stored CRC.

#[test]
fn header1_crc_mismatch_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // FileWriteGuid starts at H1+16 — flip one byte there.
    image[H1 + 16] ^= 0xFF;
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::HeaderChecksumMismatch { copy: 1, .. }
        )),
        "expected HeaderChecksumMismatch(copy=1), got: {issues:#?}"
    );
}

// ── Test 5: header 2 CRC mismatch ────────────────────────────────────────────

#[test]
fn header2_crc_mismatch_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    image[H2 + 16] ^= 0xFF;
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::HeaderChecksumMismatch { copy: 2, .. }
        )),
        "expected HeaderChecksumMismatch(copy=2), got: {issues:#?}"
    );
}

// ── Test 6: both headers invalid ─────────────────────────────────────────────

#[test]
fn both_headers_invalid_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    image[H1 + 16] ^= 0xFF; // break H1
    image[H2 + 16] ^= 0xFF; // break H2
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::BothHeaderCopiesInvalid)),
        "expected BothHeaderCopiesInvalid, got: {issues:#?}"
    );
}

// ── Test 7: header copy mismatch (sequence numbers differ in unexpected way) ─

#[test]
fn header_copy_mismatch_detected() {
    // Builder writes seq=1 in H1 and seq=0 in H2.
    // Override H2's sequence to match H1 exactly (seq=1), then the active
    // header (H1, highest seq) and H2 should have the same value — suspicious.
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Patch H2 sequence number to 1 (same as H1), recompute H2 CRC.
    image[H2 + 8..H2 + 16].copy_from_slice(&1u64.to_le_bytes());
    recompute_header_crc(&mut image, H2);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::SequenceNumbersIdentical { .. })),
        "expected SequenceNumbersIdentical, got: {issues:#?}"
    );
}

// ── Test 8: both sequence numbers zero ───────────────────────────────────────

#[test]
fn both_sequence_numbers_zero_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // H2 already has seq=0; patch H1 to seq=0 and recompute its CRC.
    image[H1 + 8..H1 + 16].copy_from_slice(&0u64.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::BothSequenceNumbersZero)),
        "expected BothSequenceNumbersZero, got: {issues:#?}"
    );
}

// ── Test 9: dirty log detected ────────────────────────────────────────────────
//
// LogLength at offset 68 within the header block (u32 LE).

#[test]
fn dirty_log_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Write LogLength = 512 in H1, then recompute H1 CRC.
    image[H1 + 68..H1 + 72].copy_from_slice(&512u32.to_le_bytes());
    image[H1 + 72..H1 + 80].copy_from_slice(&0x0030_0000u64.to_le_bytes()); // LogOffset
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::DirtyLog {
                log_length: 512,
                ..
            }
        )),
        "expected DirtyLog(log_length=512), got: {issues:#?}"
    );
}

// ── Test 10: region table 1 CRC mismatch ─────────────────────────────────────

#[test]
fn region_table1_crc_mismatch_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Flip a non-CRC byte in RT1.
    image[RT1 + 12] ^= 0xFF;
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::RegionTableChecksumMismatch { copy: 1, .. }
        )),
        "expected RegionTableChecksumMismatch(copy=1), got: {issues:#?}"
    );
}

// ── Test 11: region table copy mismatch ──────────────────────────────────────
//
// Patch RT2's BAT file_offset to a different value (re-CRC RT2 so it's
// individually valid) — now RT1 and RT2 disagree on BAT location.

#[test]
fn region_table_copy_mismatch_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // RT1 entry 0 (BAT) file_offset is at RT1 + 16 + 16 = RT1 + 32.
    // Read current value, then write a different one into RT2.
    let rt2_bat_entry_off = RT2 + 32;
    let current = u64::from_le_bytes(
        image[rt2_bat_entry_off..rt2_bat_entry_off + 8]
            .try_into()
            .unwrap(),
    );
    image[rt2_bat_entry_off..rt2_bat_entry_off + 8]
        .copy_from_slice(&(current + 0x0010_0000).to_le_bytes());
    recompute_rt_crc(&mut image, RT2);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::RegionTableCopyMismatch { .. })),
        "expected RegionTableCopyMismatch, got: {issues:#?}"
    );
}

// ── Test 12: metadata BlockSize zero ─────────────────────────────────────────

#[test]
fn metadata_block_size_zero_detected() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_meta_block_size(0)
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::BlockSizeInvalid { block_size: 0, .. }
        )),
        "expected BlockSizeInvalid(0), got: {issues:#?}"
    );
}

// ── Test 13: metadata BlockSize not power-of-two ─────────────────────────────

#[test]
fn metadata_block_size_not_power_of_two_detected() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_meta_block_size(3 * 1024 * 1024) // 3 MB — not a power of two
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::BlockSizeInvalid { .. })),
        "expected BlockSizeInvalid (not power-of-two), got: {issues:#?}"
    );
}

// ── Test 14: metadata LogicalSectorSize invalid ───────────────────────────────

#[test]
fn metadata_sector_size_invalid_detected() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_meta_sector_size(1024) // spec only allows 512 or 4096
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogicalSectorSizeInvalid { sector_size: 1024 }
        )),
        "expected LogicalSectorSizeInvalid(1024), got: {issues:#?}"
    );
}

// ── Test 15: metadata VirtualDiskSize zero ────────────────────────────────────

#[test]
fn metadata_vdisk_size_zero_detected() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_meta_vdisk_size(0)
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::VirtualDiskSizeInvalid { vdisk_size: 0, .. }
        )),
        "expected VirtualDiskSizeInvalid(0), got: {issues:#?}"
    );
}

// ── Test 16: differencing disk detected ──────────────────────────────────────

#[test]
fn differencing_disk_detected() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_has_parent()
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::DifferencingDisk)),
        "expected DifferencingDisk, got: {issues:#?}"
    );
}

// ── Test 17: BAT entry beyond container ──────────────────────────────────────

#[test]
fn bat_entry_beyond_container_detected() {
    // Construct a BAT entry for block 0 with FULLY_PRESENT state but an offset
    // that points 1 TB past the container.
    let file_offset_mb: u64 = 1_000_000; // 1 TB >> container size
    let bat_entry: u64 = (file_offset_mb << 20) | 6; // state=FULLY_PRESENT
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, bat_entry)
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::BatEntryBeyondContainer { bat_index: 0, .. }
        )),
        "expected BatEntryBeyondContainer(index=0), got: {issues:#?}"
    );
}

// ── Test 18: BAT entries overlap ─────────────────────────────────────────────
//
// A 32 MB disk has 1 data block + 1 sector bitmap entry = BAT indices 0 and 1.
// Patch BAT[0] and BAT[1] (the sector bitmap) to the same file offset.
// Actually for a 32 MB disk there's exactly 1 data block at BAT[0] and the
// sector bitmap entry lives at BAT[chunk_ratio] (very high index).
// Instead use a larger disk: 64 MB → 2 data blocks at BAT[0] and BAT[1].
// Give them the same MB offset.

#[test]
fn bat_entries_overlap_detected() {
    // 64 MB disk: 2 × 32 MB blocks → BAT[0] and BAT[1] are both data blocks.
    // Patch both to the same 1 MB-aligned offset so overlap is detected.
    // data_start is ~5MB; offset 4MB is below data_start but within the container.
    let same_mb: u64 = 4;
    let same_entry: u64 = (same_mb << 20) | 6;

    let image = builder::VhdxBuilder::new(64 * 1024 * 1024)
        .with_bat_patch(0, same_entry) // block 0 → 4 MB
        .with_bat_patch(1, same_entry) // block 1 → same 4 MB
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::BatEntriesOverlap { .. })),
        "expected BatEntriesOverlap, got: {issues:#?}"
    );
}

// ── Test 19: trailing data ────────────────────────────────────────────────────

#[test]
fn trailing_data_detected() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_trailing_bytes(4096)
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::TrailingData { .. })),
        "expected TrailingData, got: {issues:#?}"
    );
}

// ── Phase 2 tests ────────────────────────────────────────────────────────────

// Test 21: FileWriteGuid all zeros

#[test]
fn file_write_guid_all_zeros_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Zero out FileWriteGuid in the active header (H1, seq=1).
    image[H1 + 16..H1 + 32].fill(0);
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::FileWriteGuidAllZeros)),
        "expected FileWriteGuidAllZeros, got: {issues:#?}"
    );
}

// Test 22: DataWriteGuid all zeros

#[test]
fn data_write_guid_all_zeros_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Zero out DataWriteGuid in the active header (H1, seq=1).
    image[H1 + 32..H1 + 48].fill(0);
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::DataWriteGuidAllZeros)),
        "expected DataWriteGuidAllZeros, got: {issues:#?}"
    );
}

// Test 23: LogGuid non-zero with no dirty log

#[test]
fn log_guid_with_no_log_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Set a non-zero LogGuid with LogLength=0 (no dirty log).
    image[H1 + 48..H1 + 64].fill(0xAB);
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::LogGuidWithNoLog { .. })),
        "expected LogGuidWithNoLog, got: {issues:#?}"
    );
}

// Test 24: LogGuid all zeros with dirty log

#[test]
fn log_guid_all_zeros_with_dirty_log_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Set 1 MB dirty log at 3 MB; LogGuid stays all-zeros (builder default).
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes()); // LogLength=1MB
    image[H1 + 72..H1 + 80].copy_from_slice(&0x0030_0000u64.to_le_bytes()); // LogOffset=3MB
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogGuidAllZerosWithDirtyLog { log_length: 0x0010_0000 }
        )),
        "expected LogGuidAllZerosWithDirtyLog, got: {issues:#?}"
    );
}

// Test 25: LogVersion invalid

#[test]
fn log_version_invalid_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Set LogVersion = 2 (valid is 1 only).
    image[H1 + 64..H1 + 66].copy_from_slice(&2u16.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogVersionInvalid { version: 2 }
        )),
        "expected LogVersionInvalid(version=2), got: {issues:#?}"
    );
}

// Test 26: Version invalid

#[test]
fn version_invalid_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Set Version = 2 (valid is 1 only).
    image[H1 + 66..H1 + 68].copy_from_slice(&2u16.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::VersionInvalid { version: 2 }
        )),
        "expected VersionInvalid(version=2), got: {issues:#?}"
    );
}

// Test 27: LogOffset not 1 MB aligned

#[test]
fn log_offset_misaligned_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // LogLength=1MB (aligned); LogOffset=0x300001 (misaligned by 1 byte).
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    image[H1 + 72..H1 + 80].copy_from_slice(&0x0030_0001u64.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogOffsetMisaligned { log_offset: 0x0030_0001 }
        )),
        "expected LogOffsetMisaligned, got: {issues:#?}"
    );
}

// Test 28: LogLength not 1 MB aligned

#[test]
fn log_length_misaligned_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // LogLength=512 bytes (not MB-multiple); LogOffset=3MB (aligned).
    image[H1 + 68..H1 + 72].copy_from_slice(&512u32.to_le_bytes());
    image[H1 + 72..H1 + 80].copy_from_slice(&0x0030_0000u64.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogLengthMisaligned { log_length: 512 }
        )),
        "expected LogLengthMisaligned(512), got: {issues:#?}"
    );
}

// Test 29: Log extends past container end

#[test]
fn log_beyond_container_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    let container_size = image.len() as u64;
    // LogOffset=1MB before end; LogLength=2MB → log_end > container.
    let log_offset = container_size - 0x0010_0000;
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0020_0000u32.to_le_bytes()); // 2 MB
    image[H1 + 72..H1 + 80].copy_from_slice(&log_offset.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogBeyondContainer { .. }
        )),
        "expected LogBeyondContainer, got: {issues:#?}"
    );
}

// Test 30: LogOffset in header section (below 1 MB)

#[test]
fn log_in_reserved_zone_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // LogOffset=0 (below 1 MB threshold); LogLength=1 MB.
    // The only 1-MB-aligned offset below 1 MB is 0, which falls in the header section.
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes()); // LogLength
    image[H1 + 72..H1 + 80].copy_from_slice(&0u64.to_le_bytes()); // LogOffset=0
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogInReservedZone { log_offset: 0 }
        )),
        "expected LogInReservedZone, got: {issues:#?}"
    );
}

// Test 31: Sequence number gap > 1 between both valid headers

#[test]
fn sequence_number_gap_large_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // H1=seq=100, H2=seq=0 (default); gap=100 > 1.
    image[H1 + 8..H1 + 16].copy_from_slice(&100u64.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::SequenceNumberGapLarge { gap: 100, .. }
        )),
        "expected SequenceNumberGapLarge(gap=100), got: {issues:#?}"
    );
}

// Test 32: Phase 2 severity levels

#[test]
fn phase2_severity_levels_correct() {
    use Severity::*;
    let checks: &[(VhdxIntegrityAnomaly, Severity)] = &[
        (VhdxIntegrityAnomaly::FileWriteGuidAllZeros, Warning),
        (VhdxIntegrityAnomaly::DataWriteGuidAllZeros, Warning),
        (
            VhdxIntegrityAnomaly::LogGuidWithNoLog {
                log_guid: [0xAB; 16],
            },
            Warning,
        ),
        (
            VhdxIntegrityAnomaly::LogGuidAllZerosWithDirtyLog {
                log_length: 0x0010_0000,
            },
            Warning,
        ),
        (VhdxIntegrityAnomaly::LogVersionInvalid { version: 0 }, Warning),
        (VhdxIntegrityAnomaly::VersionInvalid { version: 2 }, Warning),
        (
            VhdxIntegrityAnomaly::LogOffsetMisaligned { log_offset: 1 },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::LogLengthMisaligned { log_length: 512 },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::LogBeyondContainer {
                log_offset: 0,
                log_length: 1,
                container_size: 0,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::LogInReservedZone {
                log_offset: 0x0010_0000,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::SequenceNumberGapLarge {
                seq1: 100,
                seq2: 0,
                gap: 100,
            },
            Warning,
        ),
    ];
    for (anomaly, expected) in checks {
        assert_eq!(
            &anomaly.severity(),
            expected,
            "severity mismatch for {anomaly:?}"
        );
    }
}

// ── Phase 5 tests ────────────────────────────────────────────────────────────

// Test 47: BAT region size does not match VirtualDiskSize × BlockSize formula

#[test]
fn bat_size_metadata_mismatch_detected() {
    // Build 4 MB disk (BAT = 1 MB from CRC-protected RT).
    // Override VirtualDiskSize to 32 TB → expected BAT ≈ 9 MB → mismatch.
    let vds_32tb: u64 = 32 * (1u64 << 40);
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_meta_vdisk_size(vds_32tb)
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::BatSizeMetadataMismatch { vdisk_size, .. }
            if *vdisk_size == vds_32tb
        )),
        "expected BatSizeMetadataMismatch, got: {issues:#?}"
    );
}

// Test 48: FULLY_PRESENT BAT entry points into Header structural zone

#[test]
fn bat_entry_in_structural_region_detected() {
    // FileOffsetMB=0 → file_offset=0 (File Identifier zone), state=FULLY_PRESENT.
    // BAT entries encode offsets in 1-MB units; offset_mb=0 puts the block at byte 0,
    // covering [0, block_size) which spans all structural zones.
    let bat_entry: u64 = 6; // (0u64 << 20) | 6
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, bat_entry)
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::BatEntryInStructuralRegion {
                bat_index: 0,
                collides_with: "FileIdentifier",
                ..
            }
        )),
        "expected BatEntryInStructuralRegion(FileIdentifier), got: {issues:#?}"
    );
}

// Test 49: FULLY_PRESENT data block but sector bitmap is NOT_PRESENT

#[test]
fn missing_sector_bitmap_detected() {
    // 4 MB disk with sector data → builder writes BAT[0]=FULLY_PRESENT.
    // Sector bitmap is at BAT[chunk_ratio=128]; builder leaves it NOT_PRESENT.
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_sector_data(0, vec![0xBB; 512])
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::MissingSectorBitmap {
                data_bat_index: 0,
                bitmap_bat_index: 128,
            }
        )),
        "expected MissingSectorBitmap(data=0, bitmap=128), got: {issues:#?}"
    );
}

// Test 50: data BAT entry in UNDEFINED state (1)

#[test]
fn undefined_block_state_detected() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, 1u64) // state=1 = UNDEFINED
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::UndefinedBlockState { bat_index: 0 }
        )),
        "expected UndefinedBlockState(index=0), got: {issues:#?}"
    );
}

// Test 51: UNMAPPED state (3) in a non-differencing disk

#[test]
fn unmapped_block_in_non_differencing_detected() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, 3u64) // state=3 = UNMAPPED
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::UnmappedBlockInNonDifferencing { bat_index: 0 }
        )),
        "expected UnmappedBlockInNonDifferencing, got: {issues:#?}"
    );
}

// Test 52: ghost data in NOT_PRESENT BAT entry with non-zero upper bits (opt-in)

#[test]
fn ghost_data_in_absent_block_detected() {
    // Build disk with sector data so bytes exist at the data block location.
    // Then patch BAT[0] to NOT_PRESENT (state=0) while keeping offset bits:
    // data_start for 4 MB disk = 5 MB → offset_mb=5. Ghost entry = 5<<20.
    let ghost_entry: u64 = 5u64 << 20; // NOT_PRESENT (state=0), ghost offset=5MB
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_sector_data(0, vec![0xCC; 512])
        .with_bat_patch(0, ghost_entry)
        .build();
    let issues = VhdxIntegrity::new(&image).check_bat_ghost_data();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::GhostDataInAbsentBlock { bat_index: 0, .. }
        )),
        "expected GhostDataInAbsentBlock(index=0), got: {issues:#?}"
    );
}

// Test 53: Phase 5 severity levels

#[test]
fn phase5_severity_levels_correct() {
    use Severity::*;
    let checks: &[(VhdxIntegrityAnomaly, Severity)] = &[
        (
            VhdxIntegrityAnomaly::BatSizeMetadataMismatch {
                bat_bytes_actual: 0,
                bat_entries_actual: 0,
                bat_entries_expected: 1,
                vdisk_size: 0,
                block_size: 0,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::BatEntryInStructuralRegion {
                bat_index: 0,
                file_offset: 0,
                collides_with: "Header",
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::MissingSectorBitmap {
                data_bat_index: 0,
                bitmap_bat_index: 0,
            },
            Warning,
        ),
        (
            VhdxIntegrityAnomaly::UndefinedBlockState { bat_index: 0 },
            Warning,
        ),
        (
            VhdxIntegrityAnomaly::UnmappedBlockInNonDifferencing { bat_index: 0 },
            Warning,
        ),
        (
            VhdxIntegrityAnomaly::GhostDataInAbsentBlock {
                bat_index: 0,
                file_offset: 0,
                nonzero_bytes: 1,
            },
            Warning,
        ),
    ];
    for (anomaly, expected) in checks {
        assert_eq!(
            &anomaly.severity(),
            expected,
            "severity mismatch for {anomaly:?}"
        );
    }
}

// ── Phase 4 helpers ──────────────────────────────────────────────────────────

/// Write a minimal valid 64-byte log entry at `at` with the given LogGuid and
/// SequenceNumber, computing and storing the CRC32C.
fn write_log_entry(buf: &mut [u8], at: usize, log_guid: [u8; 16], seq: u64) {
    buf[at..at + 64].fill(0);
    buf[at..at + 4].copy_from_slice(b"loge");
    // buf[at+4..at+8] = CRC (written last, currently 0).
    buf[at + 8..at + 12].copy_from_slice(&64u32.to_le_bytes()); // EntryLength = 64
    buf[at + 16..at + 24].copy_from_slice(&seq.to_le_bytes()); // SequenceNumber
    buf[at + 32..at + 48].copy_from_slice(&log_guid); // LogGuid
    let crc = crc32c(&buf[at..at + 64]); // CRC with checksum field = 0
    buf[at + 4..at + 8].copy_from_slice(&crc.to_le_bytes());
}

// Log region for Phase 4 tests: BAT area of a 4 MB sparse image (all zeros).
const LOG_OFFSET: u64 = 0x0040_0000; // 4 MB — BAT area, zero in sparse build
const LOG_GUID: [u8; 16] = [0xAB; 16];

fn setup_dirty_log(image: &mut [u8]) {
    image[H1 + 48..H1 + 64].copy_from_slice(&LOG_GUID); // non-zero LogGuid
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes()); // LogLength=1MB
    image[H1 + 72..H1 + 80].copy_from_slice(&(LOG_OFFSET).to_le_bytes()); // LogOffset=4MB
    recompute_header_crc(image, H1);
}

// ── Phase 4 tests ────────────────────────────────────────────────────────────

// Test 41: log region all zeros with dirty flag

#[test]
fn log_zeroed_but_dirty_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // BAT area at 0x400000 is all zeros; mark as dirty log.
    setup_dirty_log(&mut image);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogZeroedButDirty { .. }
        )),
        "expected LogZeroedButDirty, got: {issues:#?}"
    );
}

// Test 42: log entry does not start with "loge"

#[test]
fn log_entry_signature_missing_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    setup_dirty_log(&mut image);
    // Write non-"loge" bytes at the log start (not all zeros either).
    image[LOG_OFFSET as usize..LOG_OFFSET as usize + 4].copy_from_slice(b"XXXX");
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogEntrySignatureMissing { .. }
        )),
        "expected LogEntrySignatureMissing, got: {issues:#?}"
    );
}

// Test 43: log entry CRC mismatch

#[test]
fn log_entry_crc_mismatch_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    setup_dirty_log(&mut image);
    // Write a valid-signature entry but with a wrong CRC.
    let at = LOG_OFFSET as usize;
    image[at..at + 4].copy_from_slice(b"loge");
    image[at + 4..at + 8].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // wrong CRC
    image[at + 8..at + 12].copy_from_slice(&64u32.to_le_bytes()); // EntryLength
    image[at + 32..at + 48].copy_from_slice(&LOG_GUID);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogEntryCrcMismatch { .. }
        )),
        "expected LogEntryCrcMismatch, got: {issues:#?}"
    );
}

// Test 44: log entry LogGuid does not match active header's LogGuid

#[test]
fn log_entry_guid_mismatch_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    setup_dirty_log(&mut image);
    // Write valid entry but with a different LogGuid.
    let wrong_guid = [0xCD; 16]; // not LOG_GUID
    write_log_entry(&mut image, LOG_OFFSET as usize, wrong_guid, 1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogEntryGuidMismatch { .. }
        )),
        "expected LogEntryGuidMismatch, got: {issues:#?}"
    );
}

// Test 45: gap in log entry sequence numbers

#[test]
fn log_sequence_number_gap_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    setup_dirty_log(&mut image);
    // Entry 0: seq=1, Entry 1: seq=3 (gap — expected seq=2).
    let at = LOG_OFFSET as usize;
    write_log_entry(&mut image, at, LOG_GUID, 1);
    write_log_entry(&mut image, at + 64, LOG_GUID, 3); // gap: skipped seq 2
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogSequenceNumberGap {
                expected_seq: 2,
                found_seq: 3,
                ..
            }
        )),
        "expected LogSequenceNumberGap(expected=2,found=3), got: {issues:#?}"
    );
}

// Test 46: Phase 4 severity levels

#[test]
fn phase4_severity_levels_correct() {
    use Severity::*;
    let checks: &[(VhdxIntegrityAnomaly, Severity)] = &[
        (
            VhdxIntegrityAnomaly::LogZeroedButDirty {
                log_offset: 0,
                log_length: 0,
            },
            Warning,
        ),
        (
            VhdxIntegrityAnomaly::LogEntrySignatureMissing { entry_offset: 0 },
            Warning,
        ),
        (
            VhdxIntegrityAnomaly::LogEntryCrcMismatch {
                entry_offset: 0,
                computed: 0,
                stored: 1,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::LogEntryGuidMismatch {
                entry_offset: 0,
                entry_guid: [0u8; 16],
                header_guid: [1u8; 16],
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::LogSequenceNumberGap {
                at_offset: 0,
                expected_seq: 2,
                found_seq: 5,
            },
            Error,
        ),
    ];
    for (anomaly, expected) in checks {
        assert_eq!(
            &anomaly.severity(),
            expected,
            "severity mismatch for {anomaly:?}"
        );
    }
}

// ── Phase 3 tests ────────────────────────────────────────────────────────────

// Test 33: BAT region file_offset not 1 MB aligned

#[test]
fn region_misaligned_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Patch RT1's BAT offset to a non-1MB-aligned value, re-CRC RT1.
    image[RT1 + 32..RT1 + 40].copy_from_slice(&0x0030_0001u64.to_le_bytes());
    recompute_rt_crc(&mut image, RT1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::RegionMisaligned {
                region: "BAT",
                file_offset: 0x0030_0001
            }
        )),
        "expected RegionMisaligned(BAT), got: {issues:#?}"
    );
}

// Test 34: region declared past end of container

#[test]
fn region_beyond_container_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Patch RT1's BAT offset to 1 GB (MB-aligned, beyond container).
    image[RT1 + 32..RT1 + 40].copy_from_slice(&0x4000_0000u64.to_le_bytes());
    recompute_rt_crc(&mut image, RT1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::RegionBeyondContainer { region: "BAT", .. }
        )),
        "expected RegionBeyondContainer(BAT), got: {issues:#?}"
    );
}

// Test 35: BAT and Metadata regions overlap

#[test]
fn regions_overlap_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Set BAT offset to 0x300000 (same as Metadata) in both RT copies.
    let meta_off: u64 = 0x0030_0000;
    for rt in [RT1, RT2] {
        image[rt + 32..rt + 40].copy_from_slice(&meta_off.to_le_bytes());
        recompute_rt_crc(&mut image, rt);
    }
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::RegionsOverlap { .. })),
        "expected RegionsOverlap, got: {issues:#?}"
    );
}

// Test 36: dirty log overlaps structural region

#[test]
fn log_overlaps_structural_region_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // LogOffset=0 (File Identifier zone), LogLength=1 MB.
    // Structural zones are 0x10000-0x50000; log at offset 0 covers [0, 1MB),
    // overlapping every structural block.
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes()); // LogLength
    image[H1 + 72..H1 + 80].copy_from_slice(&0u64.to_le_bytes()); // LogOffset=0
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogOverlapsStructuralRegion { .. }
        )),
        "expected LogOverlapsStructuralRegion, got: {issues:#?}"
    );
}

// Test 37: unknown required region in RT

#[test]
fn unknown_required_region_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Increment RT1 entry count to 3, add entry 2 with unknown GUID + Required=1.
    image[RT1 + 8..RT1 + 12].copy_from_slice(&3u32.to_le_bytes()); // EntryCount=3
    // Unknown GUID at entry 2 (base = 16 + 2*32 = 80).
    image[RT1 + 80..RT1 + 96].fill(0xDE); // all 0xDE — not BAT or Metadata GUID
    image[RT1 + 96..RT1 + 104].copy_from_slice(&0x0050_0000u64.to_le_bytes()); // file_offset
    image[RT1 + 104..RT1 + 108].copy_from_slice(&0x0010_0000u32.to_le_bytes()); // length
    image[RT1 + 108..RT1 + 112].copy_from_slice(&1u32.to_le_bytes()); // Required=1
    recompute_rt_crc(&mut image, RT1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::UnknownRequiredRegion { .. }
        )),
        "expected UnknownRequiredRegion, got: {issues:#?}"
    );
}

// Test 38: reserved bytes non-zero in RT header

#[test]
fn region_table_reserved_header_nonzero_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Bytes 12-15 of RT1 are reserved; set to 1.
    image[RT1 + 12..RT1 + 16].copy_from_slice(&1u32.to_le_bytes());
    recompute_rt_crc(&mut image, RT1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::RegionTableReservedNonZero {
                copy: 1,
                location: "header",
                value: 1,
            }
        )),
        "expected RegionTableReservedNonZero(header), got: {issues:#?}"
    );
}

// Test 39: reserved bits non-zero in RT entry Required field

#[test]
fn region_table_reserved_entry_nonzero_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // RT1 entry 0 Required field is at offset 16 + 28 = 44 within RT1.
    // Set bit 1 (reserved). Bit 0 (Required) remains 1.
    let curr = u32::from_le_bytes(image[RT1 + 44..RT1 + 48].try_into().unwrap());
    image[RT1 + 44..RT1 + 48].copy_from_slice(&(curr | 0x0000_0002).to_le_bytes());
    recompute_rt_crc(&mut image, RT1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::RegionTableReservedNonZero {
                copy: 1,
                location: "entry",
                ..
            }
        )),
        "expected RegionTableReservedNonZero(entry), got: {issues:#?}"
    );
}

// Test 40: Phase 3 severity levels

#[test]
fn phase3_severity_levels_correct() {
    use Severity::*;
    let checks: &[(VhdxIntegrityAnomaly, Severity)] = &[
        (
            VhdxIntegrityAnomaly::RegionMisaligned {
                region: "BAT",
                file_offset: 1,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::RegionBeyondContainer {
                region: "BAT",
                declared_end: 0,
                container_size: 0,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::RegionsOverlap {
                region_a: "BAT",
                region_b: "Metadata",
                overlap_offset: 0,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::LogOverlapsStructuralRegion {
                log_offset: 0,
                overlapping: "Header",
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::UnknownRequiredRegion {
                guid_hex: String::new(),
            },
            Warning,
        ),
        (
            VhdxIntegrityAnomaly::RegionTableReservedNonZero {
                copy: 1,
                location: "header",
                value: 1,
            },
            Warning,
        ),
    ];
    for (anomaly, expected) in checks {
        assert_eq!(
            &anomaly.severity(),
            expected,
            "severity mismatch for {anomaly:?}"
        );
    }
}

// ── Phase 6 tests — Metadata deep analysis ───────────────────────────────────

// Metadata region layout (from builder.rs):
//   0x300000: metadata table (64 KB)
//   0x310000: item area (64 KB)
//
// Table header: [0..8] sig, [8..10] reserved, [10..12] EntryCount, [12..32] reserved
// Entry 0 (FileParameters): table[32..64]
//   GUID [32..48], Offset [48..52]=0, Length [52..56]=8, Flags [56..60]
// Entry 1 (VirtualDiskSize): table[64..96]
//   GUID [64..80], Offset [80..84]=8, Length [84..88]=8, Flags [88..92]
// Entry 2 (LogicalSectorSize): table[96..128]
//   GUID [96..112], Offset [112..116]=16, Length [116..120]=4, Flags [120..124]
// Entry 3 (added in tests): table[128..160]
// Item area:
//   items_base = 0x310000
//   FileParameters data at [0..8], VDiskSize at [8..16], LogicalSS at [16..20]
//   New item data at [20..] in tests

const META_BASE: usize = 0x0030_0000;
const ITEMS_BASE: usize = META_BASE + 0x10000; // 0x310000

// Test 54: PhysicalSectorSize present with invalid value (1024)

#[test]
fn physical_sector_size_invalid_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();

    // Increment EntryCount from 3 to 4.
    image[META_BASE + 10..META_BASE + 12].copy_from_slice(&4u16.to_le_bytes());

    // Entry 3 at table offset 128 (= 32 + 3*32).
    let e3 = META_BASE + 128;
    // GUID_PHYSICAL_SECTOR_SIZE = {CDA348C7-445D-4471-9CC9-E9885251C556}
    let guid_pss: [u8; 16] = [
        0xC7, 0x48, 0xA3, 0xCD, 0x5D, 0x44, 0x71, 0x44,
        0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56,
    ];
    image[e3..e3 + 16].copy_from_slice(&guid_pss);
    image[e3 + 16..e3 + 20].copy_from_slice(&0x1001_4u32.to_le_bytes()); // item_offset from region start
    image[e3 + 20..e3 + 24].copy_from_slice(&4u32.to_le_bytes());  // item_len=4
    // flags and reserved stay zero

    // Write invalid PhysicalSectorSize value 1024 at items_base + 20.
    image[ITEMS_BASE + 20..ITEMS_BASE + 24].copy_from_slice(&1024u32.to_le_bytes());

    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::PhysicalSectorSizeInvalid { sector_size: 1024 }
        )),
        "expected PhysicalSectorSizeInvalid(1024), got: {issues:#?}"
    );
}

// Test 55: VirtualDiskId present but all zeros

#[test]
fn virtual_disk_id_all_zeros_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();

    image[META_BASE + 10..META_BASE + 12].copy_from_slice(&4u16.to_le_bytes());
    let e3 = META_BASE + 128;
    // GUID_VIRTUAL_DISK_ID = {BECA12AB-B2E6-4523-93EF-C309E000C746}
    let guid_vdi: [u8; 16] = [
        0xAB, 0x12, 0xCA, 0xBE, 0xE6, 0xB2, 0x23, 0x45,
        0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7, 0x46,
    ];
    image[e3..e3 + 16].copy_from_slice(&guid_vdi);
    image[e3 + 16..e3 + 20].copy_from_slice(&0x1001_4u32.to_le_bytes()); // item_offset from region start
    image[e3 + 20..e3 + 24].copy_from_slice(&16u32.to_le_bytes()); // item_len=16
    // 16 bytes at items_base+20 are already zero — VirtualDiskId = [0u8;16]

    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::VirtualDiskIdAllZeros)),
        "expected VirtualDiskIdAllZeros, got: {issues:#?}"
    );
}

// Test 56: two metadata items overlap in the item area

#[test]
fn metadata_items_overlap_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();

    // Patch Entry 1 (VirtualDiskSize) item_offset from 0x10008 to 0x10004.
    // Entry 0 item: [0x10000..0x10008]; Entry 1 item: [0x10004..0x1000C] → overlap at [0x10004..0x10008].
    // Entry 1 Offset field is at table[80..84] = META_BASE + 80.
    image[META_BASE + 80..META_BASE + 84].copy_from_slice(&0x1000_4u32.to_le_bytes());

    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::MetadataItemsOverlap { .. })),
        "expected MetadataItemsOverlap, got: {issues:#?}"
    );
}

// Test 57: a metadata item data range extends past the metadata region end

#[test]
fn metadata_item_beyond_region_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();

    // Patch Entry 0 (FileParameters) Length from 8 to 0x10001.
    // Item end = 0x310000 + 0 + 0x10001 = 0x320001 > region_end 0x320000.
    // Entry 0 Length field is at table[52..56] = META_BASE + 52.
    image[META_BASE + 52..META_BASE + 56].copy_from_slice(&0x0001_0001u32.to_le_bytes());

    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::MetadataItemBeyondRegion { .. })),
        "expected MetadataItemBeyondRegion, got: {issues:#?}"
    );
}

// Test 58: LeaveBlocksAllocated (bit 0 of FileParameters.Flags) set in non-differencing disk

#[test]
fn leave_blocks_allocated_set_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();

    // FileParameters Flags at items_base + 4. Set bit 0.
    image[ITEMS_BASE + 4..ITEMS_BASE + 8].copy_from_slice(&1u32.to_le_bytes());

    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::LeaveBlocksAllocatedSet)),
        "expected LeaveBlocksAllocatedSet, got: {issues:#?}"
    );
}

// Test 59: HasParent=true but no ParentLocator metadata item present

#[test]
fn missing_parent_locator_detected() {
    // Builder sets HasParent=true but never adds a ParentLocator metadata entry.
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_has_parent()
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::MissingParentLocator)),
        "expected MissingParentLocator, got: {issues:#?}"
    );
}

// Test 60: VirtualDiskSize > what the physical BAT can address

#[test]
fn virtual_disk_size_overreported_detected() {
    // 4 MB disk: bat_length=1MB (from RT), block_size=32MB, chunk_ratio=128.
    // max_data_blocks ≈ (131072 * 128) / 129 ≈ 130050 → bat_coverage ≈ 4 TB.
    // Override VDS to 32 TB > 4 TB → VirtualDiskSizeOverreported.
    let vds_32tb: u64 = 32 * (1u64 << 40);
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_meta_vdisk_size(vds_32tb)
        .build();
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::VirtualDiskSizeOverreported { declared, .. }
            if *declared == vds_32tb
        )),
        "expected VirtualDiskSizeOverreported, got: {issues:#?}"
    );
}

// Test 61: Phase 6 severity levels

#[test]
fn phase6_severity_levels_correct() {
    use Severity::*;
    let checks: &[(VhdxIntegrityAnomaly, Severity)] = &[
        (VhdxIntegrityAnomaly::PhysicalSectorSizeInvalid { sector_size: 1024 }, Warning),
        (VhdxIntegrityAnomaly::VirtualDiskIdAllZeros, Warning),
        (
            VhdxIntegrityAnomaly::MetadataItemsOverlap {
                item_a_offset: 0,
                item_b_offset: 4,
                overlap_offset: 4,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::MetadataItemBeyondRegion {
                item_offset: 0,
                item_end: 0x1_0001,
                region_end: 0x1_0000,
            },
            Error,
        ),
        (VhdxIntegrityAnomaly::LeaveBlocksAllocatedSet, Warning),
        (VhdxIntegrityAnomaly::MissingParentLocator, Error),
        (
            VhdxIntegrityAnomaly::VirtualDiskSizeOverreported {
                declared: 32 * (1u64 << 40),
                bat_coverage: 1,
            },
            Error,
        ),
    ];
    for (anomaly, expected) in checks {
        assert_eq!(
            &anomaly.severity(),
            expected,
            "severity mismatch for {anomaly:?}"
        );
    }
}

// ── Phase 7 tests — Container / File Identifier refinements ──────────────────

// File Identifier section: bytes 0..1MB.
//   [0..8]    "vhdxfile" magic
//   [8..512]  creator string (504 bytes, null-padded)
//   [512..65536] reserved (must be zero per MS-VHDX §2.1.2)

// Test 62: non-zero bytes in the reserved area of the File Identifier section

#[test]
fn file_identifier_reserved_nonzero_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Write a non-zero byte at offset 512 (start of reserved area).
    image[512] = 0xFF;
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::FileIdentifierReservedNonZero { .. })),
        "expected FileIdentifierReservedNonZero, got: {issues:#?}"
    );
}

// Test 63: non-zero bytes in the gap between structural regions
// Gap between H1 (4096 bytes at 0x10000) and H2 (at 0x20000): 0x11000..0x20000.

#[test]
fn inter_region_gap_nonzero_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Write a non-zero byte in the gap between Header1 and Header2.
    // H1 occupies bytes [0x10000..0x11000] (4096-byte header in a 64 KB slot).
    // The gap is [0x11000..0x20000].
    image[0x11000] = 0xAB;
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::InterRegionGapNonZero { .. })),
        "expected InterRegionGapNonZero, got: {issues:#?}"
    );
}

// Test 64: non-zero bytes in the reserved portion of a valid header copy
// Header reserved area is bytes [80..4096] within the 4096-byte header block.

#[test]
fn header_reserved_nonzero_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Write non-zero data in H1's reserved area (H1 = 0x10000..0x11000).
    image[H1 + 80..H1 + 84].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    // Recompute H1 CRC so the header remains structurally valid.
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::HeaderReservedNonZero { copy: 1, .. }
        )),
        "expected HeaderReservedNonZero(copy=1), got: {issues:#?}"
    );
}

// Test 65: Phase 7 severity levels

#[test]
fn phase7_severity_levels_correct() {
    use Severity::*;
    let checks: &[(VhdxIntegrityAnomaly, Severity)] = &[
        (
            VhdxIntegrityAnomaly::FileIdentifierReservedNonZero {
                start_offset: 512,
                nonzero_count: 1,
            },
            Warning,
        ),
        (
            VhdxIntegrityAnomaly::InterRegionGapNonZero {
                from_region: "Header1",
                to_region: "Header2",
                gap_offset: 0x101000,
                gap_size: 1,
            },
            Info,
        ),
        (
            VhdxIntegrityAnomaly::HeaderReservedNonZero {
                copy: 1,
                offset_in_header: 80,
                length: 4,
            },
            Warning,
        ),
    ];
    for (anomaly, expected) in checks {
        assert_eq!(
            &anomaly.severity(),
            expected,
            "severity mismatch for {anomaly:?}"
        );
    }
}

// ── Test 20: severity levels are consistent ───────────────────────────────────

#[test]
fn severity_levels_are_sane() {
    use Severity::*;
    let anomalies_with_expected_severity: &[(VhdxIntegrityAnomaly, Severity)] = &[
        (VhdxIntegrityAnomaly::BadMagic { found: [0u8; 8] }, Critical),
        (VhdxIntegrityAnomaly::BothHeaderCopiesInvalid, Critical),
        (
            VhdxIntegrityAnomaly::HeaderChecksumMismatch {
                copy: 1,
                computed: 0,
                stored: 1,
            },
            Error,
        ),
        (
            VhdxIntegrityAnomaly::DirtyLog {
                log_length: 512,
                log_offset: 0,
            },
            Info,
        ),
        (
            VhdxIntegrityAnomaly::TrailingData {
                start_offset: 0,
                size: 100,
            },
            Warning,
        ),
    ];
    for (anomaly, expected) in anomalies_with_expected_severity {
        assert_eq!(
            &anomaly.severity(),
            expected,
            "unexpected severity for {anomaly:?}"
        );
    }
}

// ── Phase 9: robustness / no-panic tests ─────────────────────────────────────

// Test: analyse() must not panic when a region table has a valid CRC but the
// metadata region file_offset is near u64::MAX, causing meta_start + meta_length
// to overflow usize in debug mode.
#[test]
fn analyse_does_not_panic_on_extreme_meta_region_offset() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Entry 1 (Metadata) in RT1: file_offset is at byte RT1+64.
    // Set to 0xFFFF_FFFF_FFFF_0000; keep meta_length at the original 0x20000.
    // Adding: 0xFFFF_FFFF_FFFF_0000 + 0x20000 overflows u64 — causes panic without fix.
    let extreme_offset: u64 = 0xFFFF_FFFF_FFFF_0000;
    image[RT1 + 64..RT1 + 72].copy_from_slice(&extreme_offset.to_le_bytes());
    recompute_rt_crc(&mut image, RT1);
    // Must not panic — saturating arithmetic should handle the extreme offset gracefully.
    let issues = VhdxIntegrity::new(&image).analyse();
    // The extreme offset must appear as an anomaly (beyond the container).
    assert!(
        !issues.is_empty(),
        "expected at least one anomaly from extreme meta offset"
    );
}

// Test: analyse() must not panic when a region table has a valid CRC but the
// BAT region file_offset causes similar extreme-value arithmetic. (Regression
// for the saturating_add fix on the BAT path — already protected, verify stays so.)
#[test]
fn analyse_does_not_panic_on_extreme_bat_region_offset() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Entry 0 (BAT) in RT1: file_offset is at byte RT1+32.
    let extreme_offset: u64 = 0xFFFF_FFFF_FFFF_0000;
    image[RT1 + 32..RT1 + 40].copy_from_slice(&extreme_offset.to_le_bytes());
    recompute_rt_crc(&mut image, RT1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        !issues.is_empty(),
        "expected at least one anomaly from extreme BAT offset"
    );
}

// Test: analyse() must not panic when metadata entry_count is near u16::MAX
// (exercises the min(2048) cap and bounds-check in the metadata table loop).
#[test]
fn analyse_does_not_panic_on_huge_metadata_entry_count() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    const META_BASE: usize = 0x0030_0000;
    // Metadata table entry_count is at META_BASE + 10..12 (u16 LE).
    image[META_BASE + 10..META_BASE + 12].copy_from_slice(&0xFFFFu16.to_le_bytes());
    // No panic is the only requirement.
    let _ = VhdxIntegrity::new(&image).analyse();
}

// Test: analyse() must not panic when block_size = 0 in metadata (chunk_ratio
// falls back to CHUNK_RATIO_INVALID — sentinel that disables bitmap-slot detection).
#[test]
fn analyse_does_not_panic_when_block_size_is_zero() {
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_meta_block_size(0)
        .build();
    let _ = VhdxIntegrity::new(&image).analyse();
}

// Test: analyse() must not panic when a metadata item has item_offset = u32::MAX
// (exercises the checked_add chain that returns None → item skipped).
#[test]
fn analyse_does_not_panic_on_extreme_metadata_item_offset() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    const META_BASE: usize = 0x0030_0000;
    // Entry 0 item_offset field is at META_BASE + 48 (32 table header + 16 GUID).
    image[META_BASE + 48..META_BASE + 52].copy_from_slice(&u32::MAX.to_le_bytes());
    let _ = VhdxIntegrity::new(&image).analyse();
}
