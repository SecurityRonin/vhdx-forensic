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

const H1: usize = 0x0010_0000; // header 1 offset
const H2: usize = 0x0014_0000; // header 2 offset
const RT1: usize = 0x0020_0000; // region table 1 offset
const RT2: usize = 0x0024_0000; // region table 2 offset

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

// Test 30: LogOffset in reserved zone (below 0x300000)

#[test]
fn log_in_reserved_zone_detected() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // LogOffset=1MB (header zone, well below 0x300000); LogLength=1MB.
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    image[H1 + 72..H1 + 80].copy_from_slice(&0x0010_0000u64.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::LogInReservedZone { log_offset: 0x0010_0000 }
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
            Error,
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
