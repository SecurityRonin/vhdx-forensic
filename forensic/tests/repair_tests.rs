//! RED: repair/salvage tests — all must FAIL until GREEN implementation.
//!
//! Each test verifies that VhdxRepair either:
//!   (a) successfully repairs a specific anomaly and produces a usable image, or
//!   (b) reports the anomaly in cannot_repair with an explanatory reason.

mod builder;

use vhdx_forensic::{
    crc32c, RepairReport, VhdxIntegrity, VhdxIntegrityAnomaly, VhdxReader, VhdxRepair,
};

fn recompute_header_crc(buf: &mut [u8], header_off: usize) {
    buf[header_off + 4..header_off + 8].fill(0);
    let c = crc32c(&buf[header_off..header_off + 4096]);
    buf[header_off + 4..header_off + 8].copy_from_slice(&c.to_le_bytes());
}

const H1: usize = 0x0001_0000;
const H2: usize = 0x0002_0000;
const RT1: usize = 0x0003_0000;
const RT2: usize = 0x0004_0000;

// ── Test 1: single bad header CRC is repaired ────────────────────────────────

#[test]
fn repair_single_bad_header1_crc() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    image[H1 + 16] ^= 0xFF; // break H1 CRC
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        !report.repaired.is_empty(),
        "expected at least one repair action for bad header CRC"
    );
    // After repair, integrity check should find no HeaderChecksumMismatch.
    let repaired = repair.into_bytes();
    let issues = VhdxIntegrity::new(&repaired).analyse();
    assert!(
        !issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::HeaderChecksumMismatch { copy: 1, .. }
        )),
        "HeaderChecksumMismatch for copy 1 should be resolved after repair, remaining: {issues:#?}"
    );
}

// ── Test 2: single bad region table CRC is repaired ──────────────────────────

#[test]
fn repair_single_bad_rt1_crc() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    image[RT1 + 12] ^= 0xFF; // break RT1 CRC
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        !report.repaired.is_empty(),
        "expected at least one repair action for bad RT1 CRC"
    );
    let repaired = repair.into_bytes();
    let issues = VhdxIntegrity::new(&repaired).analyse();
    assert!(
        !issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::RegionTableChecksumMismatch { copy: 1, .. }
        )),
        "RegionTableChecksumMismatch(copy=1) should be resolved after repair, remaining: {issues:#?}"
    );
}

// ── Test 3: BAT entry beyond container is zeroed to NOT_PRESENT ──────────────

#[test]
fn repair_bat_entry_beyond_container() {
    let file_offset_mb: u64 = 1_000_000;
    let bad_entry: u64 = (file_offset_mb << 20) | 6;
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, bad_entry)
        .build();
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        !report.repaired.is_empty(),
        "expected repair action for BAT entry beyond container"
    );
    let repaired = repair.into_bytes();
    let issues = VhdxIntegrity::new(&repaired).analyse();
    assert!(
        !issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::BatEntryBeyondContainer { bat_index: 0, .. }
        )),
        "BatEntryBeyondContainer should be resolved after repair, remaining: {issues:#?}"
    );
}

// ── Test 4: both headers invalid → cannot repair ─────────────────────────────

#[test]
fn cannot_repair_both_headers_invalid() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    image[H1 + 16] ^= 0xFF; // break H1
    image[H2 + 16] ^= 0xFF; // break H2
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        report
            .cannot_repair
            .iter()
            .any(|c| matches!(c.anomaly, VhdxIntegrityAnomaly::BothHeaderCopiesInvalid)),
        "BothHeaderCopiesInvalid should appear in cannot_repair, got: {report:#?}"
    );
}

// ── Test 5: repair report always includes the global disclaimer ───────────────

#[test]
fn repair_report_disclaimer_is_non_empty() {
    assert!(
        !RepairReport::DISCLAIMER.is_empty(),
        "global disclaimer must not be empty"
    );
    assert!(
        RepairReport::DISCLAIMER.len() > 50,
        "disclaimer is too short to be meaningful"
    );
}

// ── Test 6: per-action disclaimer is present ─────────────────────────────────

#[test]
fn repair_action_has_disclaimer() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    image[H1 + 16] ^= 0xFF; // break H1
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    for action in &report.repaired {
        assert!(
            !action.disclaimer.is_empty(),
            "every RepairAction must carry a per-action disclaimer: {action:#?}"
        );
    }
}

// ── Test 7: after repair the VhdxReader can open the image ───────────────────

#[test]
fn repaired_image_opens_in_reader() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    image[H1 + 16] ^= 0xFF; // break H1 CRC
                            // Confirm the integrity analyser detects the anomaly.
    let pre_issues = VhdxIntegrity::new(&image).analyse();
    assert!(
        pre_issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::HeaderChecksumMismatch { copy: 1, .. }
        )),
        "corrupt image should have HeaderChecksumMismatch(copy=1)"
    );
    let mut repair = VhdxRepair::new(image);
    repair.attempt_repair();
    let repaired = repair.into_bytes();
    // After repair, no H1 anomaly and image opens successfully.
    let post_issues = VhdxIntegrity::new(&repaired).analyse();
    assert!(
        !post_issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::HeaderChecksumMismatch { copy: 1, .. }
        )),
        "HeaderChecksumMismatch(copy=1) should be resolved after repair"
    );
    assert!(
        VhdxReader::from_bytes(repaired).is_ok(),
        "repaired image should open successfully"
    );
}

// ── Phase 8 helpers ──────────────────────────────────────────────────────────

fn recompute_rt_crc(buf: &mut [u8], rt_off: usize) {
    buf[rt_off + 4..rt_off + 8].fill(0);
    let mut block = buf[rt_off..rt_off + 65536].to_vec();
    block[4..8].fill(0);
    let c = crc32c(&block);
    buf[rt_off + 4..rt_off + 8].copy_from_slice(&c.to_le_bytes());
}

fn write_log_entry(buf: &mut [u8], at: usize, log_guid: [u8; 16], seq: u64) {
    buf[at..at + 64].fill(0);
    buf[at..at + 4].copy_from_slice(b"loge");
    buf[at + 8..at + 12].copy_from_slice(&64u32.to_le_bytes());
    buf[at + 16..at + 24].copy_from_slice(&seq.to_le_bytes());
    buf[at + 32..at + 48].copy_from_slice(&log_guid);
    let c = crc32c(&buf[at..at + 64]);
    buf[at + 4..at + 8].copy_from_slice(&c.to_le_bytes());
}

const LOG_OFFSET: u64 = 0x0040_0000;
const LOG_GUID: [u8; 16] = [0xAB; 16];
const META_BASE: usize = 0x0030_0000;
const ITEMS_BASE: usize = META_BASE + 0x10000;

fn setup_dirty_log(image: &mut [u8]) {
    image[H1 + 48..H1 + 64].copy_from_slice(&LOG_GUID);
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    image[H1 + 72..H1 + 80].copy_from_slice(&LOG_OFFSET.to_le_bytes());
    recompute_header_crc(image, H1);
}

// ── Test 9: BAT entry in structural region is zeroed to NOT_PRESENT ──────────

#[test]
fn repair_bat_entry_in_structural_region() {
    // FileOffsetMB=0 → file_offset=0 (FileIdentifier zone), state=6 (FULLY_PRESENT).
    let bad_entry: u64 = 6;
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, bad_entry)
        .build();
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        !report.repaired.is_empty(),
        "expected repair for BatEntryInStructuralRegion, got: {report:#?}"
    );
    let repaired = repair.into_bytes();
    let issues = VhdxIntegrity::new(&repaired).analyse();
    assert!(
        !issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::BatEntryInStructuralRegion { bat_index: 0, .. }
        )),
        "BatEntryInStructuralRegion(0) should be resolved after repair, remaining: {issues:#?}"
    );
}

// ── Test 10: UNDEFINED block state is zeroed to NOT_PRESENT ──────────────────

#[test]
fn repair_undefined_block_state() {
    // state=1 (UNDEFINED), no file offset.
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, 1u64)
        .build();
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        !report.repaired.is_empty(),
        "expected repair for UndefinedBlockState, got: {report:#?}"
    );
    let repaired = repair.into_bytes();
    let issues = VhdxIntegrity::new(&repaired).analyse();
    assert!(
        !issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::UndefinedBlockState { bat_index: 0 }
        )),
        "UndefinedBlockState(0) should be resolved after repair, remaining: {issues:#?}"
    );
}

// ── Test 11: reserved bits cleared, offset and state preserved ────────────────

#[test]
fn repair_bat_entry_unaligned_reserved_bits() {
    // offset_mb=4 (→ 0x400000 = BAT region, within container), state=6, bits[3..19]=all-ones.
    let raw: u64 = (4u64 << 20) | (0x1FFFFu64 << 3) | 6;
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, raw)
        .build();
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        !report.repaired.is_empty(),
        "expected repair for BatEntryUnaligned, got: {report:#?}"
    );
    let repaired = repair.into_bytes();
    let issues = VhdxIntegrity::new(&repaired).analyse();
    assert!(
        !issues.iter().any(|a| matches!(
            a,
            VhdxIntegrityAnomaly::BatEntryUnaligned { bat_index: 0, .. }
        )),
        "BatEntryUnaligned(0) should be resolved after repair, remaining: {issues:#?}"
    );
    // Verify offset and state are preserved.
    let bat_base = VhdxIntegrity::new(&repaired).bat_region_offset().unwrap() as usize;
    let entry = u64::from_le_bytes(repaired[bat_base..bat_base + 8].try_into().unwrap());
    assert_eq!(entry & 0x7, 6, "state must still be FULLY_PRESENT (6)");
    assert_eq!(entry >> 20, 4, "offset_mb must be preserved (4)");
    assert_eq!(entry & 0x000F_FFF8, 0, "reserved bits must be cleared");
}

// ── Test 12: BatSizeMetadataMismatch → cannot_repair with "which field" ───────

#[test]
fn cannot_repair_bat_size_metadata_mismatch() {
    // Override VDS to 4 TiB while BAT was built for 4 MB → expected BAT >> actual BAT.
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_meta_vdisk_size(4u64 * 1024 * 1024 * 1024 * 1024)
        .build();
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        report
            .cannot_repair
            .iter()
            .any(|c| matches!(c.anomaly, VhdxIntegrityAnomaly::BatSizeMetadataMismatch { .. })),
        "BatSizeMetadataMismatch should appear in cannot_repair, got: {report:#?}"
    );
    for c in &report.cannot_repair {
        if matches!(c.anomaly, VhdxIntegrityAnomaly::BatSizeMetadataMismatch { .. }) {
            assert!(
                c.reason.contains("which field"),
                "reason must mention 'which field', got: {:?}",
                c.reason
            );
        }
    }
}

// ── Test 13: LogEntryGuidMismatch → cannot_repair with "transplanted" ─────────

#[test]
fn cannot_repair_log_entry_guid_mismatch() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Set H1 LogGuid = LOG_GUID, LogLength = 1 MB, LogOffset = 0x400000.
    image[H1 + 48..H1 + 64].copy_from_slice(&LOG_GUID);
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    image[H1 + 72..H1 + 80].copy_from_slice(&LOG_OFFSET.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    // Write a log entry with a DIFFERENT guid — mismatches the header LogGuid.
    let wrong_guid = [0xCCu8; 16];
    write_log_entry(&mut image, LOG_OFFSET as usize, wrong_guid, 1);
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        report
            .cannot_repair
            .iter()
            .any(|c| matches!(c.anomaly, VhdxIntegrityAnomaly::LogEntryGuidMismatch { .. })),
        "LogEntryGuidMismatch should appear in cannot_repair, got: {report:#?}"
    );
    for c in &report.cannot_repair {
        if matches!(c.anomaly, VhdxIntegrityAnomaly::LogEntryGuidMismatch { .. }) {
            assert!(
                c.reason.contains("transplanted"),
                "reason must mention 'transplanted', got: {:?}",
                c.reason
            );
        }
    }
}

// ── Test 14: GhostDataInAbsentBlock → cannot_repair (attempt_repair calls ghost check) ──

#[test]
fn cannot_repair_ghost_data_in_absent_block() {
    // BAT[0] state=0 (NOT_PRESENT) but upper bits encode offset_mb=4 → ghost at 0x400000.
    // Bytes at 0x400000 (the BAT itself) are non-zero, triggering ghost-data detection.
    let image = builder::VhdxBuilder::new(4 * 1024 * 1024)
        .with_bat_patch(0, 4u64 << 20) // state=0, offset_mb=4
        .build();
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        report
            .cannot_repair
            .iter()
            .any(|c| matches!(c.anomaly, VhdxIntegrityAnomaly::GhostDataInAbsentBlock { bat_index: 0, .. })),
        "GhostDataInAbsentBlock(0) should appear in cannot_repair — attempt_repair must call check_bat_ghost_data(), got: {report:#?}"
    );
    for c in &report.cannot_repair {
        if matches!(c.anomaly, VhdxIntegrityAnomaly::GhostDataInAbsentBlock { .. }) {
            assert!(
                c.reason.contains("evidence"),
                "reason must mention 'evidence', got: {:?}",
                c.reason
            );
        }
    }
}

// ── Test 15: MetadataItemsOverlap → cannot_repair with "ambiguous" ────────────

#[test]
fn cannot_repair_metadata_items_overlap() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // Entry 1 item_offset is at META_BASE+80; change from 0x10008 → 0x10004 to overlap Entry 0's [0x10000,0x10008).
    image[META_BASE + 80..META_BASE + 84].copy_from_slice(&0x1000_4u32.to_le_bytes());
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        report
            .cannot_repair
            .iter()
            .any(|c| matches!(c.anomaly, VhdxIntegrityAnomaly::MetadataItemsOverlap { .. })),
        "MetadataItemsOverlap should appear in cannot_repair, got: {report:#?}"
    );
    for c in &report.cannot_repair {
        if matches!(c.anomaly, VhdxIntegrityAnomaly::MetadataItemsOverlap { .. }) {
            assert!(
                c.reason.contains("ambiguous"),
                "reason must mention 'ambiguous', got: {:?}",
                c.reason
            );
        }
    }
}

// ── Test 16: LogGuidAllZerosWithDirtyLog → cannot_repair "contradictory" ──────

#[test]
fn cannot_repair_log_guid_all_zeros_with_dirty_log() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    // LogGuid remains all-zeros (default); set LogLength=1MB, LogOffset=0x400000.
    image[H1 + 68..H1 + 72].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    image[H1 + 72..H1 + 80].copy_from_slice(&0x0040_0000u64.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    assert!(
        report
            .cannot_repair
            .iter()
            .any(|c| matches!(c.anomaly, VhdxIntegrityAnomaly::LogGuidAllZerosWithDirtyLog { .. })),
        "LogGuidAllZerosWithDirtyLog should appear in cannot_repair, got: {report:#?}"
    );
    for c in &report.cannot_repair {
        if matches!(c.anomaly, VhdxIntegrityAnomaly::LogGuidAllZerosWithDirtyLog { .. }) {
            assert!(
                c.reason.contains("contradictory"),
                "reason must mention 'contradictory', got: {:?}",
                c.reason
            );
        }
    }
}

// ── Test 8: dirty log is reported as cannot_repair with explanation ───────────

#[test]
fn dirty_log_cannot_repair_because_replay_out_of_scope() {
    let mut image = builder::VhdxBuilder::new(4 * 1024 * 1024).build();
    image[H1 + 68..H1 + 72].copy_from_slice(&512u32.to_le_bytes()); // LogLength = 512
    image[H1 + 72..H1 + 80].copy_from_slice(&0x0030_0000u64.to_le_bytes());
    recompute_header_crc(&mut image, H1);
    let mut repair = VhdxRepair::new(image);
    let report = repair.attempt_repair();
    // DirtyLog should be listed as cannot_repair (log replay is out of scope).
    assert!(
        report
            .cannot_repair
            .iter()
            .any(|c| matches!(c.anomaly, VhdxIntegrityAnomaly::DirtyLog { .. })),
        "DirtyLog should appear in cannot_repair, got: {report:#?}"
    );
    // The reason should be non-empty.
    for c in &report.cannot_repair {
        if matches!(c.anomaly, VhdxIntegrityAnomaly::DirtyLog { .. }) {
            assert!(
                !c.reason.is_empty(),
                "cannot_repair reason must not be empty"
            );
        }
    }
}
