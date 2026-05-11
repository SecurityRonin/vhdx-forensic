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

const H1: usize = 0x0010_0000;
const H2: usize = 0x0014_0000;
const RT1: usize = 0x0020_0000;
const RT2: usize = 0x0024_0000;

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
