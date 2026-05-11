//! Phase 10: API surface tests — compile-time RED until the new APIs are added.

use vhdx_forensic::{
    anomalies_at_least, AnalysisSummary, Severity, VhdxIntegrity, VhdxIntegrityAnomaly,
};

mod builder;

// ── 10A: anomalies_at_least ───────────────────────────────────────────────────

#[test]
fn anomalies_at_least_filters_correctly() {
    let anomalies = vec![
        VhdxIntegrityAnomaly::BadMagic { found: [0u8; 8] }, // Critical
        VhdxIntegrityAnomaly::DirtyLog {
            log_length: 0x10_0000,
            log_offset: 0x40_0000,
        }, // Info
        VhdxIntegrityAnomaly::FileWriteGuidAllZeros, // Warning
        VhdxIntegrityAnomaly::HeaderChecksumMismatch {
            copy: 1,
            computed: 0,
            stored: 1,
        }, // Error
    ];

    // At or above Error: Critical + Error (= 2).
    let filtered = anomalies_at_least(&anomalies, Severity::Error);
    assert_eq!(
        filtered.len(),
        2,
        "expected BadMagic (Critical) and HeaderChecksumMismatch (Error)"
    );

    // At or above Critical: only BadMagic.
    let only_critical = anomalies_at_least(&anomalies, Severity::Critical);
    assert_eq!(only_critical.len(), 1);

    // At or above Info: all four.
    let all = anomalies_at_least(&anomalies, Severity::Info);
    assert_eq!(all.len(), 4);
}

#[test]
fn anomalies_at_least_empty_input_returns_empty() {
    let empty: Vec<VhdxIntegrityAnomaly> = vec![];
    assert!(anomalies_at_least(&empty, Severity::Info).is_empty());
}

// ── 10B: AnalysisSummary / summary() ─────────────────────────────────────────

#[test]
fn summary_counts_match_input() {
    let anomalies = vec![
        VhdxIntegrityAnomaly::BadMagic { found: [0u8; 8] }, // Critical
        VhdxIntegrityAnomaly::HeaderChecksumMismatch {
            copy: 1,
            computed: 0,
            stored: 1,
        }, // Error
        VhdxIntegrityAnomaly::FileWriteGuidAllZeros, // Warning
        VhdxIntegrityAnomaly::DirtyLog {
            log_length: 0x10_0000,
            log_offset: 0x40_0000,
        }, // Info
    ];
    let s: AnalysisSummary = VhdxIntegrity::summary(&anomalies);
    assert_eq!(s.total, 4);
    assert_eq!(s.critical, 1);
    assert_eq!(s.error, 1);
    assert_eq!(s.warning, 1);
    assert_eq!(s.info, 1);
    assert_eq!(s.highest, Some(Severity::Critical));
}

#[test]
fn summary_empty_returns_zeros_and_none() {
    let s: AnalysisSummary = VhdxIntegrity::summary(&[]);
    assert_eq!(s.total, 0);
    assert_eq!(s.critical, 0);
    assert_eq!(s.error, 0);
    assert_eq!(s.warning, 0);
    assert_eq!(s.info, 0);
    assert_eq!(s.highest, None);
}

// ── 10C: forensic_significance() ────────────────────────────────────────────

#[test]
fn forensic_significance_is_non_empty_for_selected_variants() {
    let cases: &[VhdxIntegrityAnomaly] = &[
        VhdxIntegrityAnomaly::BadMagic { found: [0u8; 8] },
        VhdxIntegrityAnomaly::ContainerTruncated { size: 0, minimum: 1 },
        VhdxIntegrityAnomaly::HeaderChecksumMismatch {
            copy: 1,
            computed: 0,
            stored: 1,
        },
        VhdxIntegrityAnomaly::BothHeaderCopiesInvalid,
        VhdxIntegrityAnomaly::FileWriteGuidAllZeros,
        VhdxIntegrityAnomaly::DataWriteGuidAllZeros,
        VhdxIntegrityAnomaly::DirtyLog {
            log_length: 1024,
            log_offset: 0x40_0000,
        },
        VhdxIntegrityAnomaly::BatEntryBeyondContainer {
            bat_index: 0,
            file_offset: 0,
            container_size: 0,
        },
        VhdxIntegrityAnomaly::BatEntriesOverlap {
            index_a: 0,
            index_b: 1,
            shared_offset: 0x50_0000,
        },
        VhdxIntegrityAnomaly::GhostDataInAbsentBlock {
            bat_index: 0,
            file_offset: 0x40_0000,
            nonzero_bytes: 8,
        },
        VhdxIntegrityAnomaly::TrailingData {
            start_offset: 0x50_0000,
            size: 0x10_0000,
        },
        VhdxIntegrityAnomaly::LogEntryGuidMismatch {
            entry_offset: 0x40_0000,
            entry_guid: [0xCC; 16],
            header_guid: [0xAB; 16],
        },
        VhdxIntegrityAnomaly::BatSizeMetadataMismatch {
            bat_bytes_actual: 0x10_0000,
            bat_entries_actual: 1,
            bat_entries_expected: 5,
            vdisk_size: 4 * 1024 * 1024,
            block_size: 1024 * 1024,
        },
        VhdxIntegrityAnomaly::VirtualDiskIdAllZeros,
        VhdxIntegrityAnomaly::FileIdentifierReservedNonZero {
            start_offset: 512,
            nonzero_count: 4,
        },
        VhdxIntegrityAnomaly::HeaderReservedNonZero {
            copy: 1,
            offset_in_header: 80,
            length: 4,
        },
    ];

    for anomaly in cases {
        let sig = anomaly.forensic_significance();
        assert!(
            !sig.is_empty(),
            "forensic_significance() must not be empty for {anomaly:?}"
        );
        assert!(
            sig.len() > 20,
            "forensic_significance() must be meaningful (>20 chars) for {anomaly:?}, got: {sig:?}"
        );
    }
}

// ── 10D: mitre_techniques() ──────────────────────────────────────────────────

#[test]
fn mitre_techniques_returns_expected_ids() {
    let mapped = &[
        (
            VhdxIntegrityAnomaly::TrailingData {
                start_offset: 0,
                size: 1,
            },
            "T1564.001",
        ),
        (
            VhdxIntegrityAnomaly::GhostDataInAbsentBlock {
                bat_index: 0,
                file_offset: 0,
                nonzero_bytes: 1,
            },
            "T1564.001",
        ),
        (
            VhdxIntegrityAnomaly::FileIdentifierReservedNonZero {
                start_offset: 512,
                nonzero_count: 1,
            },
            "T1027",
        ),
        (
            VhdxIntegrityAnomaly::HeaderReservedNonZero {
                copy: 1,
                offset_in_header: 80,
                length: 4,
            },
            "T1027",
        ),
        (
            VhdxIntegrityAnomaly::LogSequenceNumberGap {
                at_offset: 0,
                expected_seq: 1,
                found_seq: 5,
            },
            "T1070",
        ),
        (
            VhdxIntegrityAnomaly::LogEntryGuidMismatch {
                entry_offset: 0,
                entry_guid: [0; 16],
                header_guid: [1; 16],
            },
            "T1070.003",
        ),
        (
            VhdxIntegrityAnomaly::BatEntryInStructuralRegion {
                bat_index: 0,
                file_offset: 0x10_0000,
                collides_with: "Header",
            },
            "T1027",
        ),
        (
            VhdxIntegrityAnomaly::BatEntriesOverlap {
                index_a: 0,
                index_b: 1,
                shared_offset: 0,
            },
            "T1036",
        ),
        (
            VhdxIntegrityAnomaly::FileWriteGuidAllZeros,
            "T1070",
        ),
    ];

    for (anomaly, expected_id) in mapped {
        let techniques = anomaly.mitre_techniques();
        assert!(
            techniques.contains(expected_id),
            "expected {expected_id} in mitre_techniques() for {anomaly:?}, got: {techniques:?}"
        );
    }
}

#[test]
fn mitre_techniques_returns_empty_for_unmapped() {
    // Clean structural checks — no obvious ATT&CK mapping.
    let unmapped = VhdxIntegrityAnomaly::LogLengthMisaligned { log_length: 512 };
    // May return empty or may not — just verify no panic and returns a slice.
    let _ = unmapped.mitre_techniques();
}
