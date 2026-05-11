use crate::header::{
    crc32c, HEADER1_OFFSET, HEADER2_OFFSET, HEADER_SIZE, REGION_TABLE1_OFFSET, REGION_TABLE2_OFFSET,
};
use crate::integrity::{VhdxIntegrity, VhdxIntegrityAnomaly};

const REGION_TABLE_CRC_COVERAGE: usize = 65536;

/// A single repair action that was successfully applied to the image.
#[derive(Debug, Clone)]
pub struct RepairAction {
    /// Human-readable description of what was changed.
    pub description: String,
    /// Byte offset in the image where the repair was applied.
    pub byte_offset: u64,
    /// Number of bytes modified.
    pub bytes_changed: usize,
    /// Per-action caveat about forensic implications.
    pub disclaimer: &'static str,
}

/// A finding that could not be automatically repaired.
#[derive(Debug, Clone)]
pub struct CannotRepair {
    /// The anomaly that was not repaired.
    pub anomaly: VhdxIntegrityAnomaly,
    /// Reason this anomaly cannot be automatically resolved.
    pub reason: &'static str,
}

/// Summary of a repair attempt.
#[derive(Debug)]
pub struct RepairReport {
    /// Actions successfully applied to the image bytes.
    pub repaired: Vec<RepairAction>,
    /// Anomalies that were detected but could not be automatically repaired.
    pub cannot_repair: Vec<CannotRepair>,
}

impl RepairReport {
    /// Mandatory disclaimer that must accompany any repaired image used in
    /// evidence or presented in a forensic context.
    pub const DISCLAIMER: &'static str = concat!(
        "FORENSIC REPAIR DISCLAIMER: ",
        "This image has been modified by an automated repair process. ",
        "Repaired bytes no longer reflect the original evidence state. ",
        "The original unmodified image MUST be preserved and should be ",
        "used as the primary evidence artefact. This repaired copy is ",
        "provided solely to enable further analysis of recoverable content. ",
        "All repair actions are documented in RepairReport::repaired. ",
        "Do NOT submit a repaired image as unmodified forensic evidence.",
    );

    /// True if any repair actions were performed.
    pub fn any_repaired(&self) -> bool {
        !self.repaired.is_empty()
    }

    /// True if any anomalies could not be repaired.
    pub fn any_unresolved(&self) -> bool {
        !self.cannot_repair.is_empty()
    }
}

/// Mutable repair context for a VHDX image.
///
/// Call [`attempt_repair`](Self::attempt_repair) to run all available repairs.
/// Consume with [`into_bytes`](Self::into_bytes) to obtain the (possibly repaired)
/// image bytes.
pub struct VhdxRepair {
    data: Vec<u8>,
}

impl VhdxRepair {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Attempt all automated repairs and return a report.
    ///
    /// Repairable conditions (single bad header/region-table copy, BAT entries
    /// pointing past container end) are fixed in place. Conditions that require
    /// judgment or missing reference data are listed in `cannot_repair`.
    ///
    /// Always check [`RepairReport::DISCLAIMER`] before using the resulting
    /// image in any evidentiary context.
    pub fn attempt_repair(&mut self) -> RepairReport {
        let mut repaired = Vec::new();
        let mut cannot_repair = Vec::new();

        let issues = VhdxIntegrity::new(&self.data).analyse();

        for issue in issues {
            // Capture booleans / Copy fields before the match borrows `issue`.
            let was_repaired = match &issue {
                VhdxIntegrityAnomaly::HeaderChecksumMismatch { copy: 1, .. } => {
                    repaired.push(self.copy_header(2, 1));
                    true
                }
                VhdxIntegrityAnomaly::HeaderChecksumMismatch { copy: 2, .. } => {
                    repaired.push(self.copy_header(1, 2));
                    true
                }
                VhdxIntegrityAnomaly::RegionTableChecksumMismatch { copy: 1, .. } => {
                    repaired.push(self.copy_region_table(2, 1));
                    true
                }
                VhdxIntegrityAnomaly::RegionTableChecksumMismatch { copy: 2, .. } => {
                    repaired.push(self.copy_region_table(1, 2));
                    true
                }
                VhdxIntegrityAnomaly::BatEntryBeyondContainer { bat_index, .. } => {
                    let idx = *bat_index;
                    if let Some(off) = VhdxIntegrity::new(&self.data).bat_region_offset() {
                        repaired.push(self.zero_bat_entry(off, idx));
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if !was_repaired {
                let reason: &'static str = match &issue {
                    VhdxIntegrityAnomaly::BothHeaderCopiesInvalid => {
                        "Both header copies are invalid; no valid reference copy exists to restore from"
                    }
                    VhdxIntegrityAnomaly::BothRegionTableCopiesInvalid => {
                        "Both region table copies are invalid; region layout cannot be determined"
                    }
                    VhdxIntegrityAnomaly::DirtyLog { .. } => {
                        "Log replay is required to reach a consistent image state; \
                        log replay is out of scope for offline forensic analysis — \
                        mount the image on a running Hyper-V host for automatic replay"
                    }
                    VhdxIntegrityAnomaly::BatEntriesOverlap { .. } => {
                        "Overlapping BAT entries are ambiguous; cannot determine which \
                        logical block mapping is authoritative without external reference data"
                    }
                    VhdxIntegrityAnomaly::HeaderCopyMismatch { .. } => {
                        "Header field mismatch between copies requires manual forensic \
                        analysis to determine which copy reflects the intended state"
                    }
                    VhdxIntegrityAnomaly::RegionTableCopyMismatch { .. } => {
                        "Region table field mismatch between copies requires manual forensic \
                        analysis to determine which copy reflects the intended state"
                    }
                    VhdxIntegrityAnomaly::DifferencingDisk => {
                        "Differencing disk repair requires access to the full parent chain"
                    }
                    VhdxIntegrityAnomaly::BatEntryBeyondContainer { .. } => {
                        "BAT region offset cannot be determined from region tables"
                    }
                    _ => "No automated repair strategy is available for this anomaly type",
                };
                cannot_repair.push(CannotRepair {
                    anomaly: issue,
                    reason,
                });
            }
        }

        RepairReport {
            repaired,
            cannot_repair,
        }
    }

    /// Consume the repair context and return the (possibly modified) image bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the current image bytes without consuming.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl VhdxRepair {
    fn copy_header(&mut self, src_copy: u8, dst_copy: u8) -> RepairAction {
        let src_off = if src_copy == 1 {
            HEADER1_OFFSET as usize
        } else {
            HEADER2_OFFSET as usize
        };
        let dst_off = if dst_copy == 1 {
            HEADER1_OFFSET as usize
        } else {
            HEADER2_OFFSET as usize
        };
        let src_bytes: Vec<u8> = self.data[src_off..src_off + HEADER_SIZE].to_vec();
        self.data[dst_off..dst_off + HEADER_SIZE].copy_from_slice(&src_bytes);
        // Recompute CRC for the destination.
        self.data[dst_off + 4..dst_off + 8].fill(0);
        let crc = crc32c(&self.data[dst_off..dst_off + HEADER_SIZE]);
        self.data[dst_off + 4..dst_off + 8].copy_from_slice(&crc.to_le_bytes());
        RepairAction {
            description: format!(
                "Replaced corrupt header copy {dst_copy} with copy {src_copy} and recomputed CRC32C"
            ),
            byte_offset: dst_off as u64,
            bytes_changed: HEADER_SIZE,
            disclaimer: "Header copy was replaced with the other valid copy. \
                The original corrupt copy may have contained forensically significant modifications.",
        }
    }

    fn copy_region_table(&mut self, src_copy: u8, dst_copy: u8) -> RepairAction {
        let src_off = if src_copy == 1 {
            REGION_TABLE1_OFFSET as usize
        } else {
            REGION_TABLE2_OFFSET as usize
        };
        let dst_off = if dst_copy == 1 {
            REGION_TABLE1_OFFSET as usize
        } else {
            REGION_TABLE2_OFFSET as usize
        };
        let src_bytes: Vec<u8> = self.data[src_off..src_off + REGION_TABLE_CRC_COVERAGE].to_vec();
        self.data[dst_off..dst_off + REGION_TABLE_CRC_COVERAGE].copy_from_slice(&src_bytes);
        self.data[dst_off + 4..dst_off + 8].fill(0);
        let mut crc_buf = self.data[dst_off..dst_off + REGION_TABLE_CRC_COVERAGE].to_vec();
        crc_buf[4..8].fill(0);
        let crc = crc32c(&crc_buf);
        self.data[dst_off + 4..dst_off + 8].copy_from_slice(&crc.to_le_bytes());
        RepairAction {
            description: format!(
                "Replaced corrupt region table copy {dst_copy} with copy {src_copy} and recomputed CRC32C"
            ),
            byte_offset: dst_off as u64,
            bytes_changed: REGION_TABLE_CRC_COVERAGE,
            disclaimer: "Region table copy was replaced with the other valid copy. \
                The original corrupt copy may have contained forensically significant modifications.",
        }
    }

    fn zero_bat_entry(&mut self, bat_offset: u64, bat_index: usize) -> RepairAction {
        let byte_pos = bat_offset as usize + bat_index * 8;
        self.data[byte_pos..byte_pos + 8].fill(0);
        RepairAction {
            description: format!(
                "BAT entry {bat_index} pointed outside container — zeroed to NOT_PRESENT"
            ),
            byte_offset: byte_pos as u64,
            bytes_changed: 8,
            disclaimer: "BAT entry replaced with NOT_PRESENT (0). \
                Data the entry supposedly referenced cannot be recovered from this image.",
        }
    }
}
