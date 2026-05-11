use crate::header::{
    crc32c, HEADER1_OFFSET, HEADER2_OFFSET, HEADER_SIGNATURE, HEADER_SIZE,
    REGION_TABLE1_OFFSET, REGION_TABLE2_OFFSET,
};
use crate::metadata::{
    GUID_FILE_PARAMETERS, GUID_LOGICAL_SECTOR_SIZE, GUID_VIRTUAL_DISK_SIZE,
    METADATA_TABLE_SIGNATURE,
};
use crate::region::{BAT_GUID, METADATA_GUID, REGION_ENTRY_SIZE, REGION_TABLE_SIGNATURE};
use crate::FILE_MAGIC;

const MIN_CONTAINER_SIZE: u64 = 0x0025_0000;
const REGION_TABLE_CRC_COVERAGE: usize = 65536;
const REGION_TABLE_ENTRY_BASE: usize = 16;
// Offset of file_offset field within a region table entry.
const RT_ENTRY_FILE_OFFSET: usize = 16;

/// Diagnostic severity level.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Noteworthy but consistent with legitimate use (e.g. uncommitted log on a live snapshot).
    Info,
    /// Suspicious — has a plausible legitimate explanation but warrants investigation.
    Warning,
    /// Definitive evidence of tampering or structural corruption.
    Error,
    /// Prevents reliable forensic analysis; file cannot be decoded.
    Critical,
}

/// A single forensic finding in a VHDX image.
///
/// Variants are grouped by the structural layer they belong to.
/// The VHDX format has an important asymmetry: **headers and region tables are
/// CRC32C-protected** (tampering leaves a detectable fingerprint), while
/// **metadata fields and BAT entries are not** (primary silent-tampering surface).
#[derive(Debug, Clone, PartialEq)]
pub enum VhdxIntegrityAnomaly {
    // ── Container / magic ─────────────────────────────────────────────────────
    /// The 8-byte "vhdxfile" magic at offset 0 does not match.
    BadMagic { found: [u8; 8] },
    /// File is smaller than the minimum structural size (2.5 MB).
    ContainerTruncated { size: u64, minimum: u64 },

    // ── Header CRC32C integrity ───────────────────────────────────────────────
    /// One header copy has a CRC32C mismatch — content was modified after the last write.
    HeaderChecksumMismatch { copy: u8, computed: u32, stored: u32 },
    /// Both header copies have invalid CRC32C — header region is unreadable.
    BothHeaderCopiesInvalid,

    // ── Header semantic cross-checks (when both copies are valid) ─────────────
    /// Both valid header copies report identical sequence numbers, which should
    /// differ between copies (incremented on write).
    SequenceNumbersIdentical { value: u64 },
    /// Both header copies have sequence number 0; normally at least one is non-zero
    /// after the first write cycle.
    BothSequenceNumbersZero,
    /// The same named field has different values in the two valid header copies.
    /// This is normally impossible without manual patching.
    HeaderCopyMismatch {
        field: &'static str,
        copy1_value: u64,
        copy2_value: u64,
    },

    // ── Log section indicators ────────────────────────────────────────────────
    /// The active header declares a non-zero log region, indicating uncommitted
    /// writes were present at image capture time. Log replay is required for a
    /// consistent view but is out of scope for offline forensic analysis.
    DirtyLog { log_length: u32, log_offset: u64 },

    // ── Region table CRC32C integrity ─────────────────────────────────────────
    /// One region table copy has a CRC32C mismatch.
    RegionTableChecksumMismatch { copy: u8, computed: u32, stored: u32 },
    /// Both region table copies have invalid CRC32C — region layout is unreadable.
    BothRegionTableCopiesInvalid,
    /// The same BAT or Metadata region field has a different value in RT1 vs RT2
    /// (both CRCs valid). One was patched and re-signed; the other was not.
    RegionTableCopyMismatch {
        region: &'static str,
        field: &'static str,
        rt1_value: u64,
        rt2_value: u64,
    },

    // ── Metadata anomalies — NOT CRC-protected (silent-tampering surface) ─────
    /// A required metadata item (BlockSize, VirtualDiskSize) is absent.
    MetadataMissing(&'static str),
    /// BlockSize is outside the spec range [1 MB, 256 MB] or not a power of two.
    BlockSizeInvalid { block_size: u32, reason: &'static str },
    /// LogicalSectorSize is not 512 or 4096.
    LogicalSectorSizeInvalid { sector_size: u32 },
    /// VirtualDiskSize is zero, exceeds 64 TiB, or is not a multiple of sector size.
    VirtualDiskSizeInvalid { vdisk_size: u64, reason: &'static str },
    /// The declared VirtualDiskSize is smaller than the actual range covered by the
    /// present BAT entries — data beyond the declared size is hidden.
    VirtualDiskSizeUnderreported { declared: u64, bat_coverage: u64 },
    /// This image declares a differencing disk parent (`HasParent = true`), which
    /// this crate does not support. The image cannot be fully decoded without the
    /// parent chain.
    DifferencingDisk,

    // ── BAT anomalies — NOT CRC-protected (silent-tampering surface) ──────────
    /// A FULLY_PRESENT BAT entry's file offset points outside the container.
    /// The declared data block does not actually exist in this file.
    BatEntryBeyondContainer {
        bat_index: usize,
        file_offset: u64,
        container_size: u64,
    },
    /// A FULLY_PRESENT BAT entry's file offset is not aligned to 1 MB.
    /// The spec mandates MB alignment; misaligned entries indicate manual patching.
    BatEntryUnaligned { bat_index: usize, file_offset: u64 },
    /// Two FULLY_PRESENT BAT entries point to the same 1 MB block in the container.
    /// Overlapping entries are ambiguous — the same bytes represent two different
    /// logical blocks.
    BatEntriesOverlap {
        index_a: usize,
        index_b: usize,
        shared_offset: u64,
    },
    /// A data block BAT entry is in the PARTIALLY_PRESENT transient state, which
    /// should never persist in a stable image.
    PartiallyPresentBlock { bat_index: usize },
    /// A sector bitmap entry has an unexpected state value.
    SectorBitmapInvalidState { bat_index: usize, state: u8 },

    // ── Container layout / hidden data indicators ─────────────────────────────
    /// Non-zero bytes exist between the end of the last BAT-addressed data block
    /// and the physical end of the file. May indicate concealed data.
    TrailingData { start_offset: u64, size: u64 },

    // ── Creator string ────────────────────────────────────────────────────────
    /// The creator string at the File Identifier section contains an anomaly
    /// inconsistent with legitimate tools.
    CreatorStringAnomalous { anomaly: &'static str },
}

impl VhdxIntegrityAnomaly {
    /// Diagnostic severity for this finding.
    pub fn severity(&self) -> Severity {
        match self {
            Self::BadMagic { .. } | Self::ContainerTruncated { .. } => Severity::Critical,
            Self::BothHeaderCopiesInvalid | Self::BothRegionTableCopiesInvalid => {
                Severity::Critical
            }
            Self::HeaderChecksumMismatch { .. } | Self::RegionTableChecksumMismatch { .. } => {
                Severity::Error
            }
            Self::HeaderCopyMismatch { .. }
            | Self::RegionTableCopyMismatch { .. }
            | Self::BatEntriesOverlap { .. }
            | Self::BatEntryBeyondContainer { .. }
            | Self::VirtualDiskSizeUnderreported { .. } => Severity::Error,
            Self::DifferencingDisk
            | Self::MetadataMissing(_)
            | Self::BlockSizeInvalid { .. }
            | Self::LogicalSectorSizeInvalid { .. }
            | Self::VirtualDiskSizeInvalid { .. }
            | Self::BatEntryUnaligned { .. }
            | Self::PartiallyPresentBlock { .. }
            | Self::SectorBitmapInvalidState { .. } => Severity::Warning,
            Self::BothSequenceNumbersZero
            | Self::SequenceNumbersIdentical { .. }
            | Self::TrailingData { .. }
            | Self::CreatorStringAnomalous { .. } => Severity::Warning,
            Self::DirtyLog { .. } => Severity::Info,
        }
    }
}

/// Read-only forensic analyser for a VHDX byte image.
///
/// Operates on raw bytes so it can detect anomalies that would prevent normal
/// parsing (bad CRCs, missing regions, invalid metadata values).
pub struct VhdxIntegrity<'a> {
    data: &'a [u8],
}

impl<'a> VhdxIntegrity<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Run all integrity checks and return the complete list of findings.
    /// Returns an empty `Vec` for a structurally sound image.
    pub fn analyse(&self) -> Vec<VhdxIntegrityAnomaly> {
        // Stub — GREEN implementation pending.
        vec![]
    }

    // Exposed for targeted analysis.

    pub fn check_file_magic(&self) -> Vec<VhdxIntegrityAnomaly> {
        vec![]
    }

    pub fn check_headers(&self) -> Vec<VhdxIntegrityAnomaly> {
        vec![]
    }

    pub fn check_region_tables(&self) -> Vec<VhdxIntegrityAnomaly> {
        vec![]
    }

    pub fn check_metadata(&self) -> Vec<VhdxIntegrityAnomaly> {
        vec![]
    }

    pub fn check_bat(&self) -> Vec<VhdxIntegrityAnomaly> {
        vec![]
    }

    pub fn check_trailing_data(&self) -> Vec<VhdxIntegrityAnomaly> {
        vec![]
    }
}

// Internal helpers used by the GREEN implementation (defined here to suppress
// dead-code warnings even before GREEN — they will be called from analyse()).
#[allow(dead_code)]
impl<'a> VhdxIntegrity<'a> {
    fn header_block(&self, copy: u8) -> Option<&[u8]> {
        let off = if copy == 1 {
            HEADER1_OFFSET as usize
        } else {
            HEADER2_OFFSET as usize
        };
        if self.data.len() >= off + HEADER_SIZE {
            Some(&self.data[off..off + HEADER_SIZE])
        } else {
            None
        }
    }

    fn region_table_block(&self, copy: u8) -> Option<&[u8]> {
        let off = if copy == 1 {
            REGION_TABLE1_OFFSET as usize
        } else {
            REGION_TABLE2_OFFSET as usize
        };
        if self.data.len() >= off + REGION_TABLE_CRC_COVERAGE {
            Some(&self.data[off..off + REGION_TABLE_CRC_COVERAGE])
        } else {
            None
        }
    }

    fn header_crc_valid(&self, copy: u8) -> bool {
        self.header_block(copy).map_or(false, |block| {
            if &block[0..4] != HEADER_SIGNATURE {
                return false;
            }
            let stored = u32::from_le_bytes(block[4..8].try_into().unwrap());
            let mut buf = block.to_vec();
            buf[4..8].fill(0);
            crc32c(&buf) == stored
        })
    }

    fn region_table_crc_valid(&self, copy: u8) -> bool {
        self.region_table_block(copy).map_or(false, |block| {
            if &block[0..4] != REGION_TABLE_SIGNATURE {
                return false;
            }
            let stored = u32::from_le_bytes(block[4..8].try_into().unwrap());
            let mut buf = block[..REGION_TABLE_CRC_COVERAGE].to_vec();
            buf[4..8].fill(0);
            buf.resize(REGION_TABLE_CRC_COVERAGE, 0);
            crc32c(&buf) == stored
        })
    }
}
