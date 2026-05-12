use crate::header::{
    crc32c, HEADER1_OFFSET, HEADER2_OFFSET, HEADER_SIGNATURE, HEADER_SIZE, REGION_TABLE1_OFFSET,
    REGION_TABLE2_OFFSET,
};
use crate::metadata::{
    GUID_FILE_PARAMETERS, GUID_LOGICAL_SECTOR_SIZE, GUID_PARENT_LOCATOR,
    GUID_PHYSICAL_SECTOR_SIZE, GUID_VIRTUAL_DISK_ID, GUID_VIRTUAL_DISK_SIZE,
    METADATA_TABLE_SIGNATURE,
};
use crate::region::{BAT_GUID, MB, METADATA_GUID, REGION_ENTRY_SIZE, REGION_TABLE_CRC_COVERAGE, REGION_TABLE_SIGNATURE};
use crate::FILE_MAGIC;

const MIN_CONTAINER_SIZE: u64 = 0x0005_0000; // 320 KB (5 × 64 KB structural slots)

// BAT payload block states (MS-VHDX §2.3.5.1).
const PAYLOAD_BLOCK_NOT_PRESENT: u8 = 0;
const PAYLOAD_BLOCK_FULLY_PRESENT: u8 = 6;
const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u8 = 7;

// Sector bitmap entry states.
const SB_BLOCK_NOT_PRESENT: u8 = 0;
const SB_BLOCK_PRESENT: u8 = 6;

// Metadata field validation bounds (MS-VHDX §2.5.5).
const BLOCK_SIZE_MIN: u32 = 1 << 20; // 1 MB
const BLOCK_SIZE_MAX: u32 = 256 << 20; // 256 MB

// Reserved-bits mask for BAT entries: bits [3..19] must be zero (MS-VHDX §2.3.5.1).
const BAT_RESERVED_BITS_MASK: u64 = 0x000F_FFF8;

// ── Module-level helpers ──────────────────────────────────────────────────────

/// Read a little-endian u16 from `s` at byte offset `o`.
#[inline]
fn r16(s: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(s[o..o + 2].try_into().unwrap())
}

/// Read a little-endian u32 from `s` at byte offset `o`.
#[inline]
fn r32(s: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(s[o..o + 4].try_into().unwrap())
}

/// Read a little-endian u64 from `s` at byte offset `o`.
#[inline]
fn r64(s: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(s[o..o + 8].try_into().unwrap())
}

/// Copy 16 bytes from `s` at offset `o` into a GUID array.
#[inline]
fn guid_at(s: &[u8], o: usize) -> [u8; 16] {
    s[o..o + 16].try_into().unwrap()
}

/// Compute CRC32C of `block` with bytes 4..8 zeroed (the standard VHDX CRC field).
fn block_crc(block: &[u8]) -> u32 {
    let mut buf = block.to_vec();
    buf[4..8].fill(0);
    crc32c(&buf)
}

/// Verify CRC32C for a fixed-size structural block (header or region table).
///
/// Returns `Ok(())` if the signature matches and the CRC is valid.
/// Returns `Err((computed, stored))` on any failure; both are 0 when the block
/// is unreadable or has a wrong signature.
fn verify_block_crc(
    data: &[u8],
    offset: usize,
    size: usize,
    sig: &[u8],
) -> Result<(), (u32, u32)> {
    let end = offset.checked_add(size).filter(|&e| e <= data.len()).ok_or((0u32, 0u32))?;
    let block = &data[offset..end];
    if !block.starts_with(sig) {
        return Err((0, 0));
    }
    let stored = r32(block, 4);
    let computed = block_crc(block);
    if computed == stored { Ok(()) } else { Err((computed, stored)) }
}

/// Map a copy index to the corresponding header byte offset.
#[inline]
fn header_offset(copy: u8) -> usize {
    if copy == 1 { HEADER1_OFFSET as usize } else { HEADER2_OFFSET as usize }
}

/// Map a copy index to the corresponding region table byte offset.
#[inline]
fn rt_offset(copy: u8) -> usize {
    if copy == 1 { REGION_TABLE1_OFFSET as usize } else { REGION_TABLE2_OFFSET as usize }
}

/// Resolve a region entry GUID to its canonical name, or `None` for unknown GUIDs.
fn region_name_for_guid(guid: &[u8; 16]) -> Option<&'static str> {
    if guid == &BAT_GUID { Some("BAT") }
    else if guid == &METADATA_GUID { Some("Metadata") }
    else { None }
}

/// Byte offset of BAT entry `index` within the image given the BAT region start.
#[inline]
fn bat_entry_pos(bat_offset: u64, index: usize) -> usize {
    bat_offset as usize + index * 8
}

/// Pre-parsed structural state derived from one pass over a valid region table
/// and the metadata region. Threaded through all layer checks to avoid redundant
/// re-parsing of the same region tables and metadata on each check function call.
struct ParsedRegions {
    bat_offset:  u64,
    bat_length:  u32,
    meta_offset: u64,
    meta_length: u32,
    /// Raw BlockSize from FileParameters; None if item was absent or unreadable.
    block_size:  Option<u32>,
    /// Raw LogicalSectorSize; None if item absent.
    logical_ss:  Option<u32>,
    /// Raw VirtualDiskSize; None if absent.
    vdisk_size:  Option<u64>,
    /// Computed from block_size/logical_ss; `None` when not computable.
    chunk_ratio: Option<u64>,
    has_parent:  bool,
    leave_alloc: bool,
    /// PhysicalSectorSize from metadata, if the item is present.
    physical_ss: Option<u32>,
    /// VirtualDiskId (16-byte GUID) from metadata, if the item is present.
    vdisk_id: Option<[u8; 16]>,
    /// True when a ParentLocator metadata item was found.
    has_parent_locator: bool,
}

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
    /// File is smaller than the minimum structural size (320 KB).
    ContainerTruncated { size: u64, minimum: u64 },

    // ── Header CRC32C integrity ───────────────────────────────────────────────
    /// One header copy has a CRC32C mismatch — content was modified after the last write.
    HeaderChecksumMismatch {
        copy: u8,
        computed: u32,
        stored: u32,
    },
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

    // ── Log section anomalies (Phase 4) ──────────────────────────────────────
    /// The log region exists (LogLength > 0) but all bytes in the log area
    /// are zero. The log was declared dirty but its content was zeroed —
    /// possibly to block log-entry analysis while preserving the dirty state.
    LogZeroedButDirty { log_offset: u64, log_length: u32 },
    /// A log entry position does not begin with the expected "loge" signature.
    LogEntrySignatureMissing { entry_offset: u64 },
    /// A log entry's CRC32C is invalid. Cannot be safely replayed by Hyper-V.
    LogEntryCrcMismatch {
        entry_offset: u64,
        computed: u32,
        stored: u32,
    },
    /// The LogGuid inside a log entry does not match the active header's
    /// LogGuid. The log was transplanted from a different disk image.
    LogEntryGuidMismatch {
        entry_offset: u64,
        entry_guid: [u8; 16],
        header_guid: [u8; 16],
    },
    /// A gap exists in the sequence numbers of consecutive log entries.
    LogSequenceNumberGap {
        at_offset: u64,
        expected_seq: u64,
        found_seq: u64,
    },

    // ── Header GUID / version / log-pointer anomalies (Phase 2) ─────────────
    /// FileWriteGuid (header bytes 16–31) is all zeros — disk identity was
    /// wiped, preventing correlation with other images or audit trails.
    FileWriteGuidAllZeros,
    /// DataWriteGuid (header bytes 32–47) is all zeros — data-layer identity
    /// erased; disrupts parent-GUID verification in differencing disk chains.
    DataWriteGuidAllZeros,
    /// LogGuid (bytes 48–63) is non-zero but LogLength is zero — the log GUID
    /// was set but the log was cleared without updating the GUID. Indicates
    /// manual header manipulation between write cycles.
    LogGuidWithNoLog { log_guid: [u8; 16] },
    /// LogLength is non-zero (dirty log exists) but LogGuid is all zeros —
    /// structurally impossible via normal Hyper-V operation. Strong indicator
    /// of a manually constructed dirty-log header.
    LogGuidAllZerosWithDirtyLog { log_length: u32 },
    /// LogVersion (bytes 64–65) must be 1. Any other value indicates a format
    /// version violation or direct header patching.
    LogVersionInvalid { version: u16 },
    /// Version (bytes 66–67) must be 1 — the only defined VHDX format version.
    VersionInvalid { version: u16 },
    /// LogOffset (bytes 72–79) must be 1 MB aligned. Misalignment indicates
    /// manual patching of the log pointer.
    LogOffsetMisaligned { log_offset: u64 },
    /// LogLength (bytes 68–71) must be a multiple of 1 MB.
    LogLengthMisaligned { log_length: u32 },
    /// LogOffset + LogLength extends past the end of the file. The declared
    /// log region does not physically exist in this container.
    LogBeyondContainer {
        log_offset: u64,
        log_length: u32,
        container_size: u64,
    },
    /// LogOffset places the log inside the header section (below 1 MB). A
    /// log here would overwrite structural data if replayed — log poisoning.
    LogInReservedZone { log_offset: u64 },
    /// Both header copies have valid CRCs but their sequence numbers differ by
    /// more than 1. A larger gap indicates one copy was patched without going
    /// through a normal write cycle.
    SequenceNumberGapLarge { seq1: u64, seq2: u64, gap: u64 },

    // ── Log section indicators ────────────────────────────────────────────────
    /// The active header declares a non-zero log region, indicating uncommitted
    /// writes were present at image capture time. Log replay is required for a
    /// consistent view but is out of scope for offline forensic analysis.
    DirtyLog { log_length: u32, log_offset: u64 },

    // ── Region layout anomalies (Phase 3) ────────────────────────────────────
    /// A region entry's file_offset is not 1 MB aligned. All VHDX regions
    /// must start at 1 MB boundaries; misalignment indicates manual patching.
    RegionMisaligned {
        region: &'static str,
        file_offset: u64,
    },
    /// A region entry's file_offset + length extends past the container end.
    RegionBeyondContainer {
        region: &'static str,
        declared_end: u64,
        container_size: u64,
    },
    /// Two declared regions (BAT, Metadata) have overlapping byte ranges.
    RegionsOverlap {
        region_a: &'static str,
        region_b: &'static str,
        overlap_offset: u64,
    },
    /// The dirty-log region overlaps a structural zone (FileIdentifier, Header,
    /// or RegionTable). Log replay would overwrite VHDX structural data.
    LogOverlapsStructuralRegion {
        log_offset: u64,
        overlapping: &'static str,
    },
    /// A region entry has Required=1 with a GUID that is neither BAT nor
    /// Metadata. Hyper-V refuses to open such files — cannot be legitimate.
    UnknownRequiredRegion { guid_hex: String },
    /// Reserved bytes in the region table header (bytes 12–15) or in a region
    /// entry's Required field (bits 1–31) are non-zero.
    RegionTableReservedNonZero {
        copy: u8,
        /// `"header"` or `"entry"`
        location: &'static str,
        value: u32,
    },

    // ── Region table CRC32C integrity ─────────────────────────────────────────
    /// One region table copy has a CRC32C mismatch.
    RegionTableChecksumMismatch {
        copy: u8,
        computed: u32,
        stored: u32,
    },
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
    BlockSizeInvalid {
        block_size: u32,
        reason: &'static str,
    },
    /// LogicalSectorSize is not 512 or 4096.
    LogicalSectorSizeInvalid { sector_size: u32 },
    /// VirtualDiskSize is zero, exceeds 64 TiB, or is not a multiple of sector size.
    VirtualDiskSizeInvalid {
        vdisk_size: u64,
        reason: &'static str,
    },
    /// The declared VirtualDiskSize is smaller than the actual range covered by the
    /// present BAT entries — data beyond the declared size is hidden.
    VirtualDiskSizeUnderreported { declared: u64, bat_coverage: u64 },
    /// This image declares a differencing disk parent (`HasParent = true`), which
    /// this crate does not support. The image cannot be fully decoded without the
    /// parent chain.
    DifferencingDisk,

    // ── Metadata deep analysis (Phase 6) ────────────────────────────────────
    /// PhysicalSectorSize metadata item is present but its value is neither
    /// 512 nor 4096 — the only values permitted by MS-VHDX §2.5.7.
    PhysicalSectorSizeInvalid { sector_size: u32 },
    /// VirtualDiskId metadata item is present but all 16 bytes are zero.
    /// The disk identity GUID was deliberately wiped, preventing correlation
    /// with parent chains or audit logs.
    VirtualDiskIdAllZeros,
    /// Two metadata item data ranges overlap within the item area. Overlapping
    /// items are structurally impossible in a correctly written VHDX — only
    /// direct binary manipulation can produce this state.
    MetadataItemsOverlap {
        item_a_offset: u32,
        item_b_offset: u32,
        overlap_offset: u32,
    },
    /// A metadata item's data range extends past the end of the metadata
    /// region. The item cannot be safely read; indicates manual patching.
    MetadataItemBeyondRegion {
        item_offset: u32,
        item_end: u32,
        region_end: u32,
    },
    /// LeaveBlocksAllocated (bit 0 of FileParameters.Flags) is set in a
    /// non-differencing disk. This flag is only valid in differencing disks;
    /// its presence suggests post-creation cloning or image manipulation.
    LeaveBlocksAllocatedSet,
    /// HasParent is true (differencing disk declared) but no ParentLocator
    /// metadata item is present. The parent chain cannot be resolved.
    MissingParentLocator,
    /// The declared VirtualDiskSize implies a larger BAT than exists
    /// physically. Reads at LBAs beyond the BAT coverage will silently fail.
    VirtualDiskSizeOverreported { declared: u64, bat_coverage: u64 },

    // ── BAT semantic anomalies (Phase 5) ─────────────────────────────────────
    /// The BAT region's physical size (CRC-protected region table) does not
    /// match the size implied by VirtualDiskSize and BlockSize (unprotected
    /// metadata). One metadata field was silently modified after file creation.
    BatSizeMetadataMismatch {
        bat_bytes_actual: u32,
        bat_entries_actual: usize,
        bat_entries_expected: usize,
        vdisk_size: u64,
        block_size: u32,
    },
    /// A FULLY_PRESENT BAT entry's file offset falls inside a VHDX structural
    /// section (File Identifier, Header, Region Table, Metadata, or Log).
    /// This redirects virtual disk reads into structural data.
    BatEntryInStructuralRegion {
        bat_index: usize,
        file_offset: u64,
        /// `"File Identifier"`, `"Header"`, `"Region Table"`, `"Metadata"`, or `"Log"`
        collides_with: &'static str,
    },
    /// A FULLY_PRESENT data block's corresponding sector bitmap slot is in
    /// NOT_PRESENT state. Hyper-V always writes the bitmap alongside data;
    /// this combination indicates direct BAT manipulation.
    MissingSectorBitmap {
        data_bat_index: usize,
        bitmap_bat_index: usize,
    },
    /// A data BAT entry is in UNDEFINED state (1), only valid transiently
    /// during block allocation. Persistence indicates an interrupted write
    /// or direct BAT manipulation.
    UndefinedBlockState { bat_index: usize },
    /// A data BAT entry is in UNMAPPED state (3) in a non-differencing disk.
    /// UNMAPPED is only valid in differencing disks.
    UnmappedBlockInNonDifferencing { bat_index: usize },
    /// A NOT_PRESENT BAT entry's upper bits (ghost file offset) point to a
    /// file range that contains non-zero bytes. Content was written then the
    /// BAT entry was zeroed without wiping the underlying storage.
    /// Opt-in check — not included in `analyse()`; call `check_bat_ghost_data()`.
    GhostDataInAbsentBlock {
        bat_index: usize,
        file_offset: u64,
        nonzero_bytes: u64,
    },

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

    // ── Container / File Identifier refinements (Phase 7) ────────────────────
    /// Non-zero bytes exist in the reserved area of the File Identifier
    /// section (bytes 512–65535, after the creator string). Normal parsers
    /// skip this area entirely — it is a low-visibility location for
    /// data hiding or steganographic payloads.
    FileIdentifierReservedNonZero { start_offset: u64, nonzero_count: u64 },
    /// Non-zero bytes exist in a gap between two adjacent structural regions
    /// (e.g. the padding between Header1 and Header2, or between Region
    /// Table2 and the first user region). Hyper-V zeros these gaps at creation;
    /// non-zero content indicates data hiding or a partial-write artifact.
    InterRegionGapNonZero {
        from_region: &'static str,
        to_region: &'static str,
        gap_offset: u64,
        gap_size: u64,
    },
    /// Non-zero bytes exist in the reserved portion (bytes 80–4095) of a
    /// valid header copy. These bytes are CRC-protected but not semantically
    /// defined — an attacker can write data there and update the CRC to
    /// produce a structurally valid header that carries hidden content.
    HeaderReservedNonZero { copy: u8, offset_in_header: u16, length: u16 },
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
            Self::BatEntryInStructuralRegion { .. }
            | Self::BatSizeMetadataMismatch { .. } => Severity::Error,
            Self::MissingSectorBitmap { .. }
            | Self::UndefinedBlockState { .. }
            | Self::UnmappedBlockInNonDifferencing { .. }
            | Self::GhostDataInAbsentBlock { .. } => Severity::Warning,
            Self::LogEntryCrcMismatch { .. }
            | Self::LogEntryGuidMismatch { .. }
            | Self::LogSequenceNumberGap { .. } => Severity::Error,
            Self::LogZeroedButDirty { .. } | Self::LogEntrySignatureMissing { .. } => {
                Severity::Warning
            }
            Self::RegionMisaligned { .. }
            | Self::RegionBeyondContainer { .. }
            | Self::RegionsOverlap { .. }
            | Self::LogOverlapsStructuralRegion { .. } => Severity::Error,
            Self::UnknownRequiredRegion { .. } | Self::RegionTableReservedNonZero { .. } => {
                Severity::Warning
            }
            Self::FileWriteGuidAllZeros
            | Self::DataWriteGuidAllZeros
            | Self::LogGuidWithNoLog { .. }
            | Self::LogVersionInvalid { .. }
            | Self::VersionInvalid { .. }
            | Self::SequenceNumberGapLarge { .. } => Severity::Warning,
            Self::LogOffsetMisaligned { .. }
            | Self::LogLengthMisaligned { .. }
            | Self::LogBeyondContainer { .. }
            | Self::LogInReservedZone { .. } => Severity::Error,
            // log_guid=0 means no valid entries per spec; log_length>0 is a QEMU quirk, not corruption.
            Self::LogGuidAllZerosWithDirtyLog { .. } => Severity::Warning,
            Self::DirtyLog { .. } => Severity::Info,
            Self::PhysicalSectorSizeInvalid { .. } | Self::VirtualDiskIdAllZeros => {
                Severity::Warning
            }
            Self::MetadataItemsOverlap { .. }
            | Self::MetadataItemBeyondRegion { .. }
            | Self::MissingParentLocator
            | Self::VirtualDiskSizeOverreported { .. } => Severity::Error,
            Self::LeaveBlocksAllocatedSet => Severity::Warning,
            Self::FileIdentifierReservedNonZero { .. } | Self::HeaderReservedNonZero { .. } => {
                Severity::Warning
            }
            Self::InterRegionGapNonZero { .. } => Severity::Info,
        }
    }

    /// A human-readable explanation of the forensic significance of this anomaly.
    pub fn forensic_significance(&self) -> &'static str {
        match self {
            Self::BadMagic { .. } =>
                "The 8-byte VHDX magic signature is incorrect. The file is either not a VHDX \
                 image, was truncated before the identifier section, or the magic was overwritten \
                 to disguise the container's true format.",
            Self::ContainerTruncated { .. } =>
                "The file is smaller than the minimum VHDX structural size (320 KB). The \
                 container was either incompletely written, deliberately truncated to destroy \
                 evidence, or is a stub masquerading as a full image.",
            Self::HeaderChecksumMismatch { .. } =>
                "A header copy's CRC32C does not match its content. The header was modified \
                 after the last legitimate Hyper-V write — either targeted tampering or \
                 storage-layer corruption of the most security-critical region.",
            Self::BothHeaderCopiesInvalid =>
                "Both redundant header copies have invalid CRC32C. The entire header region \
                 was overwritten or corrupted, rendering the disk identity, log pointer, and \
                 sequence numbers unverifiable.",
            Self::SequenceNumbersIdentical { .. } =>
                "Both header copies share the same sequence number. Hyper-V increments the \
                 sequence number on every write cycle; identical values indicate one copy was \
                 cloned from the other, bypassing the normal redundancy mechanism.",
            Self::BothSequenceNumbersZero =>
                "Both header sequence numbers are zero. A written disk always has at least one \
                 non-zero sequence number; all-zero values suggest a manually constructed \
                 header or a factory-reset operation outside normal Hyper-V control.",
            Self::HeaderCopyMismatch { .. } =>
                "Two CRC-valid header copies disagree on a named field. This is structurally \
                 impossible through normal Hyper-V operation — one copy was patched and \
                 re-signed after the fact to introduce conflicting disk metadata.",
            Self::LogZeroedButDirty { .. } =>
                "The header declares a dirty log but all log bytes are zero. This is used to \
                 preserve the dirty-log indicator (blocking Hyper-V from mounting the disk) \
                 while destroying the log entries that would reveal which blocks were written.",
            Self::LogEntrySignatureMissing { .. } =>
                "A log entry position does not contain the expected 'loge' signature. The log \
                 region was overwritten or the log offset was manipulated to point into an \
                 area that was never written as log data.",
            Self::LogEntryCrcMismatch { .. } =>
                "A log entry's CRC32C is invalid. The entry was modified after writing — log \
                 tampering to alter the on-disk record of which blocks were changed before \
                 the last checkpoint.",
            Self::LogEntryGuidMismatch { .. } =>
                "A log entry's LogGuid does not match the active header's LogGuid. The log \
                 was transplanted from a different VHDX image, replacing the authentic \
                 write history with entries from another disk.",
            Self::LogSequenceNumberGap { .. } =>
                "Consecutive log entries have a gap in sequence numbers. Entries were deleted \
                 from the middle of the log sequence to remove evidence of specific write \
                 operations that occurred between the surviving entries.",
            Self::FileWriteGuidAllZeros =>
                "The FileWriteGuid (disk-level identity GUID) is all zeros. This GUID is \
                 updated on every write cycle and used to correlate images in audit trails; \
                 wiping it severs the chain of custody and prevents linkage to prior captures.",
            Self::DataWriteGuidAllZeros =>
                "The DataWriteGuid (data-layer identity GUID) is all zeros. This GUID tracks \
                 the data state for differencing disk chain verification; zeroing it breaks \
                 parent-image validation and obscures whether data blocks were modified.",
            Self::LogGuidWithNoLog { .. } =>
                "The header contains a non-zero LogGuid but LogLength is zero. A non-zero \
                 LogGuid with no log region indicates the log was cleared without resetting \
                 the GUID — a sign of manual header manipulation between write cycles.",
            Self::LogGuidAllZerosWithDirtyLog { .. } =>
                "A non-zero LogLength exists but LogGuid is all zeros — a combination that \
                 is structurally impossible through normal Hyper-V operation. This indicates \
                 a manually constructed dirty-log header designed to block mounting.",
            Self::LogVersionInvalid { .. } =>
                "The LogVersion field is not 1, the only valid value defined by MS-VHDX. \
                 Any other value indicates a format version violation or direct binary \
                 patching of the header without using a legitimate VHDX writer.",
            Self::VersionInvalid { .. } =>
                "The Version field is not 1, the only defined VHDX format version. This \
                 value is set at creation and never changed; an unexpected value indicates \
                 a hand-crafted header or an attempt to trigger version-specific parser bugs.",
            Self::LogOffsetMisaligned { .. } =>
                "The LogOffset is not 1 MB aligned, violating the VHDX specification. \
                 All log regions must start at MB boundaries; misalignment indicates manual \
                 patching of the log pointer to redirect log operations to an arbitrary offset.",
            Self::LogLengthMisaligned { .. } =>
                "The LogLength is not a multiple of 1 MB. The specification requires MB \
                 granularity for log regions; a misaligned length indicates direct binary \
                 editing of the header outside any legitimate VHDX tool.",
            Self::LogBeyondContainer { .. } =>
                "The declared log region extends past the end of the file. The log physically \
                 does not exist in this container; the log pointer was set to reference \
                 data that is not present, possibly to trigger parser overflow vulnerabilities.",
            Self::LogInReservedZone { .. } =>
                "The LogOffset places the log inside the header section (below 1 MB). \
                 Log replay would overwrite VHDX structural data — a log-poisoning \
                 attack that can corrupt headers or region tables on mount.",
            Self::SequenceNumberGapLarge { .. } =>
                "The two valid header copies have sequence numbers differing by more than 1. \
                 A gap larger than 1 means write cycles occurred between the two copies being \
                 updated — one copy was patched without going through a legitimate write.",
            Self::DirtyLog { .. } =>
                "The active header declares a non-zero log region, indicating uncommitted \
                 writes were present when the image was captured. This is normal for live \
                 snapshots but means the visible data may not reflect the final committed state.",
            Self::RegionMisaligned { .. } =>
                "A region entry's file_offset is not 1 MB aligned. All VHDX regions must \
                 start at MB boundaries per the specification; misalignment indicates manual \
                 patching of the region table to redirect a structural region.",
            Self::RegionBeyondContainer { .. } =>
                "A declared region extends past the end of the container file. The structural \
                 region physically does not exist; reading it would access out-of-bounds memory \
                 — a potential parser vulnerability or evidence of container truncation.",
            Self::RegionsOverlap { .. } =>
                "Two declared regions (BAT and Metadata) have overlapping byte ranges. \
                 Overlapping regions are structurally impossible in a valid VHDX — only \
                 direct binary manipulation of the region table can produce this state.",
            Self::LogOverlapsStructuralRegion { .. } =>
                "The dirty-log region overlaps a structural zone. Log replay would overwrite \
                 VHDX structural data (headers, region tables, or the file identifier) — a \
                 targeted log-poisoning vector for corrupting parser-critical structures.",
            Self::UnknownRequiredRegion { .. } =>
                "A region table entry has Required=1 with an unrecognized GUID. Hyper-V \
                 refuses to open files with unknown required regions; this state cannot \
                 occur through legitimate tools and indicates a hand-crafted region table.",
            Self::RegionTableReservedNonZero { .. } =>
                "Reserved bytes in the region table are non-zero. These bytes are \
                 CRC-protected but semantically undefined; non-zero content can carry \
                 steganographic payloads that survive most sanitization tools.",
            Self::RegionTableChecksumMismatch { .. } =>
                "A region table copy's CRC32C is invalid. The region table was modified \
                 after the last legitimate write — targeted tampering of the structure \
                 that maps the physical layout of BAT and Metadata regions.",
            Self::BothRegionTableCopiesInvalid =>
                "Both redundant region table copies have invalid CRC32C. The entire \
                 region layout is unverifiable; BAT and Metadata offsets cannot be \
                 trusted, preventing reliable forensic decoding of the container.",
            Self::RegionTableCopyMismatch { .. } =>
                "Two CRC-valid region table copies disagree on a region's offset or size. \
                 One was patched and re-signed; the copies now describe different physical \
                 layouts, making the true data location ambiguous.",
            Self::MetadataMissing(_) =>
                "A required metadata item (BlockSize or VirtualDiskSize) is absent. \
                 These items are mandatory per MS-VHDX; their absence indicates a \
                 deliberately stripped or hand-constructed metadata table.",
            Self::BlockSizeInvalid { .. } =>
                "The BlockSize metadata item has an invalid value (outside [1 MB, 256 MB] \
                 or not a power of two). An invalid block size corrupts BAT index \
                 calculations, causing every block lookup to produce incorrect offsets.",
            Self::LogicalSectorSizeInvalid { .. } =>
                "The LogicalSectorSize is not 512 or 4096. Only these two values are \
                 defined by MS-VHDX; any other value indicates metadata tampering that \
                 breaks sector-to-LBA mapping for the entire virtual disk.",
            Self::VirtualDiskSizeInvalid { .. } =>
                "The VirtualDiskSize is zero, exceeds 64 TiB, or is not a multiple of \
                 the logical sector size. An invalid size corrupts the block count used \
                 to build the BAT index and may cause reads to access arbitrary offsets.",
            Self::VirtualDiskSizeUnderreported { .. } =>
                "The declared VirtualDiskSize is smaller than the range covered by \
                 present BAT entries. Data beyond the declared size is hidden from \
                 parsers that respect the VirtualDiskSize bound — a capacity-hiding attack.",
            Self::DifferencingDisk =>
                "The image declares a differencing disk parent (HasParent=true). The \
                 full data surface cannot be recovered without the parent chain; \
                 differencing disks are also used to split evidence across multiple files.",
            Self::PhysicalSectorSizeInvalid { .. } =>
                "The PhysicalSectorSize metadata item is not 512 or 4096. Only these \
                 values are permitted by MS-VHDX §2.5.7; an invalid value indicates \
                 direct metadata manipulation outside any legitimate VHDX writer.",
            Self::VirtualDiskIdAllZeros =>
                "The VirtualDiskId GUID is all zeros. This GUID is a unique disk \
                 identity written at creation; zeroing it severs the audit trail, \
                 prevents correlation with cloned images, and breaks chain-of-custody.",
            Self::MetadataItemsOverlap { .. } =>
                "Two metadata item data ranges overlap within the item area. Overlapping \
                 items are structurally impossible without direct binary manipulation — \
                 the ambiguous layout can be exploited to confuse different parsers.",
            Self::MetadataItemBeyondRegion { .. } =>
                "A metadata item's data range extends past the end of the metadata \
                 region. The item cannot be safely read; this state indicates manual \
                 patching of the metadata table to create out-of-bounds access conditions.",
            Self::LeaveBlocksAllocatedSet =>
                "The LeaveBlocksAllocated flag is set in a non-differencing disk. This \
                 flag is only valid in differencing disks; its presence in a standalone \
                 image suggests post-creation cloning or deliberate image manipulation.",
            Self::MissingParentLocator =>
                "HasParent is true but no ParentLocator metadata item is present. The \
                 parent chain cannot be resolved, so data blocks that defer to the parent \
                 are unreadable — the image is incomplete or the locator was stripped.",
            Self::VirtualDiskSizeOverreported { .. } =>
                "The declared VirtualDiskSize is larger than what the BAT can address. \
                 Reads at LBAs beyond the BAT coverage silently fail; the declared size \
                 is larger than the actual addressable data surface.",
            Self::BatSizeMetadataMismatch { .. } =>
                "The BAT region's physical size (CRC-protected) does not match the size \
                 implied by VirtualDiskSize and BlockSize (unprotected metadata). One \
                 metadata field was silently modified after file creation.",
            Self::BatEntryInStructuralRegion { .. } =>
                "A FULLY_PRESENT BAT entry's file offset falls inside a VHDX structural \
                 section (File Identifier, Header, Region Table, Metadata, or Log). \
                 This redirects virtual disk reads into structural data — a data-aliasing attack.",
            Self::MissingSectorBitmap { .. } =>
                "A FULLY_PRESENT data block's corresponding sector bitmap slot is in \
                 NOT_PRESENT state. Hyper-V always writes the bitmap alongside data; \
                 this combination indicates direct BAT manipulation after the write.",
            Self::UndefinedBlockState { .. } =>
                "A data BAT entry is in UNDEFINED state (1), which is only valid transiently \
                 during block allocation. Persistent UNDEFINED state indicates an interrupted \
                 write or deliberate BAT manipulation to create unreadable blocks.",
            Self::UnmappedBlockInNonDifferencing { .. } =>
                "A data BAT entry is in UNMAPPED state (3) in a non-differencing disk. \
                 UNMAPPED is only valid in differencing disks; its presence indicates \
                 direct BAT manipulation outside the defined state machine.",
            Self::GhostDataInAbsentBlock { .. } =>
                "A NOT_PRESENT BAT entry's ghost offset points to a file range containing \
                 non-zero bytes. Content was written to the block then the BAT entry was \
                 zeroed without wiping the underlying storage — a data-hiding technique.",
            Self::BatEntryBeyondContainer { .. } =>
                "A FULLY_PRESENT BAT entry's file offset points outside the container. \
                 The declared data block does not exist in this file; reads will fail \
                 or access attacker-controlled memory depending on the parser implementation.",
            Self::BatEntryUnaligned { .. } =>
                "A FULLY_PRESENT BAT entry's file offset is not 1 MB aligned. The \
                 spec mandates MB alignment; a misaligned entry indicates manual patching \
                 of the BAT to redirect a data block to a sub-MB granularity offset.",
            Self::BatEntriesOverlap { .. } =>
                "Two FULLY_PRESENT BAT entries map different logical blocks to the same \
                 physical 1 MB region. The same bytes represent two different logical \
                 blocks — a masquerading technique that makes LBA-to-physical mapping ambiguous.",
            Self::PartiallyPresentBlock { .. } =>
                "A data block BAT entry is in PARTIALLY_PRESENT transient state, which \
                 should never persist in a stable image. Persistence indicates an \
                 interrupted block allocation or deliberate injection of a transient state.",
            Self::SectorBitmapInvalidState { .. } =>
                "A sector bitmap BAT entry has an unexpected state value. The bitmap \
                 slot state must be NOT_PRESENT or FULLY_PRESENT; any other value \
                 indicates direct BAT manipulation of the bitmap tracking structure.",
            Self::TrailingData { .. } =>
                "Non-zero bytes exist between the end of the last BAT-addressed data block \
                 and the physical end of the file. This region is outside the BAT-mapped \
                 address space and invisible to virtual disk parsers — a steganographic \
                 channel for concealing data after the nominal end of the disk image.",
            Self::CreatorStringAnomalous { .. } =>
                "The File Identifier creator string contains an anomaly inconsistent with \
                 legitimate VHDX tools. The creator string is not CRC-protected in older \
                 format versions and is a low-visibility field for tool-fingerprint spoofing.",
            Self::FileIdentifierReservedNonZero { .. } =>
                "Non-zero bytes exist in the reserved area of the File Identifier section \
                 (bytes 512–65535, after the creator string). Normal parsers skip this \
                 area entirely — it is a low-visibility location for data hiding or \
                 steganographic payloads that survive most forensic sanitization tools.",
            Self::InterRegionGapNonZero { .. } =>
                "Non-zero bytes exist in a padding gap between two adjacent structural \
                 regions. Hyper-V zeros these gaps at creation; non-zero content indicates \
                 data hiding or a partial-write artifact from an abnormal shutdown.",
            Self::HeaderReservedNonZero { .. } =>
                "Non-zero bytes exist in the reserved portion of a valid header copy. \
                 These bytes are CRC-protected but not semantically defined — an attacker \
                 can write arbitrary data there and update the CRC to produce a structurally \
                 valid header that carries hidden content undetected by integrity checkers.",
        }
    }

    /// MITRE ATT&CK technique IDs associated with this anomaly.
    ///
    /// Returns an empty slice for anomalies with no established ATT&CK mapping
    /// (e.g. pure structural corruption that has no deception intent).
    pub fn mitre_techniques(&self) -> &'static [&'static str] {
        match self {
            Self::TrailingData { .. } | Self::GhostDataInAbsentBlock { .. } =>
                &["T1564.001"],
            Self::FileIdentifierReservedNonZero { .. }
            | Self::HeaderReservedNonZero { .. }
            | Self::BatEntryInStructuralRegion { .. } =>
                &["T1027"],
            Self::LogSequenceNumberGap { .. }
            | Self::FileWriteGuidAllZeros
            | Self::DataWriteGuidAllZeros
            | Self::LogZeroedButDirty { .. } =>
                &["T1070"],
            Self::LogEntryGuidMismatch { .. } => &["T1070.003"],
            Self::BatEntriesOverlap { .. } => &["T1036"],
            Self::VirtualDiskSizeUnderreported { .. } => &["T1564"],
            Self::InterRegionGapNonZero { .. } => &["T1564.001"],
            _ => &[],
        }
    }
}

/// Aggregated counts from a slice of anomalies.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisSummary {
    pub total: usize,
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
    /// The highest severity present, or `None` if the input was empty.
    pub highest: Option<Severity>,
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

    /// Aggregate anomaly counts from a slice.
    pub fn summary(anomalies: &[VhdxIntegrityAnomaly]) -> AnalysisSummary {
        let mut s = AnalysisSummary {
            total: 0,
            critical: 0,
            error: 0,
            warning: 0,
            info: 0,
            highest: None,
        };
        for a in anomalies {
            s.total += 1;
            let sev = a.severity();
            match sev {
                Severity::Critical => s.critical += 1,
                Severity::Error => s.error += 1,
                Severity::Warning => s.warning += 1,
                Severity::Info => s.info += 1,
            }
            s.highest = Some(match s.highest.take() {
                None => sev,
                Some(h) => h.max(sev),
            });
        }
        s
    }

    /// Run all integrity checks and return the complete list of findings.
    /// Returns an empty `Vec` for a structurally sound image.
    pub fn analyse(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();

        // Layer 1: container-level checks (fast gate).
        issues.extend(self.check_file_magic());
        if issues.iter().any(|a| a.severity() == Severity::Critical) {
            return issues;
        }

        // Layer 1.5: File Identifier reserved area + inter-region gaps (Phase 7).
        issues.extend(self.check_file_identifier_reserved());
        issues.extend(self.check_inter_region_gaps());

        // Layer 2: header CRC + semantic checks.
        issues.extend(self.check_headers());

        // Layer 3: region table CRC + copy-consistency checks.
        issues.extend(self.check_region_tables());

        // Layers 4+ require the region tables to be readable.
        if issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::BothRegionTableCopiesInvalid))
        {
            return issues;
        }

        // Layer 3.5: region layout checks (Phase 3).
        issues.extend(self.check_region_layout());

        // Layer 3.6: log entry analysis (Phase 4) — only when a dirty log was found.
        if issues
            .iter()
            .any(|a| matches!(a, VhdxIntegrityAnomaly::DirtyLog { .. }))
        {
            issues.extend(self.check_log());
        }

        // Parse all region + metadata state in one pass; thread through remaining layers.
        let regions = self.parse_regions();
        let rr = regions.as_ref();

        // Layer 4: metadata field validation (not CRC-protected).
        issues.extend(self.check_metadata_inner(rr));

        // Layer 5: BAT entry validation (not CRC-protected).
        issues.extend(self.check_bat_inner(rr));

        // Layer 6: trailing data scan.
        issues.extend(self.check_trailing_data_inner(rr));

        issues
    }

    // End of the header section (all structural blocks must be below this).
    const LOG_RESERVED_ZONE_END: u64 = 0x0005_0000; // 320 KB

    // ── Public check functions ────────────────────────────────────────────────

    pub fn check_file_magic(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        if (self.data.len() as u64) < MIN_CONTAINER_SIZE {
            issues.push(VhdxIntegrityAnomaly::ContainerTruncated {
                size: self.data.len() as u64,
                minimum: MIN_CONTAINER_SIZE,
            });
            return issues;
        }
        if &self.data[0..8] != FILE_MAGIC {
            let mut found = [0u8; 8];
            found.copy_from_slice(&self.data[0..8]);
            issues.push(VhdxIntegrityAnomaly::BadMagic { found });
        }
        issues
    }

    pub fn check_headers(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();

        let h1_bad = self.check_single_header_crc(1);
        let h2_bad = self.check_single_header_crc(2);
        let (h1_ok, h2_ok) = (h1_bad.is_none(), h2_bad.is_none());

        match (h1_bad, h2_bad) {
            (Some(_), Some(_)) => {
                issues.push(VhdxIntegrityAnomaly::BothHeaderCopiesInvalid);
                return issues;
            }
            (Some(a), None) => issues.push(a),
            (None, Some(a)) => issues.push(a),
            (None, None) => {}
        }

        if h1_ok && h2_ok {
            issues.extend(self.check_header_pair());
        }

        // 7C: Reserved bytes [80..4096] in each CRC-valid header copy.
        for (copy, ok, off) in [
            (1u8, h1_ok, HEADER1_OFFSET as usize),
            (2u8, h2_ok, HEADER2_OFFSET as usize),
        ] {
            if ok && self.data.len() >= off + HEADER_SIZE {
                let header_reserved = &self.data[off + 80..off + HEADER_SIZE];
                if header_reserved.iter().any(|&b| b != 0) {
                    let first_nonzero = header_reserved
                        .iter()
                        .position(|&b| b != 0)
                        .unwrap_or(0) as u16;
                    let length = header_reserved.iter().filter(|&&b| b != 0).count() as u16;
                    issues.push(VhdxIntegrityAnomaly::HeaderReservedNonZero {
                        copy,
                        offset_in_header: 80 + first_nonzero,
                        length,
                    });
                }
            }
        }

        // Phase 2 + DirtyLog checks on the active (highest-seq) header.
        if let Some(active) = self.active_header_block() {
            // 2A: GUID validity.
            if active[16..32].iter().all(|&b| b == 0) {
                issues.push(VhdxIntegrityAnomaly::FileWriteGuidAllZeros);
            }
            if active[32..48].iter().all(|&b| b == 0) {
                issues.push(VhdxIntegrityAnomaly::DataWriteGuidAllZeros);
            }
            let log_guid: [u8; 16] = active[48..64].try_into().unwrap();
            let log_length = u32::from_le_bytes(active[68..72].try_into().unwrap());
            let log_offset = u64::from_le_bytes(active[72..80].try_into().unwrap());
            let log_guid_zero = log_guid == [0u8; 16];
            if !log_guid_zero && log_length == 0 {
                issues.push(VhdxIntegrityAnomaly::LogGuidWithNoLog { log_guid });
            }
            if log_guid_zero && log_length > 0 {
                issues.push(VhdxIntegrityAnomaly::LogGuidAllZerosWithDirtyLog { log_length });
            }

            // 2B: Version fields.
            let log_version = u16::from_le_bytes(active[64..66].try_into().unwrap());
            if log_version != 1 {
                issues.push(VhdxIntegrityAnomaly::LogVersionInvalid { version: log_version });
            }
            let version = u16::from_le_bytes(active[66..68].try_into().unwrap());
            if version != 1 {
                issues.push(VhdxIntegrityAnomaly::VersionInvalid { version });
            }

            // 2C: Log alignment/range (only when log is active).
            if log_length > 0 {
                if log_offset % 0x0010_0000 != 0 {
                    issues.push(VhdxIntegrityAnomaly::LogOffsetMisaligned { log_offset });
                }
                if log_length % 0x0010_0000 != 0 {
                    issues.push(VhdxIntegrityAnomaly::LogLengthMisaligned { log_length });
                }
                if log_offset.saturating_add(u64::from(log_length)) > self.data.len() as u64 {
                    issues.push(VhdxIntegrityAnomaly::LogBeyondContainer {
                        log_offset,
                        log_length,
                        container_size: self.data.len() as u64,
                    });
                }
                if log_offset < 0x0010_0000 {
                    issues.push(VhdxIntegrityAnomaly::LogInReservedZone { log_offset });
                }
                issues.push(VhdxIntegrityAnomaly::DirtyLog { log_length, log_offset });
            }
        }

        issues
    }

    pub fn check_region_tables(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();

        let rt1_bad = self.check_single_rt_crc(1);
        let rt2_bad = self.check_single_rt_crc(2);
        let (rt1_ok, rt2_ok) = (rt1_bad.is_none(), rt2_bad.is_none());

        match (rt1_bad, rt2_bad) {
            (Some(_), Some(_)) => {
                issues.push(VhdxIntegrityAnomaly::BothRegionTableCopiesInvalid);
                return issues;
            }
            (Some(a), None) => issues.push(a),
            (None, Some(a)) => issues.push(a),
            (None, None) => {}
        }

        if rt1_ok && rt2_ok {
            issues.extend(self.check_region_table_pair());
        }

        issues
    }

    /// Check the File Identifier reserved area (bytes 512–65535) for non-zero content.
    pub fn check_file_identifier_reserved(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        // File Identifier section is bytes 0..0x100000; reserved area is 512..65536.
        const RESERVED_START: usize = 512;
        const RESERVED_END: usize = 65536;
        if self.data.len() < RESERVED_END {
            return issues;
        }
        let reserved = &self.data[RESERVED_START..RESERVED_END];
        let first_nonzero = reserved.iter().position(|&b| b != 0);
        if let Some(pos) = first_nonzero {
            let start_offset = (RESERVED_START + pos) as u64;
            let nonzero_count =
                reserved[pos..].iter().filter(|&&b| b != 0).count() as u64;
            issues.push(VhdxIntegrityAnomaly::FileIdentifierReservedNonZero {
                start_offset,
                nonzero_count,
            });
        }
        issues
    }

    /// Check for non-zero bytes in the padding gaps between fixed structural regions.
    pub fn check_inter_region_gaps(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        if self.data.len() < 0x0010_0000 {
            return issues;
        }

        // Fixed structural gaps (VHDX spec §2.1):
        //   Each block occupies a 64 KB slot within the first 1 MB.
        //   Headers are 4 KB; the remaining 60 KB of each header slot must be zero.
        //   Region tables consume the full 64 KB slot (CRC covers the whole block).
        //   RT1 and RT2 are adjacent — no gap between them.
        //   Bytes [0x50000..0x100000] (reserved padding to 1 MB boundary) must be zero.
        let h1 = HEADER1_OFFSET as usize;
        let h2 = HEADER2_OFFSET as usize;
        let rt1 = REGION_TABLE1_OFFSET as usize;
        let rt2 = REGION_TABLE2_OFFSET as usize;
        let fixed_gaps: &[(&'static str, &'static str, usize, usize)] = &[
            ("Header1",      "Header2",      h1 + HEADER_SIZE, h2),
            ("Header2",      "RegionTable1", h2 + HEADER_SIZE, rt1),
            ("RegionTable2", "DataArea",     rt2 + REGION_TABLE_CRC_COVERAGE, 0x0010_0000),
        ];
        for &(from, to, gap_start, gap_end) in fixed_gaps {
            if self.data.len() < gap_end {
                break;
            }
            let gap = &self.data[gap_start..gap_end];
            if gap.iter().any(|&b| b != 0) {
                issues.push(VhdxIntegrityAnomaly::InterRegionGapNonZero {
                    from_region: from,
                    to_region: to,
                    gap_offset: gap_start as u64,
                    gap_size: (gap_end - gap_start) as u64,
                });
            }
        }
        issues
    }

    /// Analyse log entries for structural anomalies. Called only when a dirty
    /// log was detected (LogLength > 0 in the active header).
    pub fn check_log(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        let active = match self.active_header_block() {
            Some(h) => h,
            None => return issues,
        };
        let log_length = u32::from_le_bytes(active[68..72].try_into().unwrap());
        let log_offset = u64::from_le_bytes(active[72..80].try_into().unwrap());
        let header_log_guid: [u8; 16] = active[48..64].try_into().unwrap();
        if log_length == 0 {
            return issues;
        }
        // Per MS-VHDX spec §2.1: log_guid=0 means no valid log entries — skip entry scan.
        if header_log_guid == [0u8; 16] {
            return issues;
        }
        let log_start = log_offset as usize;
        let log_end = log_start.saturating_add(log_length as usize);
        if self.data.len() < log_end {
            return issues; // already caught by LogBeyondContainer
        }
        let log_data = &self.data[log_start..log_end];

        if log_data.iter().all(|&b| b == 0) {
            issues.push(VhdxIntegrityAnomaly::LogZeroedButDirty {
                log_offset,
                log_length,
            });
            return issues;
        }

        let mut pos: usize = 0;
        let mut prev_seq: Option<u64> = None;
        while pos + 64 <= log_data.len() {
            let entry_offset = log_offset + pos as u64;
            let entry = &log_data[pos..];

            if &entry[0..4] != b"loge" {
                issues.push(VhdxIntegrityAnomaly::LogEntrySignatureMissing { entry_offset });
                break;
            }

            let entry_length = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as usize;
            if entry_length < 64 || pos + entry_length > log_data.len() {
                break;
            }

            let stored_crc = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            let mut entry_buf = log_data[pos..pos + entry_length].to_vec();
            entry_buf[4..8].fill(0);
            let computed_crc = crc32c(&entry_buf);
            if computed_crc != stored_crc {
                issues.push(VhdxIntegrityAnomaly::LogEntryCrcMismatch {
                    entry_offset,
                    computed: computed_crc,
                    stored: stored_crc,
                });
                pos += entry_length;
                continue;
            }

            let entry_guid: [u8; 16] = entry[32..48].try_into().unwrap();
            if entry_guid != header_log_guid {
                issues.push(VhdxIntegrityAnomaly::LogEntryGuidMismatch {
                    entry_offset,
                    entry_guid,
                    header_guid: header_log_guid,
                });
            }

            let seq = u64::from_le_bytes(entry[16..24].try_into().unwrap());
            if let Some(prev) = prev_seq {
                if seq != prev.wrapping_add(1) {
                    issues.push(VhdxIntegrityAnomaly::LogSequenceNumberGap {
                        at_offset: entry_offset,
                        expected_seq: prev.wrapping_add(1),
                        found_seq: seq,
                    });
                }
            }
            prev_seq = Some(seq);
            pos += entry_length;
        }

        issues
    }

    /// Check region entry alignment, range, overlap, reserved fields, and
    /// unknown required entries. Called after CRC validity is confirmed.
    pub fn check_region_layout(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();

        // Use the first CRC-valid RT copy for entry scanning.
        let rt_info = [(REGION_TABLE1_OFFSET as usize, 1u8), (REGION_TABLE2_OFFSET as usize, 2u8)];
        let (rt_off, copy) = match rt_info
            .iter()
            .find(|&&(_, c)| self.check_single_rt_crc(c).is_none())
        {
            Some(&x) => x,
            None => return issues,
        };
        let rt = &self.data[rt_off..rt_off + REGION_TABLE_CRC_COVERAGE];
        let container_size = self.data.len() as u64;

        // 3D: Reserved bytes 12–15 of RT header.
        let header_reserved = u32::from_le_bytes(rt[12..16].try_into().unwrap());
        if header_reserved != 0 {
            issues.push(VhdxIntegrityAnomaly::RegionTableReservedNonZero {
                copy,
                location: "header",
                value: header_reserved,
            });
        }

        let entry_count =
            (u32::from_le_bytes(rt[8..12].try_into().unwrap()) as usize).min(2048);
        let mut known: Vec<(&'static str, u64, u64)> = Vec::new(); // (name, start, end)

        for i in 0..entry_count {
            let base = 16 + i * REGION_ENTRY_SIZE;
            if base + REGION_ENTRY_SIZE > rt.len() {
                break;
            }
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&rt[base..base + 16]);
            let file_offset =
                u64::from_le_bytes(rt[base + 16..base + 24].try_into().unwrap());
            let length = u32::from_le_bytes(rt[base + 24..base + 28].try_into().unwrap());
            let required_field =
                u32::from_le_bytes(rt[base + 28..base + 32].try_into().unwrap());

            // 3D: Reserved bits 1–31 of the Required word.
            let reserved_bits = required_field & !1u32;
            if reserved_bits != 0 {
                issues.push(VhdxIntegrityAnomaly::RegionTableReservedNonZero {
                    copy,
                    location: "entry",
                    value: reserved_bits,
                });
            }

            let region_name: &'static str = if guid == BAT_GUID {
                "BAT"
            } else if guid == METADATA_GUID {
                "Metadata"
            } else {
                // 3C: Unknown required region.
                if required_field & 1 != 0 {
                    let guid_hex: String =
                        guid.iter().map(|b| format!("{b:02x}")).collect();
                    issues.push(VhdxIntegrityAnomaly::UnknownRequiredRegion { guid_hex });
                }
                continue;
            };

            // 3A: 1 MB alignment.
            if file_offset % 0x0010_0000 != 0 {
                issues.push(VhdxIntegrityAnomaly::RegionMisaligned {
                    region: region_name,
                    file_offset,
                });
            }

            // 3A: Range within container.
            let declared_end = file_offset.saturating_add(u64::from(length));
            if declared_end > container_size {
                issues.push(VhdxIntegrityAnomaly::RegionBeyondContainer {
                    region: region_name,
                    declared_end,
                    container_size,
                });
            }

            known.push((region_name, file_offset, declared_end));
        }

        // 3B: Pairwise overlap between known (BAT/Metadata) regions.
        for i in 0..known.len() {
            for j in (i + 1)..known.len() {
                let (name_a, start_a, end_a) = known[i];
                let (name_b, start_b, end_b) = known[j];
                let overlap_start = start_a.max(start_b);
                let overlap_end = end_a.min(end_b);
                if overlap_start < overlap_end {
                    issues.push(VhdxIntegrityAnomaly::RegionsOverlap {
                        region_a: name_a,
                        region_b: name_b,
                        overlap_offset: overlap_start,
                    });
                }
            }
        }

        // 3B: Log vs structural zone overlap.
        if let Some(active) = self.active_header_block() {
            let log_length = u32::from_le_bytes(active[68..72].try_into().unwrap());
            let log_offset = u64::from_le_bytes(active[72..80].try_into().unwrap());
            if log_length > 0 {
                let log_end = log_offset.saturating_add(u64::from(log_length));
                let structural: &[(&'static str, u64, u64)] = &[
                    ("FileIdentifier", 0x0000_0000, 0x0001_0000),
                    ("Header1",        0x0001_0000, 0x0002_0000),
                    ("Header2",        0x0002_0000, 0x0003_0000),
                    ("RegionTable1",   0x0003_0000, 0x0004_0000),
                    ("RegionTable2",   0x0004_0000, Self::LOG_RESERVED_ZONE_END),
                ];
                for &(name, s_start, s_end) in structural {
                    if log_offset.max(s_start) < log_end.min(s_end) {
                        issues.push(VhdxIntegrityAnomaly::LogOverlapsStructuralRegion {
                            log_offset,
                            overlapping: name,
                        });
                    }
                }
            }
        }

        issues
    }

    /// Validate metadata fields.
    pub fn check_metadata(&self) -> Vec<VhdxIntegrityAnomaly> {
        self.check_metadata_inner(self.parse_regions().as_ref())
    }

    /// Validate BAT entries.
    pub fn check_bat(&self) -> Vec<VhdxIntegrityAnomaly> {
        self.check_bat_inner(self.parse_regions().as_ref())
    }

    /// Opt-in ghost data scan: find NOT_PRESENT BAT entries whose upper bits
    /// (retained file offset from a prior FULLY_PRESENT state) point to
    /// physical file ranges that contain non-zero bytes. Not called by
    /// `analyse()` — this check is expensive (scans physical blocks).
    pub fn check_bat_ghost_data(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        let r = match self.parse_regions() {
            Some(r) => r,
            None => return issues,
        };
        let bs = match r.block_size {
            Some(bs) if bs > 0 => u64::from(bs),
            _ => return issues,
        };
        let bat_len = r.bat_length as usize;
        let entry_count = bat_len / 8;
        let container_size = self.data.len() as u64;

        for i in 0..entry_count {
            let ep = bat_entry_pos(r.bat_offset, i);
            if ep + 8 > self.data.len() {
                break;
            }
            let raw = r64(self.data, ep);
            let state = (raw & 0b111) as u8;
            // Skip FULLY_PRESENT and sector bitmap slots.
            if state == PAYLOAD_BLOCK_FULLY_PRESENT {
                continue;
            }
            if r.chunk_ratio.is_some_and(|cr| (i as u64 % (cr + 1)) == cr) {
                continue;
            }
            let offset_mb = raw >> 20;
            if offset_mb == 0 {
                continue; // no ghost offset retained
            }
            let file_offset = offset_mb * 0x0010_0000;
            if file_offset >= container_size {
                continue;
            }
            let block_end = file_offset.saturating_add(bs).min(container_size);
            let nonzero_bytes = self.data[file_offset as usize..block_end as usize]
                .iter()
                .filter(|&&b| b != 0)
                .count() as u64;
            if nonzero_bytes > 0 {
                issues.push(VhdxIntegrityAnomaly::GhostDataInAbsentBlock {
                    bat_index: i,
                    file_offset,
                    nonzero_bytes,
                });
            }
        }
        issues
    }

    /// Detect trailing non-zero data.
    pub fn check_trailing_data(&self) -> Vec<VhdxIntegrityAnomaly> {
        self.check_trailing_data_inner(self.parse_regions().as_ref())
    }

    /// Return the file offset of the BAT region, or `None` if unreadable.
    /// Used by the repair module to locate BAT entries.
    pub fn bat_region_offset(&self) -> Option<u64> {
        self.parse_regions().map(|r| r.bat_offset)
    }

    // ── Private: ParsedRegions ────────────────────────────────────────────────

    /// Parse region table + metadata in one pass. Returns None only if no valid
    /// region table can be found.
    fn parse_regions(&self) -> Option<ParsedRegions> {
        for rt_off in [REGION_TABLE1_OFFSET as usize, REGION_TABLE2_OFFSET as usize] {
            if let Some(r) = self.try_parse_regions(rt_off) {
                return Some(r);
            }
        }
        None
    }

    fn try_parse_regions(&self, rt_off: usize) -> Option<ParsedRegions> {
        if self.data.len() < rt_off + REGION_TABLE_CRC_COVERAGE {
            return None;
        }
        let rt = &self.data[rt_off..rt_off + REGION_TABLE_CRC_COVERAGE];
        if &rt[0..4] != REGION_TABLE_SIGNATURE {
            return None;
        }
        let stored = u32::from_le_bytes(rt[4..8].try_into().unwrap());
        let mut buf = rt.to_vec();
        buf[4..8].fill(0);
        if crc32c(&buf) != stored {
            return None;
        }
        let entry_count =
            (u32::from_le_bytes(rt[8..12].try_into().unwrap()) as usize).min(2048);
        let mut bat: Option<(u64, u32)> = None;
        let mut meta: Option<(u64, u32)> = None;
        for i in 0..entry_count {
            let base = 16usize.checked_add(i.checked_mul(REGION_ENTRY_SIZE)?)?;
            if base + REGION_ENTRY_SIZE > rt.len() {
                break;
            }
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&rt[base..base + 16]);
            let off = u64::from_le_bytes(rt[base + 16..base + 24].try_into().unwrap());
            let len = u32::from_le_bytes(rt[base + 24..base + 28].try_into().unwrap());
            if guid == BAT_GUID {
                bat = Some((off, len));
            } else if guid == METADATA_GUID {
                meta = Some((off, len));
            }
        }
        let (bat_offset, bat_length) = bat?;
        let (meta_offset, meta_length) = meta?;

        // Parse metadata items in one pass.
        let mut block_size: Option<u32> = None;
        let mut logical_ss: Option<u32> = None;
        let mut vdisk_size: Option<u64> = None;
        let mut has_parent = false;
        let mut leave_alloc = false;
        let mut physical_ss: Option<u32> = None;
        let mut vdisk_id: Option<[u8; 16]> = None;
        let mut has_parent_locator = false;

        let meta_start = meta_offset as usize;
        let meta_table_end = meta_start.saturating_add(meta_length as usize);
        if self.data.len() >= meta_table_end && meta_length >= 8 {
            let region = &self.data[meta_start..meta_table_end];
            if &region[..8] == METADATA_TABLE_SIGNATURE {
                let count =
                    u16::from_le_bytes(region[10..12].try_into().unwrap()) as usize;
                for i in 0..count.min(256) {
                    let base = 32usize.checked_add(i.checked_mul(32)?)?;
                    if base + 32 > region.len() {
                        break;
                    }
                    let mut guid = [0u8; 16];
                    guid.copy_from_slice(&region[base..base + 16]);
                    let item_off = u32::from_le_bytes(
                        region[base + 16..base + 20].try_into().unwrap(),
                    ) as usize;
                    // Offset is from the start of the metadata region (MS-VHDX §3.3.2).
                    let data_start = meta_start.checked_add(item_off)?;
                    if guid == GUID_FILE_PARAMETERS && self.data.len() >= data_start + 8 {
                        block_size = Some(u32::from_le_bytes(
                            self.data[data_start..data_start + 4].try_into().unwrap(),
                        ));
                        let flags = u32::from_le_bytes(
                            self.data[data_start + 4..data_start + 8].try_into().unwrap(),
                        );
                        leave_alloc = flags & 1 != 0;
                        has_parent = flags & 2 != 0;
                    } else if guid == GUID_VIRTUAL_DISK_SIZE
                        && self.data.len() >= data_start + 8
                    {
                        vdisk_size = Some(u64::from_le_bytes(
                            self.data[data_start..data_start + 8].try_into().unwrap(),
                        ));
                    } else if guid == GUID_LOGICAL_SECTOR_SIZE
                        && self.data.len() >= data_start + 4
                    {
                        logical_ss = Some(u32::from_le_bytes(
                            self.data[data_start..data_start + 4].try_into().unwrap(),
                        ));
                    } else if guid == GUID_PHYSICAL_SECTOR_SIZE
                        && self.data.len() >= data_start + 4
                    {
                        physical_ss = Some(u32::from_le_bytes(
                            self.data[data_start..data_start + 4].try_into().unwrap(),
                        ));
                    } else if guid == GUID_VIRTUAL_DISK_ID
                        && self.data.len() >= data_start + 16
                    {
                        let mut id = [0u8; 16];
                        id.copy_from_slice(&self.data[data_start..data_start + 16]);
                        vdisk_id = Some(id);
                    } else if guid == GUID_PARENT_LOCATOR {
                        has_parent_locator = true;
                    }
                }
            }
        }

        let chunk_ratio = match (block_size, logical_ss) {
            (Some(bs), Some(ss)) if bs > 0 && ss > 0 => {
                Some((1u64 << 23) * u64::from(ss) / u64::from(bs))
            }
            (Some(bs), None) if bs > 0 => Some((1u64 << 23) * 512 / u64::from(bs)),
            _ => None,
        };

        Some(ParsedRegions {
            bat_offset,
            bat_length,
            meta_offset,
            meta_length,
            block_size,
            logical_ss,
            vdisk_size,
            chunk_ratio,
            has_parent,
            leave_alloc,
            physical_ss,
            vdisk_id,
            has_parent_locator,
        })
    }

    // ── Private: layer check implementations ─────────────────────────────────

    fn check_metadata_inner(
        &self,
        regions: Option<&ParsedRegions>,
    ) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        let r = match regions {
            Some(r) => r,
            None => return issues,
        };

        if r.has_parent {
            issues.push(VhdxIntegrityAnomaly::DifferencingDisk);
            if !r.has_parent_locator {
                issues.push(VhdxIntegrityAnomaly::MissingParentLocator);
            }
        }

        if r.leave_alloc && !r.has_parent {
            issues.push(VhdxIntegrityAnomaly::LeaveBlocksAllocatedSet);
        }

        if let Some(ps) = r.physical_ss {
            if ps != 512 && ps != 4096 {
                issues.push(VhdxIntegrityAnomaly::PhysicalSectorSizeInvalid { sector_size: ps });
            }
        }

        if let Some(vid) = r.vdisk_id {
            if vid == [0u8; 16] {
                issues.push(VhdxIntegrityAnomaly::VirtualDiskIdAllZeros);
            }
        }

        // Scan metadata item entries for overlap and out-of-range conditions.
        let meta_start = r.meta_offset as usize;
        let meta_end = meta_start.saturating_add(r.meta_length as usize);
        if self.data.len() >= meta_end && r.meta_length >= 8 {
            let region = &self.data[meta_start..meta_end];
            // Item offsets in table entries are from the start of the metadata region (§3.3.2).
            let region_size = r.meta_length as usize;
            if &region[..8] == METADATA_TABLE_SIGNATURE {
                let count =
                    u16::from_le_bytes(region[10..12].try_into().unwrap()) as usize;
                let mut item_ranges: Vec<(u32, u32)> = Vec::new(); // (item_offset, item_end)

                for i in 0..count.min(2048) {
                    let base = 32usize.saturating_add(i.saturating_mul(32));
                    if base + 32 > region.len() {
                        break;
                    }
                    let item_off = u32::from_le_bytes(
                        region[base + 16..base + 20].try_into().unwrap(),
                    );
                    let item_len = u32::from_le_bytes(
                        region[base + 20..base + 24].try_into().unwrap(),
                    );
                    let item_end = item_off.saturating_add(item_len);

                    // Check: item data extends past end of metadata region.
                    if item_end as usize > region_size {
                        issues.push(VhdxIntegrityAnomaly::MetadataItemBeyondRegion {
                            item_offset: item_off,
                            item_end,
                            region_end: region_size as u32,
                        });
                    }

                    // Collect for overlap check.
                    item_ranges.push((item_off, item_end));
                }

                // Pairwise overlap check (O(n²) but n ≤ 2048 and metadata tables are tiny).
                item_ranges.sort_unstable_by_key(|&(off, _)| off);
                for w in item_ranges.windows(2) {
                    let (a_off, a_end) = w[0];
                    let (b_off, b_end) = w[1];
                    if b_off < a_end && b_end > a_off {
                        let overlap_offset = a_off.max(b_off);
                        issues.push(VhdxIntegrityAnomaly::MetadataItemsOverlap {
                            item_a_offset: a_off,
                            item_b_offset: b_off,
                            overlap_offset,
                        });
                    }
                }
            }
        }

        match r.block_size {
            None => issues.push(VhdxIntegrityAnomaly::MetadataMissing("BlockSize")),
            Some(bs) => {
                if bs == 0 || bs < BLOCK_SIZE_MIN || bs > BLOCK_SIZE_MAX {
                    issues.push(VhdxIntegrityAnomaly::BlockSizeInvalid {
                        block_size: bs,
                        reason: "outside spec range [1 MB, 256 MB]",
                    });
                } else if bs.count_ones() != 1 {
                    issues.push(VhdxIntegrityAnomaly::BlockSizeInvalid {
                        block_size: bs,
                        reason: "not a power of two",
                    });
                }
            }
        }

        if let Some(ss) = r.logical_ss {
            if ss != 512 && ss != 4096 {
                issues.push(VhdxIntegrityAnomaly::LogicalSectorSizeInvalid { sector_size: ss });
            }
        }

        match r.vdisk_size {
            None => issues.push(VhdxIntegrityAnomaly::MetadataMissing("VirtualDiskSize")),
            Some(0) => issues.push(VhdxIntegrityAnomaly::VirtualDiskSizeInvalid {
                vdisk_size: 0,
                reason: "zero",
            }),
            Some(vds) => {
                const VDS_MAX: u64 = 64 * (1u64 << 40);
                if vds > VDS_MAX {
                    issues.push(VhdxIntegrityAnomaly::VirtualDiskSizeInvalid {
                        vdisk_size: vds,
                        reason: "exceeds 64 TiB spec limit",
                    });
                }
                let sector_sz = r.logical_ss.unwrap_or(512);
                if sector_sz > 0 && vds % u64::from(sector_sz) != 0 {
                    issues.push(VhdxIntegrityAnomaly::VirtualDiskSizeInvalid {
                        vdisk_size: vds,
                        reason: "not a multiple of LogicalSectorSize",
                    });
                }
            }
        }

        issues
    }

    fn check_bat_inner(&self, regions: Option<&ParsedRegions>) -> Vec<VhdxIntegrityAnomaly> {
        let r = match regions { Some(r) => r, None => return vec![] };
        let bat_len = r.bat_length as usize;
        let bat_end = (r.bat_offset as usize).saturating_add(bat_len);
        if self.data.len() < bat_end || bat_len < 8 {
            return vec![];
        }
        let entry_count = bat_len / 8;
        let container_size = self.data.len() as u64;

        let mut issues = self.bat_check_size_formula(r, entry_count);
        let (entry_issues, present) = self.bat_scan_entries(r, entry_count, container_size);
        issues.extend(entry_issues);
        issues.extend(Self::bat_check_coverage(r, &present, entry_count));
        issues
    }

    /// 5A — verify BAT physical size matches what VirtualDiskSize + BlockSize imply.
    fn bat_check_size_formula(
        &self,
        r: &ParsedRegions,
        entry_count: usize,
    ) -> Vec<VhdxIntegrityAnomaly> {
        let (Some(bs), Some(vds), Some(cr)) = (r.block_size, r.vdisk_size, r.chunk_ratio)
        else { return vec![] };
        if bs == 0 { return vec![]; }
        let data_blocks = vds.div_ceil(u64::from(bs)) as usize;
        let bat_entries_expected = data_blocks + data_blocks.div_ceil(cr as usize);
        let expected_bat_bytes = ((bat_entries_expected as u64 * 8).next_multiple_of(MB)) as u32;
        if expected_bat_bytes == r.bat_length {
            return vec![];
        }
        vec![VhdxIntegrityAnomaly::BatSizeMetadataMismatch {
            bat_bytes_actual: r.bat_length,
            bat_entries_actual: entry_count,
            bat_entries_expected,
            vdisk_size: vds,
            block_size: bs,
        }]
    }

    /// Per-entry BAT scan: state checks (5B/5C/5D), structural-region redirect,
    /// range, bitmap consistency, and alignment. Also returns sorted present-offset
    /// list for the overlap + coverage checks that follow.
    fn bat_scan_entries(
        &self,
        r: &ParsedRegions,
        entry_count: usize,
        container_size: u64,
    ) -> (Vec<VhdxIntegrityAnomaly>, Vec<(u64, usize)>) {
        let mut issues = Vec::new();
        let mut present: Vec<(u64, usize)> = Vec::new(); // (offset_mb, bat_index)

        // Precompute log zone for structural-region redirect check (5B).
        let log_zone: Option<(u64, u64)> = self.active_header_block().and_then(|h| {
            let ll = r32(h, 68);
            let lo = r64(h, 72);
            if ll > 0 { Some((lo, lo.saturating_add(u64::from(ll)))) } else { None }
        });
        let meta_end = r.meta_offset.saturating_add(u64::from(r.meta_length));

        // Returns the structural zone name for a given file offset, or None.
        let structural_zone = |fo: u64| -> Option<&'static str> {
            if fo < 0x0001_0000 { return Some("FileIdentifier"); }
            if fo < 0x0002_0000 { return Some("Header1"); }
            if fo < 0x0003_0000 { return Some("Header2"); }
            if fo < 0x0004_0000 { return Some("RegionTable1"); }
            if fo < 0x0005_0000 { return Some("RegionTable2"); }
            if fo >= r.meta_offset && fo < meta_end { return Some("Metadata"); }
            if let Some((lo, le)) = log_zone { if fo >= lo && fo < le { return Some("Log"); } }
            None
        };

        for i in 0..entry_count {
            let ep = bat_entry_pos(r.bat_offset, i);
            if ep + 8 > self.data.len() { break; }
            let raw = r64(self.data, ep);
            let state = (raw & 0b111) as u8;

            // Sector bitmap slots use different valid states from data blocks.
            let is_bitmap_slot = r.chunk_ratio.is_some_and(|cr| (i as u64 % (cr + 1)) == cr);
            if is_bitmap_slot {
                if state != SB_BLOCK_NOT_PRESENT && state != SB_BLOCK_PRESENT {
                    issues.push(VhdxIntegrityAnomaly::SectorBitmapInvalidState { bat_index: i, state });
                }
                continue;
            }

            // Data block state checks (5D).
            match state {
                PAYLOAD_BLOCK_PARTIALLY_PRESENT => {
                    issues.push(VhdxIntegrityAnomaly::PartiallyPresentBlock { bat_index: i });
                }
                1 => issues.push(VhdxIntegrityAnomaly::UndefinedBlockState { bat_index: i }),
                3 if !r.has_parent => {
                    issues.push(VhdxIntegrityAnomaly::UnmappedBlockInNonDifferencing { bat_index: i });
                }
                _ => {}
            }
            if state != PAYLOAD_BLOCK_FULLY_PRESENT { continue; }

            let offset_mb  = raw >> 20;
            let file_offset = offset_mb * MB;

            if raw & BAT_RESERVED_BITS_MASK != 0 {
                issues.push(VhdxIntegrityAnomaly::BatEntryUnaligned { bat_index: i, file_offset });
            }
            if let Some(zone) = structural_zone(file_offset) {
                issues.push(VhdxIntegrityAnomaly::BatEntryInStructuralRegion {
                    bat_index: i, file_offset, collides_with: zone,
                });
            }
            if file_offset >= container_size {
                issues.push(VhdxIntegrityAnomaly::BatEntryBeyondContainer {
                    bat_index: i, file_offset, container_size,
                });
                continue;
            }

            // 5C: the sector bitmap slot for this data block must also be PRESENT.
            if let Some(cr) = r.chunk_ratio {
                let cr_us = cr as usize;
                let bitmap_idx = (i / (cr_us + 1)) * (cr_us + 1) + cr_us;
                if bitmap_idx < entry_count {
                    let bep = bat_entry_pos(r.bat_offset, bitmap_idx);
                    if bep + 8 <= self.data.len()
                        && (r64(self.data, bep) & 0b111) as u8 == SB_BLOCK_NOT_PRESENT
                    {
                        issues.push(VhdxIntegrityAnomaly::MissingSectorBitmap {
                            data_bat_index: i, bitmap_bat_index: bitmap_idx,
                        });
                    }
                }
            }

            present.push((offset_mb, i));
        }

        // Sort by file offset to enable O(n) overlap detection.
        present.sort_unstable_by_key(|&(off, _)| off);
        for w in present.windows(2) {
            if w[0].0 == w[1].0 {
                issues.push(VhdxIntegrityAnomaly::BatEntriesOverlap {
                    index_a: w[0].1, index_b: w[1].1, shared_offset: w[0].0 * MB,
                });
            }
        }

        (issues, present)
    }

    /// Cross-coverage checks against declared VirtualDiskSize:
    /// underreported (physical data exceeds declared size) and
    /// overreported (declared size exceeds physical BAT capacity).
    fn bat_check_coverage(
        r: &ParsedRegions,
        present: &[(u64, usize)],
        entry_count: usize,
    ) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        let (Some(bs), Some(declared_vds)) = (r.block_size, r.vdisk_size) else { return issues };
        if bs == 0 { return issues; }

        if !present.is_empty() {
            let max_mb = present.iter().map(|&(off, _)| off).max().unwrap_or(0);
            let bat_coverage = (max_mb + 1) * MB;
            if bat_coverage > declared_vds {
                issues.push(VhdxIntegrityAnomaly::VirtualDiskSizeUnderreported {
                    declared: declared_vds, bat_coverage,
                });
            }
        }

        if let Some(cr) = r.chunk_ratio {
            let max_data_blocks = entry_count as u64 * cr / (cr + 1);
            let bat_coverage = max_data_blocks * u64::from(bs);
            if declared_vds > bat_coverage {
                issues.push(VhdxIntegrityAnomaly::VirtualDiskSizeOverreported {
                    declared: declared_vds, bat_coverage,
                });
            }
        }

        issues
    }

    fn check_trailing_data_inner(
        &self,
        regions: Option<&ParsedRegions>,
    ) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        let r = match regions {
            Some(r) => r,
            None => return issues,
        };

        let block_size = match r.block_size {
            Some(bs) if bs > 0 => u64::from(bs),
            _ => return issues,
        };

        let bat_start = r.bat_offset as usize;
        let bat_len = r.bat_length as usize;
        let entry_count = bat_len / 8;
        let container_size = self.data.len() as u64;

        let mut max_end: u64 = 0;
        for i in 0..entry_count {
            let ep = bat_start + i * 8;
            if ep + 8 > self.data.len() {
                break;
            }
            let raw = u64::from_le_bytes(self.data[ep..ep + 8].try_into().unwrap());
            if (raw & 0b111) as u8 != PAYLOAD_BLOCK_FULLY_PRESENT {
                continue;
            }
            let file_offset = (raw >> 20) * 0x0010_0000;
            let block_end = file_offset.saturating_add(block_size);
            if block_end <= container_size && block_end > max_end {
                max_end = block_end;
            }
        }

        if max_end == 0 {
            let bat_end = r.bat_offset.saturating_add(r.bat_length as u64);
            max_end = bat_end
                .checked_next_multiple_of(0x0010_0000)
                .unwrap_or(u64::MAX);
        }

        if container_size > max_end {
            let trailing_start = max_end as usize;
            let has_nonzero = self.data[trailing_start..].iter().any(|&b| b != 0);
            if has_nonzero {
                issues.push(VhdxIntegrityAnomaly::TrailingData {
                    start_offset: max_end,
                    size: container_size - max_end,
                });
            }
        }

        issues
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn check_single_header_crc(&self, copy: u8) -> Option<VhdxIntegrityAnomaly> {
        let off = if copy == 1 {
            HEADER1_OFFSET as usize
        } else {
            HEADER2_OFFSET as usize
        };
        if self.data.len() < off + HEADER_SIZE {
            return Some(VhdxIntegrityAnomaly::HeaderChecksumMismatch {
                copy,
                computed: 0,
                stored: 0,
            });
        }
        let block = &self.data[off..off + HEADER_SIZE];
        if &block[0..4] != HEADER_SIGNATURE {
            return Some(VhdxIntegrityAnomaly::HeaderChecksumMismatch {
                copy,
                computed: 0,
                stored: 0,
            });
        }
        let stored = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let mut buf = block.to_vec();
        buf[4..8].fill(0);
        let computed = crc32c(&buf);
        if computed != stored {
            Some(VhdxIntegrityAnomaly::HeaderChecksumMismatch {
                copy,
                computed,
                stored,
            })
        } else {
            None
        }
    }

    fn check_single_rt_crc(&self, copy: u8) -> Option<VhdxIntegrityAnomaly> {
        let off = if copy == 1 {
            REGION_TABLE1_OFFSET as usize
        } else {
            REGION_TABLE2_OFFSET as usize
        };
        if self.data.len() < off + REGION_TABLE_CRC_COVERAGE {
            return Some(VhdxIntegrityAnomaly::RegionTableChecksumMismatch {
                copy,
                computed: 0,
                stored: 0,
            });
        }
        let block = &self.data[off..off + REGION_TABLE_CRC_COVERAGE];
        if &block[0..4] != REGION_TABLE_SIGNATURE {
            return Some(VhdxIntegrityAnomaly::RegionTableChecksumMismatch {
                copy,
                computed: 0,
                stored: 0,
            });
        }
        let stored = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let mut buf = block.to_vec();
        buf[4..8].fill(0);
        let computed = crc32c(&buf);
        if computed != stored {
            Some(VhdxIntegrityAnomaly::RegionTableChecksumMismatch {
                copy,
                computed,
                stored,
            })
        } else {
            None
        }
    }

    fn check_header_pair(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        let h1 = &self.data[HEADER1_OFFSET as usize..HEADER1_OFFSET as usize + HEADER_SIZE];
        let h2 = &self.data[HEADER2_OFFSET as usize..HEADER2_OFFSET as usize + HEADER_SIZE];

        let seq1 = u64::from_le_bytes(h1[8..16].try_into().unwrap());
        let seq2 = u64::from_le_bytes(h2[8..16].try_into().unwrap());

        if seq1 == 0 && seq2 == 0 {
            issues.push(VhdxIntegrityAnomaly::BothSequenceNumbersZero);
        } else if seq1 == seq2 {
            issues.push(VhdxIntegrityAnomaly::SequenceNumbersIdentical { value: seq1 });
        } else {
            // 2D: gap > 1 indicates one copy was patched outside a normal write cycle.
            let gap = seq1.abs_diff(seq2);
            if gap > 1 {
                issues.push(VhdxIntegrityAnomaly::SequenceNumberGapLarge { seq1, seq2, gap });
            }
        }

        let log_len1 = u32::from_le_bytes(h1[68..72].try_into().unwrap());
        let log_len2 = u32::from_le_bytes(h2[68..72].try_into().unwrap());
        if log_len1 != log_len2 {
            issues.push(VhdxIntegrityAnomaly::HeaderCopyMismatch {
                field: "LogLength",
                copy1_value: u64::from(log_len1),
                copy2_value: u64::from(log_len2),
            });
        }
        let log_off1 = u64::from_le_bytes(h1[72..80].try_into().unwrap());
        let log_off2 = u64::from_le_bytes(h2[72..80].try_into().unwrap());
        if log_off1 != log_off2 {
            issues.push(VhdxIntegrityAnomaly::HeaderCopyMismatch {
                field: "LogOffset",
                copy1_value: log_off1,
                copy2_value: log_off2,
            });
        }

        issues
    }

    fn check_region_table_pair(&self) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();

        let rt1 = &self.data[REGION_TABLE1_OFFSET as usize
            ..REGION_TABLE1_OFFSET as usize + REGION_TABLE_CRC_COVERAGE];
        let rt2 = &self.data[REGION_TABLE2_OFFSET as usize
            ..REGION_TABLE2_OFFSET as usize + REGION_TABLE_CRC_COVERAGE];

        let count1 = (u32::from_le_bytes(rt1[8..12].try_into().unwrap()) as usize).min(2048);
        let count2 = (u32::from_le_bytes(rt2[8..12].try_into().unwrap()) as usize).min(2048);
        let count = count1.min(count2);

        for i in 0..count {
            let base = 16 + i * REGION_ENTRY_SIZE;
            if base + REGION_ENTRY_SIZE > rt1.len() || base + REGION_ENTRY_SIZE > rt2.len() {
                break;
            }
            let mut guid1 = [0u8; 16];
            guid1.copy_from_slice(&rt1[base..base + 16]);
            let mut guid2 = [0u8; 16];
            guid2.copy_from_slice(&rt2[base..base + 16]);
            if guid1 != guid2 {
                continue;
            }
            let region_name = if guid1 == BAT_GUID {
                "BAT"
            } else if guid1 == METADATA_GUID {
                "Metadata"
            } else {
                continue;
            };

            let off1 = u64::from_le_bytes(rt1[base + 16..base + 24].try_into().unwrap());
            let off2 = u64::from_le_bytes(rt2[base + 16..base + 24].try_into().unwrap());
            if off1 != off2 {
                issues.push(VhdxIntegrityAnomaly::RegionTableCopyMismatch {
                    region: region_name,
                    field: "file_offset",
                    rt1_value: off1,
                    rt2_value: off2,
                });
            }
            let len1 = u32::from_le_bytes(rt1[base + 24..base + 28].try_into().unwrap());
            let len2 = u32::from_le_bytes(rt2[base + 24..base + 28].try_into().unwrap());
            if len1 != len2 {
                issues.push(VhdxIntegrityAnomaly::RegionTableCopyMismatch {
                    region: region_name,
                    field: "length",
                    rt1_value: u64::from(len1),
                    rt2_value: u64::from(len2),
                });
            }
        }

        issues
    }

    fn active_header_block(&self) -> Option<&[u8]> {
        let h1_off = HEADER1_OFFSET as usize;
        let h2_off = HEADER2_OFFSET as usize;
        let h1_ok = self.check_single_header_crc(1).is_none();
        let h2_ok = self.check_single_header_crc(2).is_none();
        match (h1_ok, h2_ok) {
            (true, true) => {
                let seq1 =
                    u64::from_le_bytes(self.data[h1_off + 8..h1_off + 16].try_into().unwrap());
                let seq2 =
                    u64::from_le_bytes(self.data[h2_off + 8..h2_off + 16].try_into().unwrap());
                if seq1 >= seq2 {
                    Some(&self.data[h1_off..h1_off + HEADER_SIZE])
                } else {
                    Some(&self.data[h2_off..h2_off + HEADER_SIZE])
                }
            }
            (true, false) => Some(&self.data[h1_off..h1_off + HEADER_SIZE]),
            (false, true) => Some(&self.data[h2_off..h2_off + HEADER_SIZE]),
            (false, false) => None,
        }
    }
}
