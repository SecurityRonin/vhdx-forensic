use crate::header::{
    crc32c, HEADER1_OFFSET, HEADER2_OFFSET, HEADER_SIGNATURE, HEADER_SIZE, REGION_TABLE1_OFFSET,
    REGION_TABLE2_OFFSET,
};
use crate::metadata::{
    GUID_FILE_PARAMETERS, GUID_LOGICAL_SECTOR_SIZE, GUID_VIRTUAL_DISK_SIZE,
    METADATA_TABLE_SIGNATURE,
};
use crate::region::{BAT_GUID, METADATA_GUID, REGION_ENTRY_SIZE, REGION_TABLE_SIGNATURE};
use crate::FILE_MAGIC;

const MIN_CONTAINER_SIZE: u64 = 0x0025_0000; // 2.5 MB
const REGION_TABLE_CRC_COVERAGE: usize = 65536;

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

// Sentinel for chunk_ratio when it cannot be computed from metadata.
const CHUNK_RATIO_INVALID: u64 = u64::MAX;

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
    /// Computed from block_size/logical_ss; CHUNK_RATIO_INVALID when not computable.
    chunk_ratio: u64,
    has_parent:  bool,
    leave_alloc: bool,
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
    /// File is smaller than the minimum structural size (2.5 MB).
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

    // ── Log section indicators ────────────────────────────────────────────────
    /// The active header declares a non-zero log region, indicating uncommitted
    /// writes were present at image capture time. Log replay is required for a
    /// consistent view but is out of scope for offline forensic analysis.
    DirtyLog { log_length: u32, log_offset: u64 },

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
        let mut issues = Vec::new();

        // Layer 1: container-level checks (fast gate).
        issues.extend(self.check_file_magic());
        if issues.iter().any(|a| a.severity() == Severity::Critical) {
            return issues;
        }

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

        // Check dirty log on the active header (highest sequence number).
        if let Some(active) = self.active_header_block() {
            let log_length = u32::from_le_bytes(active[68..72].try_into().unwrap());
            let log_offset = u64::from_le_bytes(active[72..80].try_into().unwrap());
            if log_length > 0 {
                issues.push(VhdxIntegrityAnomaly::DirtyLog {
                    log_length,
                    log_offset,
                });
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

    /// Validate metadata fields.
    pub fn check_metadata(&self) -> Vec<VhdxIntegrityAnomaly> {
        self.check_metadata_inner(self.parse_regions().as_ref())
    }

    /// Validate BAT entries.
    pub fn check_bat(&self) -> Vec<VhdxIntegrityAnomaly> {
        self.check_bat_inner(self.parse_regions().as_ref())
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

        let meta_start = meta_offset as usize;
        let meta_table_end = meta_start + meta_length as usize;
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
                    let data_start =
                        meta_start.checked_add(0x10000)?.checked_add(item_off)?;
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
                    }
                }
            }
        }

        let chunk_ratio = match (block_size, logical_ss) {
            (Some(bs), Some(ss)) if bs > 0 && ss > 0 => {
                (1u64 << 23) * u64::from(ss) / u64::from(bs)
            }
            (Some(bs), None) if bs > 0 => (1u64 << 23) * 512 / u64::from(bs),
            _ => CHUNK_RATIO_INVALID,
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

    fn check_bat_inner(
        &self,
        regions: Option<&ParsedRegions>,
    ) -> Vec<VhdxIntegrityAnomaly> {
        let mut issues = Vec::new();
        let r = match regions {
            Some(r) => r,
            None => return issues,
        };

        let bat_start = r.bat_offset as usize;
        let bat_len = r.bat_length as usize;
        let bat_end = bat_start.saturating_add(bat_len);
        if self.data.len() < bat_end || bat_len < 8 {
            return issues;
        }

        let container_size = self.data.len() as u64;
        let entry_count = bat_len / 8;
        let chunk_ratio = r.chunk_ratio;

        let mut present: Vec<(u64, usize)> = Vec::new();

        for i in 0..entry_count {
            let entry_pos = bat_start + i * 8;
            let raw =
                u64::from_le_bytes(self.data[entry_pos..entry_pos + 8].try_into().unwrap());
            let state = (raw & 0b111) as u8;
            let is_bitmap_slot = chunk_ratio < CHUNK_RATIO_INVALID
                && (i as u64 % (chunk_ratio + 1)) == chunk_ratio;

            if is_bitmap_slot {
                if state != SB_BLOCK_NOT_PRESENT && state != SB_BLOCK_PRESENT {
                    issues.push(VhdxIntegrityAnomaly::SectorBitmapInvalidState {
                        bat_index: i,
                        state,
                    });
                }
                continue;
            }

            // Data block entry.
            if state == PAYLOAD_BLOCK_PARTIALLY_PRESENT {
                issues.push(VhdxIntegrityAnomaly::PartiallyPresentBlock { bat_index: i });
            }
            if state != PAYLOAD_BLOCK_FULLY_PRESENT {
                continue;
            }

            let offset_mb = raw >> 20;
            let file_offset = offset_mb * 0x0010_0000;

            if raw & 0x000F_FFF8 != 0 {
                issues.push(VhdxIntegrityAnomaly::BatEntryUnaligned {
                    bat_index: i,
                    file_offset,
                });
            }

            if file_offset >= container_size {
                issues.push(VhdxIntegrityAnomaly::BatEntryBeyondContainer {
                    bat_index: i,
                    file_offset,
                    container_size,
                });
                continue;
            }

            present.push((offset_mb, i));
        }

        // Overlap detection.
        present.sort_unstable_by_key(|&(off, _)| off);
        for w in present.windows(2) {
            if w[0].0 == w[1].0 {
                issues.push(VhdxIntegrityAnomaly::BatEntriesOverlap {
                    index_a: w[0].1,
                    index_b: w[1].1,
                    shared_offset: w[0].0 * 0x0010_0000,
                });
            }
        }

        // VirtualDiskSizeUnderreported — highest present offset vs declared size.
        if let (Some(bs), Some(declared_vds)) = (r.block_size, r.vdisk_size) {
            if bs > 0 && !present.is_empty() {
                let max_offset_mb = present.iter().map(|&(off, _)| off).max().unwrap_or(0);
                let bat_coverage = (max_offset_mb + 1) * 0x0010_0000;
                if bat_coverage > declared_vds {
                    issues.push(VhdxIntegrityAnomaly::VirtualDiskSizeUnderreported {
                        declared: declared_vds,
                        bat_coverage,
                    });
                }
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
            max_end = bat_end.next_multiple_of(0x0010_0000);
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
