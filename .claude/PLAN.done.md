# vhdx-forensic: Enhancement Plan

This document captures the full set of planned enhancements following the initial
implementation (19-variant anomaly enum, `VhdxIntegrity`, `VhdxRepair`, 48 passing tests).

The VHDX format has one forensically critical asymmetry: **header + region table sections
are CRC32C-protected** (tampering is detectable), while **metadata fields and BAT entries
are not** (the primary silent-tampering surface). Every enhancement in the unprotected
layers is therefore high forensic value.

---

## Current state

### Anomalies detected (19 variants)

| Variant | Layer | Severity |
|---|---|---|
| `BadMagic` | Container | Critical |
| `ContainerTruncated` | Container | Critical |
| `HeaderChecksumMismatch` | Header CRC | Error |
| `BothHeaderCopiesInvalid` | Header CRC | Critical |
| `SequenceNumbersIdentical` | Header semantics | Warning |
| `BothSequenceNumbersZero` | Header semantics | Warning |
| `HeaderCopyMismatch` (LogLength, LogOffset) | Header semantics | Error |
| `DirtyLog` | Header log field | Info |
| `RegionTableChecksumMismatch` | Region table CRC | Error |
| `BothRegionTableCopiesInvalid` | Region table CRC | Critical |
| `RegionTableCopyMismatch` | Region table semantics | Error |
| `MetadataMissing` | Metadata | Warning |
| `BlockSizeInvalid` | Metadata | Warning |
| `LogicalSectorSizeInvalid` | Metadata | Warning |
| `VirtualDiskSizeInvalid` | Metadata | Warning |
| `VirtualDiskSizeUnderreported` | Metadata vs BAT | Error |
| `DifferencingDisk` | Metadata | Warning |
| `BatEntryBeyondContainer` | BAT | Error |
| `BatEntryUnaligned` | BAT | Warning |
| `BatEntriesOverlap` | BAT | Error |
| `PartiallyPresentBlock` | BAT | Warning |
| `SectorBitmapInvalidState` | BAT | Warning |
| `TrailingData` | Layout | Warning |
| `CreatorStringAnomalous` | File Identifier | Warning |

### Repairs implemented

| Repair | Condition |
|---|---|
| Copy H2 → H1 (recompute CRC) | `HeaderChecksumMismatch { copy: 1 }` |
| Copy H1 → H2 (recompute CRC) | `HeaderChecksumMismatch { copy: 2 }` |
| Copy RT2 → RT1 (recompute CRC) | `RegionTableChecksumMismatch { copy: 1 }` |
| Copy RT1 → RT2 (recompute CRC) | `RegionTableChecksumMismatch { copy: 2 }` |
| Zero BAT entry to NOT_PRESENT | `BatEntryBeyondContainer` |

### Key structural gap

`analyse()` currently invokes `region_locations()`, `bat_region_length()`,
`raw_block_size()`, and `chunk_ratio()` as independent functions, each of which
re-parses the region table from raw bytes. This precludes cross-layer consistency
checks and is the first thing to fix.

---

## Phase 1 — `ParsedRegions` internal refactor (prerequisite)

**Scope:** internal refactor only — no API change, no new anomaly variants.  
**Files modified:** `src/integrity.rs`

Extract a private `ParsedRegions` struct that holds all region-level data derived
from one pass over a valid region table:

```rust
struct ParsedRegions {
    bat_offset:       u64,
    bat_length:       u32,
    meta_offset:      u64,
    meta_length:      u32,
    block_size:       u32,   // from metadata FileParameters
    logical_ss:       u32,   // from metadata LogicalSectorSize
    physical_ss:      u32,   // from metadata PhysicalSectorSize
    vdisk_size:       u64,   // from metadata VirtualDiskSize
    chunk_ratio:      u64,   // computed
    has_parent:       bool,
    leave_alloc:      bool,
    vdisk_id:         [u8; 16],
}
```

Replace the four independent helper functions with a single `parse_regions()` that
returns `Option<ParsedRegions>`. Thread this through `check_metadata()`,
`check_bat()`, `check_trailing_data()`, and all new check functions added in later
phases.

**Why this comes first:** Phases 2–7 all need cross-layer data (e.g. BAT formula
validation needs both the BAT region length from the region table and VirtualDiskSize
from metadata). Without a shared parsed state, each check would re-parse everything
independently.

**TDD plan — Phase 1:**

All existing tests must remain green after this refactor. No new tests are needed
(the refactor is purely internal). Run the full test suite to confirm GREEN.

---

## Phase 2 — Header semantic hardening

**Files modified:** `src/integrity.rs`  
**New anomaly variants added to `VhdxIntegrityAnomaly`:**

### 2A — GUID validity

The VHDX header (MS-VHDX §2.1.3) contains three GUIDs in bytes 16–63:
`FileWriteGuid` (16–31), `DataWriteGuid` (32–47), `LogGuid` (48–63).

```rust
/// FileWriteGuid is all zeros — disk identity was wiped or file was never
/// properly written. Prevents correlation with other images or audit trails.
FileWriteGuidAllZeros,

/// DataWriteGuid is all zeros — data-layer identity erased. Specifically
/// disrupts parent-GUID verification in differencing disk chains.
DataWriteGuidAllZeros,

/// LogGuid is non-zero but LogLength is zero — the log GUID was set but
/// the log was cleared without updating the GUID. Indicates manual header
/// manipulation between write cycles.
LogGuidWithNoLog { log_guid: [u8; 16] },

/// LogLength is non-zero (dirty log exists) but LogGuid is all zeros —
/// structurally impossible via normal Hyper-V operation. Strong indicator
/// of a manually constructed dirty-log header.
LogGuidAllZerosWithDirtyLog { log_length: u32 },
```

Severity: all `Warning` except `LogGuidAllZerosWithDirtyLog` → `Error`.

### 2B — Version fields

```rust
/// LogVersion (bytes 64–65) must be 1. Any other value indicates a format
/// version violation or direct header patching.
LogVersionInvalid { version: u16 },

/// Version (bytes 66–67) must be 1 — the only defined VHDX format version.
VersionInvalid { version: u16 },
```

Severity: `Warning` for both.

### 2C — Log offset/length alignment and range

```rust
/// LogOffset (bytes 72–79) must be 1 MB aligned (multiple of 0x100000).
/// Misalignment is impossible via normal writes; indicates manual patching
/// of the log pointer.
LogOffsetMisaligned { log_offset: u64 },

/// LogLength (bytes 68–71) must be a multiple of 1 MB. Misalignment
/// is impossible via normal writes.
LogLengthMisaligned { log_length: u32 },

/// LogOffset + LogLength extends past the end of the file. The declared
/// log region does not physically exist in this container.
LogBeyondContainer {
    log_offset: u64,
    log_length: u32,
    container_size: u64,
},

/// LogOffset places the log inside the reserved header/region-table zone
/// (below 0x300000). A log in this range would overwrite structural data
/// if replayed — a strong indicator of log poisoning.
LogInReservedZone { log_offset: u64 },
```

Severity: `LogOffsetMisaligned` → `Error`, `LogLengthMisaligned` → `Error`,
`LogBeyondContainer` → `Error`, `LogInReservedZone` → `Error`.

### 2D — SequenceNumber gap

```rust
/// Both header copies have valid CRCs but their sequence numbers differ by
/// more than 1. Normally the two copies differ by exactly 1 (the active
/// copy is higher). A larger gap indicates one copy was patched directly
/// without going through a normal write cycle.
SequenceNumberGapLarge { seq1: u64, seq2: u64, gap: u64 },
```

Severity: `Warning`.

**Where these are checked:** inside `check_headers()` (after CRC validation confirms
both copies are readable), and inside `check_header_pair()` for 2D.

**TDD plan — Phase 2:**

RED commit: add all new variant stubs; write tests asserting exact severity for each
variant; write `check_headers()` tests with crafted buffers that trigger each case
(zero GUID at offset 16, LogVersion ≠ 1 at offset 64, LogOffset = 0x50001 etc.).
Confirm tests FAIL.

GREEN commit: implement detection inside `check_headers()` and `check_header_pair()`.
Confirm tests PASS.

---

## Phase 3 — Region layout validation

**Files modified:** `src/integrity.rs`  
**New anomaly variants:**

### 3A — Region entry alignment and range

```rust
/// A region entry's file_offset is not 1 MB aligned. All VHDX regions
/// must start at 1 MB boundaries; misalignment indicates the region table
/// was manually patched.
RegionMisaligned {
    region: &'static str,
    file_offset: u64,
},

/// A region entry's file_offset + length extends past the end of the
/// container. The declared region does not physically exist.
RegionBeyondContainer {
    region: &'static str,
    declared_end: u64,
    container_size: u64,
},
```

Severity: both `Error`.

### 3B — Region overlap

```rust
/// Two declared regions (BAT, Metadata, Log) have overlapping byte ranges.
/// Structurally impossible via normal Hyper-V operation; if the BAT and
/// metadata regions overlap, all BAT-level analysis is tainted.
RegionsOverlap {
    region_a: &'static str,
    region_b: &'static str,
    overlap_offset: u64,
},

/// The dirty-log section overlaps the header or region-table section.
/// Log replay would overwrite VHDX structural data — a direct log-poisoning
/// technique.
LogOverlapsStructuralRegion {
    log_offset: u64,
    overlapping: &'static str,
},
```

Severity: both `Error`.

### 3C — Unknown required region

```rust
/// A region table entry has Required = 1 with a GUID that is neither the
/// BAT GUID nor the Metadata GUID. Hyper-V refuses to open files with
/// unknown required regions; this file cannot have been created by any
/// legitimate Microsoft tool.
UnknownRequiredRegion { guid_hex: String },
```

Severity: `Warning`.

### 3D — Reserved field detection

```rust
/// Bytes 12–15 of the region table header, or bytes 28–31 of a region
/// entry, are non-zero. These are explicitly reserved (must be zero per
/// MS-VHDX §2.1.5); non-zero values indicate data hiding or a format
/// version violation.
RegionTableReservedNonZero {
    copy: u8,
    /// "header" or "entry N"
    location: &'static str,
    value: u32,
},
```

Severity: `Warning`.

**Where these are checked:** new `check_region_layout()` function called from
`analyse()` after `check_region_tables()` and before `check_metadata()`.

**TDD plan — Phase 3:** RED → GREEN, one test per new variant.

---

## Phase 4 — Log section deep analysis

**Files modified:** `src/integrity.rs` (new `check_log()` function)  
**New anomaly variants:**

The VHDX log (MS-VHDX §2.4) stores structured entries with signature `loge`,
CRC32C at offset 4, LogGuid at offset 8 (16 bytes), and SequenceNumber at offset
24 (8 bytes).

```rust
/// The log region exists (LogLength > 0) but all bytes in the log area
/// are zero. The log was declared dirty but its content was zeroed —
/// possibly to prevent log-entry analysis while preserving the dirty
/// appearance to block automated tooling.
LogZeroedButDirty { log_offset: u64, log_length: u32 },

/// A log entry position does not begin with the expected "loge" signature.
/// Indicates structural corruption or a non-standard log format injection.
LogEntrySignatureMissing { entry_offset: u64 },

/// A log entry's CRC32C is invalid. A log with bad entry CRCs cannot be
/// safely replayed by Hyper-V (creating perpetual "dirty" appearance) but
/// still holds the file in an inconsistent state. Deliberate use prevents
/// Hyper-V from mounting the image.
LogEntryCrcMismatch {
    entry_offset: u64,
    computed: u32,
    stored: u32,
},

/// The LogGuid field inside a log entry does not match the LogGuid in the
/// active header. The log was transplanted from a different disk image —
/// the most direct form of log injection.
LogEntryGuidMismatch {
    entry_offset: u64,
    entry_guid: [u8; 16],
    header_guid: [u8; 16],
},

/// A gap exists in the sequence numbers of consecutive log entries. Log
/// entries must have consecutive sequence numbers in a circular log;
/// a gap means entries were selectively removed.
LogSequenceNumberGap {
    at_offset: u64,
    expected_seq: u64,
    found_seq: u64,
},
```

Severity:
| Variant | Severity |
|---|---|
| `LogZeroedButDirty` | Warning |
| `LogEntrySignatureMissing` | Warning |
| `LogEntryCrcMismatch` | Error |
| `LogEntryGuidMismatch` | Error |
| `LogSequenceNumberGap` | Error |

**Where checked:** `check_log()` is called from `analyse()` only when
`DirtyLog` is in the issue list (i.e. LogLength > 0). Log analysis short-circuits
after the first `Critical` finding from earlier layers (already handled by the
existing `BothRegionTableCopiesInvalid` guard).

**TDD plan — Phase 4:**

RED commit: add variant stubs; write tests with crafted log regions (all-zero log,
log with wrong signature at entry 0, log with bad CRC, log with wrong GUID).

GREEN commit: implement `check_log()` that walks entries using `EntryLength` to
advance, validating each.

---

## Phase 5 — BAT semantic hardening

**Files modified:** `src/integrity.rs` (extends `check_bat()`)  
**New anomaly variants:**

### 5A — BAT size formula validation (highest priority)

The expected number of BAT entries is fully determined by two metadata values:
```
data_blocks   = ceil(VirtualDiskSize / BlockSize)
bat_entries   = data_blocks + ceil(data_blocks / chunk_ratio)
bat_byte_size = bat_entries * 8, rounded up to next MB
```
The BAT region's physical size (from the region table, which IS CRC-protected) can
therefore be compared against the declared metadata values (which are NOT protected).
A mismatch proves that either `VirtualDiskSize` or `BlockSize` was altered after
the file was created.

```rust
/// The BAT region's physical size (from the CRC-protected region table)
/// does not match the size implied by VirtualDiskSize and BlockSize
/// (from the unprotected metadata). One of the metadata fields was
/// silently modified after the file was created.
///
/// The region table is the trusted reference because it is CRC32C
/// protected; the metadata fields are the suspect values.
BatSizeMetadataMismatch {
    bat_bytes_actual:   u32,
    bat_entries_actual: usize,
    bat_entries_expected: usize,
    vdisk_size:  u64,
    block_size:  u32,
},
```

Severity: `Error`.

### 5B — BAT entry in structural region

```rust
/// A FULLY_PRESENT BAT entry's file offset falls inside a VHDX structural
/// section (File Identifier, header section, region tables, or metadata
/// region). Reading this "virtual disk block" would return VHDX structural
/// bytes. This can be used to make forensic tooling read header data as
/// virtual disk content — or to redirect disk reads into structural metadata.
BatEntryInStructuralRegion {
    bat_index: usize,
    file_offset: u64,
    /// "File Identifier", "Header", "Region Table", "Metadata", or "Log"
    collides_with: &'static str,
},
```

Severity: `Critical` (worse than `BatEntryBeyondContainer` — the offset is
within the file but in the wrong region, creating a structural redirect attack).

### 5C — Missing sector bitmap

```rust
/// A FULLY_PRESENT data block's corresponding sector bitmap slot is in
/// NOT_PRESENT state. Hyper-V always writes the bitmap alongside data;
/// this combination is impossible via normal operation and indicates direct
/// BAT manipulation.
MissingSectorBitmap {
    data_bat_index:   usize,
    bitmap_bat_index: usize,
},
```

Severity: `Warning`.

### 5D — Undefined / transient block states

```rust
/// A data BAT entry is in UNDEFINED state (1), which is only valid
/// transiently during block allocation. Persistence indicates an
/// interrupted write or direct BAT manipulation.
UndefinedBlockState { bat_index: usize },

/// A data BAT entry is in UNMAPPED state (3) in a non-differencing disk.
/// UNMAPPED is only valid in differencing disks (blocks not present in
/// this layer but potentially in the parent chain).
UnmappedBlockInNonDifferencing { bat_index: usize },
```

Severity: `Warning` for both.

### 5E — Ghost data in absent blocks

```rust
/// A NOT_PRESENT or ZERO-state BAT entry's corresponding file range
/// contains non-zero bytes. The virtual disk logically reports no data
/// in this range, but physical bytes exist — content was written then
/// the BAT entry was zeroed without wiping the underlying storage.
/// The content remains physically recoverable.
GhostDataInAbsentBlock {
    bat_index:    usize,
    file_offset:  u64,
    nonzero_bytes: u64,
},
```

Severity: `Warning`.

Note: this check is expensive (scans physical file ranges) and is opt-in via
`check_bat_ghost_data()` — not included in the default `analyse()` call. Callers
who want it can call it explicitly and merge results.

**TDD plan — Phase 5:**

RED commit: add all variant stubs; write tests for each case (craft a VHDX where
`VirtualDiskSize` is altered post-BAT-creation to trigger `BatSizeMetadataMismatch`;
craft a BAT entry pointing at 0x100000 to trigger `BatEntryInStructuralRegion`; etc.).

GREEN commit: implement each check inside `check_bat()` using the `ParsedRegions`
struct from Phase 1.

---

## Phase 6 — Metadata deep analysis

**Files modified:** `src/integrity.rs` (extends `check_metadata()`)  
**New anomaly variants:**

### 6A — Physical sector size

```rust
/// PhysicalSectorSize is not 512 or 4096. Per MS-VHDX, only these two
/// values are valid. Any other value indicates a metadata field violation.
PhysicalSectorSizeInvalid { sector_size: u32 },
```

Severity: `Warning`.

### 6B — Virtual disk identity

```rust
/// VirtualDiskId (the GUID that uniquely identifies this virtual disk) is
/// all zeros. The disk's identity was wiped — disrupts parent-chain GUID
/// verification and prevents correlation with snapshot lineage.
VirtualDiskIdAllZeros,
```

Severity: `Warning`.

### 6C — Metadata item layout

```rust
/// Two metadata item data regions occupy overlapping byte ranges within
/// the metadata area. Structurally impossible without manual construction;
/// one item's data may be concealed inside another's apparent content.
MetadataItemsOverlap {
    item_a: &'static str,
    item_b: &'static str,
    overlap_offset: u64,
},

/// A metadata item's data_offset + data_length extends beyond the metadata
/// region boundary. Out-of-bounds access would occur on a straight read.
MetadataItemBeyondRegion {
    item_name: &'static str,
    declared_end: u64,
    region_end: u64,
},
```

Severity: `MetadataItemsOverlap` → `Error`, `MetadataItemBeyondRegion` → `Warning`.

### 6D — LeaveBlocksAllocated flag

```rust
/// The LeaveBlocksAllocated flag is set in FileParameters. Freed blocks
/// are not removed from the BAT — they remain FULLY_PRESENT after logical
/// deletion. Wiped content is physically preserved and recoverable.
/// Legitimate as a Hyper-V performance optimization but forensically
/// significant: the file accumulates "deleted" content indefinitely.
LeaveBlocksAllocatedSet,
```

Severity: `Info`.

### 6E — Missing parent locator

```rust
/// HasParent = true in FileParameters but no Parent Locator metadata item
/// exists. The differencing disk cannot identify its parent chain —
/// structural corruption or deliberate erasure of chain provenance.
MissingParentLocator,
```

Severity: `Warning`.

### 6F — VirtualDiskSize over-reporting

```rust
/// VirtualDiskSize claims more addressable space than the BAT region's
/// physical size can address at the declared BlockSize. Some of the
/// declared virtual address space cannot be reached — a structural
/// inconsistency (less suspicious than underreporting but still a
/// metadata/BAT mismatch).
VirtualDiskSizeOverreported { declared: u64, bat_coverage: u64 },
```

Severity: `Info`.

**TDD plan — Phase 6:**

RED commit: add variant stubs; write tests with crafted metadata items (zero-GUID
at VirtualDiskId offset, two items with overlapping offsets, etc.).

GREEN commit: implement detection inside `check_metadata()` using `ParsedRegions`.

---

## Phase 7 — Container / File Identifier refinements

**Files modified:** `src/integrity.rs`

### 7A — File Identifier reserved bytes

The File Identifier section (1 MB starting at offset 0) contains:
- bytes 0–7: `vhdxfile` magic
- bytes 8–511: creator string (UTF-16LE, null-terminated)
- bytes 512–65535: reserved (must be zero per MS-VHDX §2.1.2)

```rust
/// Non-zero bytes exist in the reserved area of the File Identifier
/// section (bytes 512–65535). Data is being hidden in a region that
/// normal parsers skip entirely.
FileIdentifierReservedNonZero { start_offset: u64, nonzero_count: u64 },
```

Severity: `Warning`.

### 7B — Inter-region gap data

```rust
/// Non-zero bytes exist in a gap between two declared structural regions
/// (e.g. between the region table section and the first data region).
/// These gaps are zeroed in all Hyper-V-created files; non-zero content
/// indicates data hiding or a partial-write artifact.
InterRegionGapNonZero {
    from_region: &'static str,
    to_region:   &'static str,
    gap_offset:  u64,
    gap_size:    u64,
},
```

Severity: `Info`.

### 7C — Header reserved bytes

```rust
/// Non-zero bytes exist in the reserved area of a header copy (bytes 80–4095
/// of the 4096-byte header block). These bytes are not covered by the CRC
/// field and are invisible to standard parsers — a hiding location for
/// small amounts of data.
HeaderReservedNonZero { copy: u8, offset_in_header: u16, length: u16 },
```

Severity: `Warning`.

**TDD plan — Phase 7:** RED → GREEN per sub-case.

---

## Phase 8 — Repair enhancements

**Files modified:** `src/repair.rs`

Extend `attempt_repair()` with three additional repairable conditions:

| Anomaly | Repair action | Disclaimer |
|---|---|---|
| `BatEntryInStructuralRegion` | Zero to NOT_PRESENT (same as BeyondContainer) | Entry redirected to structural region — original logical block is unrecoverable from this image |
| `UndefinedBlockState` | Zero to NOT_PRESENT | Transient state persisted; zeroed to stable NOT_PRESENT; any in-flight data from the interrupted write is lost |
| `BatEntryUnaligned` (reserved bits only, offset otherwise valid) | Clear bits 3–19 while preserving offset and state | Reserved bits cleared; payload offset preserved; original anomaly may have been forensically significant |

Add to `cannot_repair` with explicit reasons:

| Anomaly | Reason |
|---|---|
| `BatSizeMetadataMismatch` | "Cannot determine which field (VirtualDiskSize or BlockSize) was altered without an external reference; altering either would destroy evidence" |
| `LogEntryGuidMismatch` | "Log was transplanted from a different image; replay would overwrite this image's metadata with data from the source image" |
| `GhostDataInAbsentBlock` | "Absent-block data cannot be zeroed without destroying evidence; use a carver to extract the content before repair" |
| `MetadataItemsOverlap` | "Overlapping metadata items are ambiguous; cannot determine which item's data is authoritative without external reference" |
| `BothHeaderCopiesInvalid` | (already exists) |
| `LogGuidAllZerosWithDirtyLog` | "Log structure is internally contradictory; replay is unsafe and clearing the log would destroy evidence of the anomaly" |

**TDD plan — Phase 8:**

Extend `tests/repair_tests.rs` — one test per new repairable condition, one test per
new `cannot_repair` condition. RED → GREEN.

---

## Phase 9 — Robustness / fuzz hardening

**Files modified:** `src/integrity.rs`, `src/repair.rs`  
**New files created:** `fuzz/fuzz_targets/parse_vhdx.rs`, `fuzz/Cargo.toml`

### Specific gaps to close

**1. Region entry count arithmetic**  
`16 + entry_count * REGION_ENTRY_SIZE` (in `parse_region_locations`) lacks an
overflow check. The `.min(2048)` cap prevents iteration overflow but not the
multiplication itself.

Fix: replace with `16usize.checked_add(entry_count.checked_mul(REGION_ENTRY_SIZE)?)?`.

**2. Metadata entry array arithmetic**  
`32 + i * 32` in `check_metadata` lacks overflow check for large `i`.

Fix: use `32usize.checked_add(i.checked_mul(32)?)?`.

**3. Log offset + length overflow**  
`log_offset as u64 + log_length as u64` (used in `LogBeyondContainer` detection)
can overflow if both are near `u64::MAX`.

Fix: use `log_offset.checked_add(u64::from(log_length))` → `None` → skip check.

**4. Chunk ratio sentinel in BAT loop**  
If `chunk_ratio()` returns `u64::MAX` (no valid metadata), the BAT loop uses
`chunk_ratio + 1` which wraps to 0 on overflow. The `u64::MAX` case is handled
by a guard (`chunk_ratio < u64::MAX`) but this invariant is implicit.

Fix: use `Option<u64>` for chunk_ratio; `None` disables bitmap-slot detection
explicitly.

**5. Metadata item data offset arithmetic**  
`start + 0x10000 + item_offset` — if `item_offset` is near `usize::MAX`, this
overflows. Use checked arithmetic: `start.checked_add(0x10000)?.checked_add(item_offset as usize)?`.

**6. Fuzz target**

```toml
# fuzz/Cargo.toml
[package]
name = "vhdx-forensic-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[[bin]]
name = "parse_vhdx"
path = "fuzz_targets/parse_vhdx.rs"
test = false
doc = false

[dependencies]
libfuzzer-sys = "0.4"
vhdx-forensic = { path = ".." }
```

```rust
// fuzz/fuzz_targets/parse_vhdx.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use vhdx_forensic::VhdxIntegrity;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input.
    let _ = VhdxIntegrity::new(data).analyse();
});
```

Seed corpus: the existing `tests/builder.rs` builds can generate seed inputs by
writing `VhdxBuilder::new(4 * 1024 * 1024).build()` to `fuzz/corpus/parse_vhdx/`.

**7. Maximum container size guard**  
Currently `MIN_CONTAINER_SIZE` is checked but there is no maximum. A `u64`
`container_size` value used in arithmetic with region offsets should be bounded
to avoid wrapping. Guard: if `data.len() > 64 * (1u64 << 40) as usize + HEADER_OVERHEAD`,
emit a `ContainerTruncated`-analogue or just proceed (the checks will find
out-of-bounds naturally).

**TDD plan — Phase 9:**

For each arithmetic gap: write a test with a crafted buffer that currently would
panic or produce wrong output (e.g., region entry count = u32::MAX, metadata item
offset = 0xFFFFFFFF). Confirm it panics on RED. Fix on GREEN.

---

## Phase 10 — API / reporting

**Files modified:** `src/integrity.rs`, `src/lib.rs`

### 10A — `anomalies_at_least` public helper

```rust
/// Filter a slice of anomalies to those at or above a minimum severity.
pub fn anomalies_at_least(
    anomalies: &[VhdxIntegrityAnomaly],
    min: Severity,
) -> Vec<&VhdxIntegrityAnomaly> {
    anomalies.iter().filter(|a| a.severity() >= min).collect()
}
```

### 10B — `summary()` method

```rust
pub struct AnalysisSummary {
    pub total: usize,
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
    pub highest: Option<Severity>,
}

impl VhdxIntegrity<'_> {
    pub fn summary(anomalies: &[VhdxIntegrityAnomaly]) -> AnalysisSummary { ... }
}
```

### 10C — `forensic_significance()` method

```rust
impl VhdxIntegrityAnomaly {
    /// One-sentence forensic interpretation of this finding, suitable for
    /// inclusion in an IR report or court exhibit.
    pub fn forensic_significance(&self) -> &'static str { ... }
}
```

Returns a non-generic, VHDX-specific explanation for each variant. Example:

| Variant | `forensic_significance()` |
|---|---|
| `BatSizeMetadataMismatch` | "The CRC-protected BAT allocation is inconsistent with the declared virtual disk size or block size — one of these metadata fields was silently altered after file creation." |
| `BatEntriesOverlap` | "Two logical blocks map to the same physical bytes; an investigator reading both blocks sees identical content regardless of what was logically written to each." |
| `GhostDataInAbsentBlock` | "Content exists at a physical location the virtual disk reports as empty; the data was written and then the allocation pointer was zeroed, but the bytes remain physically recoverable." |
| `LogEntryGuidMismatch` | "The log was assembled from entries belonging to a different disk image; if replayed, it would write that image's metadata over this disk's structural data." |

### 10D — MITRE ATT&CK cross-reference

As an associated constant or method:

```rust
impl VhdxIntegrityAnomaly {
    /// MITRE ATT&CK technique IDs most closely associated with this finding,
    /// or an empty slice if no mapping applies.
    pub fn mitre_techniques(&self) -> &'static [&'static str] { ... }
}
```

| Variant | ATT&CK Techniques |
|---|---|
| `TrailingData` | T1564.001 — Hide Artifacts: Hidden Files |
| `GhostDataInAbsentBlock` | T1564.001 |
| `FileIdentifierReservedNonZero` | T1027 — Obfuscated Files or Information |
| `HeaderReservedNonZero` | T1027 |
| `VirtualDiskSizeUnderreported` | T1564 — Hide Artifacts |
| `LogSequenceNumberGap` | T1070 — Indicator Removal on Host |
| `LogEntryGuidMismatch` | T1070.003 — Clear Command History (log injection analogue) |
| `BatEntryInStructuralRegion` | T1027 |
| `BatEntriesOverlap` | T1036 — Masquerading |
| `FileWriteGuidAllZeros` | T1070 |

**TDD plan — Phase 10:** tests assert that `anomalies_at_least` filters correctly;
`forensic_significance()` returns non-empty strings for every variant; `summary()`
returns correct counts.

---

## Implementation order

```
Phase 1  (ParsedRegions refactor)        ← prerequisite for 5, 6
Phase 2  (header semantics)              ← independent
Phase 3  (region layout)                 ← independent
Phase 4  (log deep analysis)             ← depends on Phase 2 (DirtyLog check)
Phase 5  (BAT hardening)                 ← depends on Phase 1
Phase 6  (metadata depth)                ← depends on Phase 1
Phase 7  (container / file identifier)   ← independent
Phase 8  (repair enhancements)           ← depends on Phase 5 (new repairable anomalies)
Phase 9  (robustness / fuzz)             ← depends on Phase 1 (arithmetic fixes)
Phase 10 (API / reporting)               ← depends on all anomaly variants being final
```

Phases 2, 3, 7 can be done in parallel. Phases 5 and 6 can be done in parallel
after Phase 1. Phase 9 can be done in parallel with Phases 5–7.

---

## Files to create / modify

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/integrity.rs` | All new anomaly variants and check functions |
| Modify | `src/repair.rs` | New repairable conditions and cannot_repair entries |
| Modify | `src/lib.rs` | Re-export new public items |
| Modify | `tests/integrity_tests.rs` | Tests for all new anomalies |
| Modify | `tests/repair_tests.rs` | Tests for new repair / cannot_repair cases |
| Create | `fuzz/Cargo.toml` | Fuzz crate manifest |
| Create | `fuzz/fuzz_targets/parse_vhdx.rs` | libfuzzer-sys entry point |
| Create | `fuzz/corpus/parse_vhdx/` | Seed corpus files from builder |

---

## What is deliberately excluded

**No `vhdx-carver` crate.** Carved VHDX would require reconstructing the BAT and
region tables — a writeback to an evidence file. Detection and reporting of
unaddressable or hidden data is the correct forensic response. Callers who need to
extract content from ghost blocks can read the physical file bytes directly using
the anomaly's reported offset.

**No severity override.** Severity is a fixed property of each anomaly type derived
from MS-VHDX semantics and observed attack patterns. Callers can filter; they cannot
reassign severity.

**No log replay.** Log replay requires executing Hyper-V's journaling logic, which
modifies the image. `DirtyLog` and `LogEntry*` anomalies are documented and reported;
the caller must mount the image on a live Hyper-V host for automatic replay, or use
`VhdxRepair::cannot_repair` as the documented outcome.

**No differencing disk chain traversal.** Parent locator validation (Phase 6E) checks
that the locator metadata item exists, but does not open or parse the parent file.
Full chain analysis is out of scope for a single-file analyser.
