# vhdx-forensic

[![crates.io](https://img.shields.io/crates/v/vhdx-forensic.svg)](https://crates.io/crates/vhdx-forensic)
[![docs.rs](https://img.shields.io/docsrs/vhdx-forensic)](https://docs.rs/vhdx-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml)

Pure-Rust forensic analyser and read-only reader for VHDX disk images.

Decodes the [MS-VHDX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83f6b700-6216-40f0-aa99-9fcb421206e2) outer container format, exposes a `Read + Seek` interface over the virtual sector stream, and detects structural anomalies that indicate tampering, corruption, or anti-forensic manipulation. No unsafe code, no C bindings, no GPL.

## When to use this

You have a VHDX disk image (the native Windows virtual disk format used by Hyper-V, WSL2's `ext4.vhdx`, and Azure) and you want to:

- **Read raw sectors** in a forensic context — offline, read-only, no Windows storage stack side-effects
- **Audit structural integrity** before mounting or analysing — detect tampered headers, BAT corruption, ghost data, and GUID wiping
- **Produce an evidence-grade report** of every structural anomaly with forensic significance attached

This crate is the **CONTAINER** layer in the [Issen](https://github.com/SecurityRonin/issen) forensic stack: it sits between raw byte sources (E01/EWF via [`ewf`](https://crates.io/crates/ewf), raw files) and filesystem parsers (`ext4fs-forensic`, `ntfs-forensic`).

## Usage

```toml
[dependencies]
vhdx-forensic = "0.1"
```

### Reading sectors (VhdxReader)

```rust
use std::io::{Read, Seek, SeekFrom};
use vhdx_forensic::VhdxReader;

let mut reader = VhdxReader::open("disk.vhdx")?;
println!("virtual disk size: {} bytes", reader.virtual_disk_size());

let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

reader.seek(SeekFrom::Start(1024 * 1024))?;
reader.read_exact(&mut sector)?;
```

`VhdxReader` implements `std::io::Read + std::io::Seek`, so it can be dropped in anywhere an ordinary file handle is expected.

### Forensic integrity analysis (VhdxIntegrity)

```rust
use vhdx_forensic::{anomalies_at_least, Severity, VhdxIntegrity};

let image = std::fs::read("disk.vhdx")?;
let issues = VhdxIntegrity::new(&image).analyse();

// Surface only Error/Critical findings for triage
let critical = anomalies_at_least(&issues, Severity::Error);
for anomaly in &critical {
    println!("[{:?}] {}", anomaly.severity(), anomaly.forensic_significance());
}

// Enumerate every anomaly with its severity
for anomaly in &issues {
    println!("[{:?}] {:?}", anomaly.severity(), anomaly);
}
```

`VhdxIntegrity` works on raw bytes and does not require a fully valid structure — it analyses as much as it can regardless of how many anomalies it finds. It produces findings across six phases: container/magic, CRC integrity, header semantics, region layout, metadata, and BAT/data-block analysis.

### In-memory repair (VhdxRepair)

```rust
use vhdx_forensic::{VhdxRepair, RepairReport};

let image = std::fs::read("disk.vhdx")?;
let mut repair = VhdxRepair::new(image);
let report = repair.attempt_repair();

if report.any_repaired() {
    std::fs::write("disk_repaired.vhdx", repair.as_bytes())?;
}
if report.any_unresolved() {
    // some anomalies require manual intervention
}
```

`VhdxRepair` reconstructs CRC32C checksums for header and region table copies from valid peer copies — it does not alter payload data.

## Anomaly categories

| Severity | Category | Examples |
|---|---|---|
| Critical | Container / magic | `BadMagic`, `ContainerTruncated`, `BothHeaderCopiesInvalid` |
| Error | CRC integrity | `HeaderChecksumMismatch`, `RegionTableChecksumMismatch` |
| Error | Header semantics | `HeaderCopyMismatch`, `RegionTableCopyMismatch` |
| Error | Region layout | `RegionsOverlap`, `RegionBeyondContainer`, `LogInReservedZone` |
| Error | Log integrity | `LogEntryCrcMismatch`, `LogEntryGuidMismatch` |
| Error | BAT structure | `BatEntriesOverlap`, `BatEntryBeyondContainer` |
| Error | Metadata | `MetadataItemsOverlap`, `MissingParentLocator`, `VirtualDiskSizeUnderreported` |
| Warning | GUID wiping | `FileWriteGuidAllZeros`, `DataWriteGuidAllZeros`, `VirtualDiskIdAllZeros` |
| Warning | BAT anomalies | `GhostDataInAbsentBlock`, `UndefinedBlockState`, `UnmappedBlockInNonDifferencing` |
| Warning | Structural | `DifferencingDisk`, `LeaveBlocksAllocatedSet`, `TrailingData` |
| Info | Log state | `DirtyLog`, `InterRegionGapNonZero` |

## Hardening against crafted images

VHDX headers and region tables are CRC32C-protected, but the **BAT** (Block Allocation Table) and **metadata** fields are not. A crafted image can carry semantically invalid values while maintaining valid CRCs. This crate validates all of the following before any arithmetic that depends on them:

| Field | Constraint enforced |
|-------|---------------------|
| `BlockSize` | Power-of-two in \[1 MB, 256 MB\] |
| `LogicalSectorSize` | Exactly 512 or 4096 |
| `VirtualDiskSize` | Non-zero, ≤ 64 TiB, multiple of sector size |
| Region entry `file_offset + length` | Within container bounds |
| Region `entry_count` | Capped at 2048 (DoS guard) |
| Container size | Minimum 2.5 MB before any offset arithmetic |
| BAT offset arithmetic | `checked_mul`/`checked_add` — `AddressOverflow` instead of panic |

Differencing disks (`HasParent = true`) can be opened via `VhdxReader::from_bytes_with_parent(child, parent)`. `VhdxReader::from_bytes` still rejects them without a parent to prevent silent data loss. `VhdxIntegrity` analyses the raw structure regardless and emits `DifferencingDisk` (Warning).

## Supported formats

- VHDX Version 1 (Windows 8 / Server 2012 and later)
- Dynamic disks (sparse BAT-addressed data blocks)
- Fixed disks (all blocks preallocated)
- Differencing disks (via `VhdxReader::from_bytes_with_parent`)

Dirty-log recovery is applied automatically on open: if the active header carries a non-zero `LogGuid`, the log region is replayed into the in-memory buffer before any BAT or metadata parsing.

## Testing

138 tests across 10 test suites. Real images from two independent sources are committed to the repository:

| Source | Images | Purpose |
|---|---|---|
| [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) corpus | `ext2.vhdx`, `fat-parent.vhdx`, `fat-differential.vhdx`, `ext2.vhd` | Doer-checker: images built by a separate tool verify our parser against independently created data |
| QEMU v11.0.0 (Homebrew) | `qemu_empty_dynamic.vhdx`, `qemu_fixed.vhdx` | Zero-FP baseline and injection tests; virtual disk sizes cross-validated with `qemu-img info` |

Detection capability is verified by injecting corruptions at spec-mandated byte offsets (§2.0) into real QEMU images, then asserting the expected anomaly variant is detected. This proves detection on real images independently of our builder code.

See [docs/VALIDATION.md](docs/VALIDATION.md) for the full validation report including per-image field cross-validation and detection test results.

## Related

- [`vhdx-core`](https://github.com/SecurityRonin/vhdx-core) — Pure-Rust VHDX container reader (published as `vhdx-core`, imported as `vhdx`); the parser layer this crate depends on
- [`ewf`](https://crates.io/crates/ewf) — EWF/E01 container reader; pairs with this crate in the Issen stack
- [`ewf-forensic`](https://crates.io/crates/ewf-forensic) — Integrity auditor and Adler-32 repair for EWF images; the EWF counterpart to this crate
- [libvhdi](https://github.com/libyal/libvhdi) — C-based VHDX/VHD reader (LGPL); the independent reference implementation we validate against

## License

MIT — see [LICENSE](LICENSE).  
[Privacy Policy](https://securityronin.github.io/vhdx-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/vhdx-forensic/terms/) · © 2026 Security Ronin Ltd
