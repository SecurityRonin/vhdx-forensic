# vhdx-forensic

[![Crates.io: vhdx-forensic](https://img.shields.io/crates/v/vhdx-forensic.svg?label=vhdx-forensic)](https://crates.io/crates/vhdx-forensic)
[![Crates.io: vhdx-core](https://img.shields.io/crates/v/vhdx-core.svg?label=vhdx-core)](https://crates.io/crates/vhdx-core)
[![Docs.rs](https://img.shields.io/docsrs/vhdx-forensic)](https://docs.rs/vhdx-forensic)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Audit a Hyper-V VHDX disk image for tampering and corruption in pure Rust — point it at raw bytes and get back graded structural findings across 63 anomaly codes.**

```toml
[dependencies]
vhdx-forensic = "0.2"
```

```rust
use vhdx_forensic::{anomalies_at_least, Severity, VhdxIntegrity};

let image = std::fs::read("disk.vhdx")?;
let anomalies = VhdxIntegrity::new(&image).analyse();

// Surface only Error/Critical findings for triage
for a in anomalies_at_least(&anomalies, Severity::Error) {
    println!("[{:?}] {}", a.severity(), a.forensic_significance());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`vhdx-forensic` is the integrity **analyzer**. It reads the [MS-VHDX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83f6b700-6216-40f0-aa99-9fcb421206e2) container format through its sibling reader [`vhdx-core`](https://crates.io/crates/vhdx-core) (imported as `vhdx`), then audits the raw structure for anomalies consistent with tampering, corruption, or anti-forensic GUID/log wiping. It emits `forensicnomicon::report::Finding` and offers optional in-memory CRC repair. No unsafe code, no C bindings, no GPL.

## When to use this

You have a VHDX disk image (the native Windows virtual disk format used by Hyper-V, WSL2's `ext4.vhdx`, and Azure) and you want to:

- **Audit structural integrity** before mounting or analysing — detect tampered headers, BAT corruption, ghost data, and GUID wiping
- **Produce an evidence-grade record** of every structural anomaly with forensic significance and MITRE ATT&CK context attached
- **Read raw sectors** in a forensic context — offline, read-only, no Windows storage stack side-effects (via the bundled `vhdx-core` reader)

This crate is the **CONTAINER**-layer analyzer in the [Issen](https://github.com/SecurityRonin/issen) forensic stack: it sits between raw byte sources (E01/EWF via [`ewf`](https://crates.io/crates/ewf), raw files) and filesystem parsers (`ext4fs-forensic`, `ntfs-forensic`).

## Forensic integrity analysis (VhdxIntegrity)

`VhdxIntegrity` works on raw bytes and does not require a fully valid structure — it analyses as much as it can regardless of how many anomalies it finds. It produces findings across six phases: container/magic, CRC integrity, header semantics, region layout, metadata, and BAT/data-block analysis. Each `VhdxIntegrityAnomaly` variant carries a stable `code` string, a graded `severity()`, a `forensic_significance()` narrative, and `mitre_techniques()` — surfaced as "consistent with," never as a verdict.

```rust
use vhdx_forensic::VhdxIntegrity;

let image = std::fs::read("disk.vhdx")?;
for anomaly in VhdxIntegrity::new(&image).analyse() {
    println!("[{:?}] {:?}", anomaly.severity(), anomaly);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Reading sectors (VhdxReader)

The reader is re-exported from [`vhdx-core`](https://crates.io/crates/vhdx-core). `VhdxReader` implements `std::io::Read + std::io::Seek`, so it can be dropped in anywhere an ordinary file handle is expected.

```rust
use std::io::{Read, Seek, SeekFrom};
use vhdx_forensic::VhdxReader;

let mut reader = VhdxReader::open("disk.vhdx")?;
println!("virtual disk size: {} bytes", reader.virtual_disk_size());

let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

reader.seek(SeekFrom::Start(1024 * 1024))?;
reader.read_exact(&mut sector)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## In-memory repair (VhdxRepair)

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

## Anomaly codes

Each variant exposes a stable `code` string (scheme-prefixed `VHDX-…`). There are **63** in total; representative codes by category:

| Severity | Category | Example `code` strings |
|---|---|---|
| Critical | Container / magic | `VHDX-BAD-MAGIC`, `VHDX-CONTAINER-TRUNCATED`, `VHDX-BOTH-HEADER-COPIES-INVALID` |
| Error | CRC integrity | `VHDX-HEADER-CHECKSUM-MISMATCH`, `VHDX-REGION-TABLE-CHECKSUM-MISMATCH` |
| Error | Header semantics | `VHDX-HEADER-COPY-MISMATCH`, `VHDX-REGION-TABLE-COPY-MISMATCH` |
| Error | Region layout | `VHDX-REGIONS-OVERLAP`, `VHDX-REGION-BEYOND-CONTAINER`, `VHDX-LOG-IN-RESERVED-ZONE` |
| Error | Log integrity | `VHDX-LOG-ENTRY-CRC-MISMATCH`, `VHDX-LOG-ENTRY-GUID-MISMATCH` |
| Error | BAT structure | `VHDX-BAT-ENTRIES-OVERLAP`, `VHDX-BAT-ENTRY-BEYOND-CONTAINER` |
| Error | Metadata | `VHDX-METADATA-ITEMS-OVERLAP`, `VHDX-MISSING-PARENT-LOCATOR`, `VHDX-VIRTUAL-DISK-SIZE-UNDERREPORTED` |
| Warning | GUID wiping | `VHDX-FILE-WRITE-GUID-ALL-ZEROS`, `VHDX-DATA-WRITE-GUID-ALL-ZEROS`, `VHDX-VIRTUAL-DISK-ID-ALL-ZEROS` |
| Warning | BAT anomalies | `VHDX-GHOST-DATA-IN-ABSENT-BLOCK`, `VHDX-UNDEFINED-BLOCK-STATE`, `VHDX-UNMAPPED-BLOCK-IN-NON-DIFFERENCING` |
| Warning | Structural | `VHDX-DIFFERENCING-DISK`, `VHDX-LEAVE-BLOCKS-ALLOCATED-SET`, `VHDX-TRAILING-DATA` |
| Info | Log state | `VHDX-DIRTY-LOG`, `VHDX-INTER-REGION-GAP-NON-ZERO` |

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

## Trust but verify

- **Panic-free on hostile input.** No `.unwrap()`/`.expect()`/`panic!` or unchecked indexing in production code (`unwrap_used`/`expect_used` are hard `deny` lints). Every length, offset, and count field is bounds-checked before any arithmetic — see [Hardening against crafted images](#hardening-against-crafted-images) above.
- **Fuzzed.** A `cargo-fuzz` workspace exercises the parse and analyse paths; the invariant is "must not panic."
- **Validated against real artifacts**, not only synthetic fixtures (below).

## Testing

The forensic crate ships a suite of integration tests across nine test files. Real images from two independent sources are committed to the repository:

| Source | Images | Purpose |
|---|---|---|
| [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) corpus | `ext2.vhdx`, `fat-parent.vhdx`, `fat-differential.vhdx`, `ext2.vhd` | Doer-checker: images built by a separate tool verify our parser against independently created data |
| QEMU v11.0.0 (Homebrew) | `qemu_empty_dynamic.vhdx`, `qemu_fixed.vhdx` | Zero-FP baseline and injection tests; virtual disk sizes cross-validated with `qemu-img info` |

The decoded virtual byte stream is verified **byte-identical to `qemu-img convert -O raw`** (an independent C codebase) on the committed corpus — the load-bearing correctness oracle. Detection capability is verified by injecting corruptions at spec-mandated MS-VHDX §2.0 byte offsets into real QEMU images, then asserting the expected anomaly variant is detected — independently of our builder code.

See the [validation report](https://securityronin.github.io/vhdx-forensic/validation/) ([source](../docs/validation.md)) for the full per-capability evidence, oracle/corpus tables, and documented gaps.

## Related

- [`vhdx-core`](https://crates.io/crates/vhdx-core) — Pure-Rust VHDX container reader (published as `vhdx-core`, imported as `vhdx`); the reader layer this crate depends on
- [`ewf`](https://crates.io/crates/ewf) — EWF/E01 container reader; pairs with this crate in the Issen stack
- [`ewf-forensic`](https://crates.io/crates/ewf-forensic) — Integrity auditor and Adler-32 repair for EWF images; the EWF counterpart to this crate
- [libvhdi](https://github.com/libyal/libvhdi) — C-based VHDX/VHD reader (LGPL); a candidate independent forensic-analysis oracle (a `libvhdi` differential is a documented validation gap, see the [validation report](https://securityronin.github.io/vhdx-forensic/validation/))

---

[Privacy Policy](https://securityronin.github.io/vhdx-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/vhdx-forensic/terms/) · © 2026 Security Ronin Ltd
