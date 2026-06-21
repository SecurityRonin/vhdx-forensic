# vhdx-forensic

**Read and audit Hyper-V VHDX disk images in pure Rust — a hardened `Read + Seek` container reader plus a 63-code structural integrity analyzer for DFIR.**

This workspace ships two crates: **`vhdx-core`** — the VHDX/Hyper-V virtual-disk container reader (dynamic, fixed, differencing, automatic dirty-log recovery), exposing a `Read + Seek` view over the virtual sector stream (published as `vhdx-core`, imported as `vhdx`); and **`vhdx-forensic`** — the integrity analyzer that audits the raw bytes for tampering, corruption, and anti-forensic GUID/log wiping, emitting `forensicnomicon::report::Finding` plus optional in-memory CRC repair. Zero unsafe code, no C bindings, no external tools.

```toml
[dependencies]
vhdx-core = "0.2"       # reader — imported as `vhdx`
vhdx-forensic = "0.2"   # analyzer — graded structural findings
```

```rust
use vhdx_forensic::{anomalies_at_least, Severity, VhdxIntegrity};

let image = std::fs::read("disk.vhdx")?;
let anomalies = VhdxIntegrity::new(&image).analyse();
for a in anomalies_at_least(&anomalies, Severity::Error) {
    println!("[{:?}] {}", a.severity(), a.forensic_significance());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Supported formats

| Format | Supported |
|--------|:---------:|
| VHDX Version 1 (Windows 8 / Server 2012+) | ✓ |
| Dynamic disks (sparse, BAT-addressed) | ✓ |
| Fixed disks (pre-allocated) | ✓ |
| Differencing disks (single-level parent chain) | ✓ |
| Log replay (dirty-log recovery) | ✓ |

Read-only. Differencing disks require the parent image to be supplied via `VhdxReader::from_bytes_with_parent`. Log replay is applied automatically on open when the active header carries a non-zero LogGuid.

## Forensic analysis — `vhdx-forensic`

`VhdxIntegrity::new(&bytes).analyse()` walks the raw container across six phases — container/magic, CRC integrity, header semantics, region layout, metadata, and BAT/data-block analysis. There are **63** distinct anomaly codes; a representative sample:

| Code | Severity | Meaning |
|------|----------|---------|
| `VHDX-BAD-MAGIC` | Critical | File does not start with the `vhdxfile` signature |
| `VHDX-BOTH-HEADER-COPIES-INVALID` | Critical | Both header copies fail CRC32C — header recovery impossible |
| `VHDX-HEADER-CHECKSUM-MISMATCH` | Error | A header copy's stored CRC32C does not match the computed value |
| `VHDX-REGIONS-OVERLAP` | Error | Two region-table entries claim overlapping container bytes |
| `VHDX-LOG-ENTRY-CRC-MISMATCH` | Error | A log entry's CRC fails — replay would corrupt the image |
| `VHDX-BAT-ENTRY-BEYOND-CONTAINER` | Error | A BAT entry points past the end of the file |
| `VHDX-FILE-WRITE-GUID-ALL-ZEROS` | Warning | FileWriteGuid wiped — consistent with anti-forensic tampering |
| `VHDX-GHOST-DATA-IN-ABSENT-BLOCK` | Warning | Non-zero payload in a block marked absent — residual/hidden data |
| `VHDX-DIFFERENCING-DISK` | Warning | Image is a child disk requiring a parent to read |
| `VHDX-DIRTY-LOG` | Info | Active log present — image was not cleanly closed |

Findings are observations, never legal conclusions — MITRE mappings are surfaced as "consistent with," for the analyst to weigh. `VhdxRepair::new(bytes).attempt_repair()` rebuilds header and region-table CRC32C checksums from a valid peer copy in memory; it never alters payload data.

## Trust but verify

Panic-free on hostile input (no `unwrap`/`expect`/`panic!` or unchecked indexing in production code, hard `deny` lints, bounds-checked length/offset/count fields, `checked_mul`/`checked_add` BAT addressing), fuzzed via a `cargo-fuzz` workspace, and validated against real artifacts from the log2timeline/dfvfs corpus and QEMU output with virtual disk sizes cross-checked against `qemu-img info`, with the decoded byte stream verified byte-identical to `qemu-img convert -O raw`. See [Validation](validation.md).

See the project [README](https://github.com/SecurityRonin/vhdx-forensic) for the full usage guide, CLI, and related-crate map.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
