# vhdx-forensic — Design, Purpose & Scope

This is the design/intent document for a **library-tier** fleet repo. It records
what the crates are for, where they sit in the fleet architecture, and what is
deliberately out of scope. It is not a PRD — `vhdx-forensic` ships no
examiner-facing product; the end-user CLI is `disk4n6`/Issen. The debug `vhdx`
binary in `cli/` exists for local inspection only.

For the *why* behind specific choices, see the ADRs in
[`docs/decisions/`](decisions/).

## Purpose

Read and audit Microsoft **VHDX** (Hyper-V) virtual-disk images in pure Rust, for
DFIR use, with no C bindings and no external tools:

- **`vhdx-core`** decodes the MS-VHDX outer container and exposes a `Read + Seek`
  view over the virtual sector stream — the CONTAINER layer, the same role `ewf`
  plays for E01.
- **`vhdx-forensic`** audits the raw container bytes for tampering, corruption,
  and anti-forensic GUID/log wiping, emitting graded
  `forensicnomicon::report::Finding`s (63 distinct anomaly codes), plus in-memory
  CRC repair that never touches payload data.

## Fleet position

CONTAINER layer (`ronin-issen/CLAUDE.md` → Multi-Repo Architecture). Dependency
direction is strictly one-way:

```
forensicnomicon (KNOWLEDGE)
        ▲
   vhdx-core  ──────────────┐  (optional: forensic-vfs ImageSource, feature "vfs")
        ▲                   │
   vhdx-forensic            │  emits forensicnomicon::report::Finding
        ▲                   │
   disk4n6 / Issen / forensic-vfs-engine (ORCHESTRATION)
```

A decoded VHDX composes into the fleet VFS as an `Arc<dyn ImageSource>` (ADR
0008), so downstream stacks (`VHDX → GPT → NTFS`, …) read it without any
per-format branch.

## Module map

`core/`:
- `reader.rs` — `VhdxReader` public API (`open`, `from_bytes`,
  `from_bytes_with_parent`, `open_reader`); `Read + Seek`.
- `backing.rs` — `Backing` positioned-read store (File / Sub / Mem / Reader),
  bounded memory, no mmap (ADR 0004).
- `header.rs`, `region.rs`, `metadata.rs`, `bat.rs`, `log.rs`, `backing.rs` —
  MS-VHDX structural decode + automatic dirty-log replay.
- `bytes.rs` — bounds-checked LE readers (ADR 0005).
- `vfs.rs` — `VhdxSource` `ImageSource` impl, `#[cfg(feature = "vfs")]` (ADR 0008).

`forensic/`:
- `integrity.rs` — `VhdxIntegrity`, the six-phase raw-byte audit and the 63
  `VhdxIntegrityAnomaly` variants; `impl forensicnomicon::report::Observation`.
- `repair.rs` — `VhdxRepair`, in-memory header/region CRC32C rebuild from a valid
  peer copy.

`cli/`:
- `main.rs` — debug `vhdx info` command.

## Supported formats (in scope)

- VHDX Version 1 (Windows 8 / Server 2012+).
- Dynamic (sparse, BAT-addressed), fixed (pre-allocated), and single-level
  differencing (parent-chain) disks.
- Automatic log replay (dirty-log recovery) on open when the active header
  carries a non-zero LogGuid.

## Non-goals

- **Writing/creating VHDX images.** Read-only; the analyzer's "repair" is
  in-memory CRC rebuild only, never a write-back to the source (a writer is
  planned, not present — `core/Cargo.toml` description).
- **Multi-level differencing chains.** Only a single parent level is resolved.
- **VHD (legacy) images** — handled by the separate `vhd` crate.
- **Filesystem parsing.** `vhdx-core` yields a sector stream; filesystem
  navigation belongs to the FILESYSTEM layer / `forensic-vfs`.
- **Being an examiner-facing product.** No GUI, no MCP server; correlation and UX
  live in `disk4n6`/Issen.

## Validation approach

Correctness is proven against independent oracles, not self-authored fixtures
(ADR 0007): the decoded stream is asserted **byte-identical to
`qemu-img convert -O raw`** (sampled every 64 KiB across block/sector boundaries
plus a near-end read), sizes cross-checked against `qemu-img info`, and
detection proven by injecting corruptions at MS-VHDX §2.0 byte offsets into real
QEMU / dfvfs images. The analyzer's in-situ parse-and-analyse path is fuzzed
(`forensic/fuzz/`: `VhdxIntegrity::analyse` + `check_bat_ghost_data`) with the
invariant "must not panic"; the `vhdx-core` reader's structural decode path
(`VhdxReader::open`/`from_bytes` → header/region/metadata/bat/log) is not yet
fuzzed — a gap against the fleet "one target per parsed structure" standard. See
[`docs/validation.md`](validation.md).
