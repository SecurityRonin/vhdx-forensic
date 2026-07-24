# 2. Reader/analyzer split; the analyzer audits raw bytes

Date: 2026-07-24
Status: Accepted

## Context

A `-core` reader is built to read *valid* data robustly, so it normalizes away
exactly the detail a forensic auditor must see: CRC mismatches, overlapping
regions, ghost data in blocks marked absent, wiped GUIDs. The fleet
Crate-structure standard states the `-forensic` layer is *not required* to route
through the reader's happy-path API — it "often needs to go much lower level than
the `-core` API."

`vhdx-forensic` was originally self-contained; commit `5fd76fd`
("refactor(GREEN): vhdx-forensic depends on vhdx crate, removes reader modules")
made it depend on the reader for the parsing it *can* share, while its analysis
entry point takes raw bytes.

## Decision

- `vhdx-forensic` depends on `vhdx-core` (`forensic/Cargo.toml` →
  `vhdx = { workspace = true }`) and reuses its stable primitives — the CRC32C
  routine and spec offset/GUID constants (`use vhdx::header::{crc32c, …}`,
  `use vhdx::region::{…}`, `use vhdx::metadata::{…}` in `integrity.rs`).
- The analyzer's public surface operates on **raw bytes**, not the reader's
  decoded stream: `VhdxIntegrity::new(&image_bytes).analyse()`. It "works on raw
  bytes and does not require a fully valid structure" (README), re-parsing header,
  region-table, metadata, and BAT structures in situ (`integrity.rs` has its own
  offset readers `r16`/`r32`/`r64`) so it can observe corruptions a robust reader
  would reject or silently repair.
- The dependency direction is one-way and acyclic: `forensic → core → forensicnomicon`.

## Consequences

- The analyzer sees the broken structure directly; it is never blinded by the
  reader normalizing an anomaly away — the exact failure the fleet standard warns
  against.
- Shared, well-tested primitives (CRC32C, spec constants) are reused rather than
  duplicated, but structural walking is analyzer-owned so it can grade malformed
  input.
- `forensic/lib.rs` re-exports the reader (`pub use vhdx::{…VhdxReader…}`), so a
  caller needing both reading and auditing depends on one crate.
