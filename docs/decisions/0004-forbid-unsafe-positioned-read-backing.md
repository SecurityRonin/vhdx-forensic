# 4. `forbid(unsafe)` via a positioned-read, bounded `Backing`

Date: 2026-07-24
Status: Accepted

## Context

These crates parse untrusted, attacker-controllable disk images (Paranoid
Gatekeeper standard). The fleet accepts one bounded `unsafe` (`mmap`) for
containers that need it — e.g. `ewf` downgrades to `unsafe_code = "deny"` + a
per-site allow — but that surrenders the compiler-proved memory-safety guarantee
for a parser of hostile input. VHDX has no such constraint: it can serve reads
without memory-mapping the file.

The reader originally held the **entire image** in a `Vec<u8>`, so a 2 TB VHDX
implied a 2 TB heap. Commit `c9b4df0` ("feat(reader): bounded positioned-read
backing (stop loading the whole image into RAM)") replaced that with a
positioned-read abstraction.

## Decision

- Keep `unsafe_code = "forbid"` workspace-wide
  (`Cargo.toml` → `[workspace.lints.rust] unsafe_code = "forbid"`); no `mmap`,
  no C bindings ("Zero unsafe code, no C bindings, no external tools" — README).
- Serve reads through `Backing` (`core/src/backing.rs`), a four-arm enum with a
  cursor-free positioned-read API (`read_at` + `len`) and **no boxed trait on the
  hot path** (a `match` the compiler inlines):
  - `File` — OS positioned read; only BAT-selected blocks touch RAM, so peak
    memory no longer scales with image size.
  - `Sub` — a contiguous sub-range of a larger file (a STORED zip entry).
  - `Mem` — the legacy in-RAM `from_bytes` path (or an inflated DEFLATE entry).
  - `Reader` — an arbitrary boxed `Read + Seek + Send` reader (the forensic-vfs
    engine path), bridged under a mutex — still no `mmap`, so `forbid(unsafe)`
    holds.

## Consequences

- Provable "zero places a crafted input can corrupt memory" — badgeable as
  `unsafe forbidden`, a sharper trust signal than `ewf`'s `deny` + bounded-allow
  posture.
- Peak memory is bounded by the resolved block, not the virtual disk size; the
  open/parse pass reads only small structures from their known offsets.
- The `Reader` arm lets the fleet VFS hand a `SourceCursor` straight to the
  parser without `forensic-vfs` appearing in the production dependency tree.
