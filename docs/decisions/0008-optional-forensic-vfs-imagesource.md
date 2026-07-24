# 8. Optional `forensic-vfs` `ImageSource` integration

Date: 2026-07-24
Status: Accepted

## Context

The fleet's VFS abstraction (`ronin-issen/CLAUDE.md` → "VFS & Universal Container
Abstraction") lets a whole stack — `container → volume system → filesystem` —
read as one `Arc<dyn ImageSource>` that workers share, so a consumer never knows
one container format from another. A decoded VHDX should compose into that stack.
But `forensic-vfs` must not become a mandatory dependency of the reader — many
consumers want only the `Read + Seek` view. Commits `74dc214`/`fca7a2e`
(reader-composes-as-ImageSource) and `033e96e`/`17d4ef7`
("feat(vfs): implement public forensic-vfs ImageSource for decoded VHDX")
implemented it; `2abad59` bumped the dep to 0.3.

## Decision

- Gate VFS integration behind an **off-by-default** Cargo feature
  (`core/Cargo.toml` → `[features] vfs = ["dep:forensic-vfs"]`,
  `forensic-vfs = { version = "0.3", optional = true }`).
- Under the feature, expose `VhdxSource` (`core/src/vfs.rs`, re-exported from
  `core/src/lib.rs` under `#[cfg(feature = "vfs")]`) implementing the
  `forensic-vfs` `ImageSource` positioned-byte contract.
- Feed the VFS engine through the boxed-reader `Backing::Reader` arm and
  `VhdxReader::open_reader`, so `forensic-vfs` stays out of the production
  dependency tree of a plain reader consumer (`backing.rs` doc comment).

## Consequences

- A default `vhdx-core` build has no `forensic-vfs` dependency; a VFS consumer
  opts in with `--features vfs` and gets a shareable `ImageSource`.
- Decoded VHDX composes into full stacks (`VHDX → GPT → NTFS`, …) without any
  per-format branch in the consumer — the abstraction, not an `if vhdx` case.
- The optional dep keeps `forbid(unsafe)` and the lean-library posture intact
  (ADR 0004).
