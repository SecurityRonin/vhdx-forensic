# 1. Single-repo workspace: `core` + `forensic` + `cli`

Date: 2026-07-24
Status: Accepted

## Context

VHDX support in the fleet started as two separate crates (a reader and an
analyzer). The fleet's Crate-structure standard (`ronin-issen/CLAUDE.md` →
"Crate-structure standard — reader/analyzer split") defines Pattern A for a
single-format container: **one workspace repo named `<x>-forensic`** with a
`core/` reader crate and a `forensic/` analyzer crate, plus an optional debug
`cli/` member. Commit `b876a46` ("refactor: consolidate vhdx-core +
vhdx-forensic into one workspace (core/forensic/cli)") performed the merge.

## Decision

Ship one repository, `vhdx-forensic`, as a Cargo workspace
(`Cargo.toml` → `members = ["core", "forensic", "cli"]`) with three members:

- `core/` → crate `vhdx-core` — the pure-Rust VHDX container reader.
- `forensic/` → crate `vhdx-forensic` — the integrity analyzer + in-memory repair.
- `cli/` → crate `vhdx-cli` (binary `vhdx`) — a debug/inspection CLI (`vhdx info`).

Fields shared by every member (`edition`, `rust-version`, `license`,
`repository`) and every dependency version are hoisted into
`[workspace.package]` / `[workspace.dependencies]` so a change is one edit (DRY),
while each crate keeps an independent `version` (core `0.3.1`, forensic `0.3.0`,
cli `0.1.0`).

## Consequences

- One repo, one CI, one README, one test corpus — the reader and analyzer evolve
  together and version independently.
- The `cli` member is a debug surface only; the examiner-facing CLI remains
  `disk4n6`/Issen, so this repo stays LIBRARY tier despite shipping a binary.
- Workspace inheritance means a shared-field or dependency bump touches a single
  line; the per-crate `version` split lets a reader-only change avoid a forced
  analyzer release.
