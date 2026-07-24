# 9. Declared MSRV floor separate from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`CLAUDE.core.md` → "Rust MSRV & Toolchain Policy")
separates the **dev toolchain** (what we build/fmt/clippy with — pinned to the
current stable, fleet-wide) from the **declared MSRV** (`rust-version`, a
downstream-facing promise kept low for published libraries so their crates.io
audience stays broad). Commit `7657b38` pinned the toolchain; the workspace
manifest declares the MSRV floor.

## Decision

- Pin the dev toolchain to the fleet stable in `rust-toolchain.toml`
  (`channel = "1.96.0"`, `components = ["rustfmt", "clippy"]`) — one version
  across contributors and CI.
- Declare the published-library MSRV floor once at
  `[workspace.package] rust-version = "1.85"` (`Cargo.toml`), inherited by every
  member via `rust-version.workspace = true`, so `vhdx-core` and `vhdx-forensic`
  promise a floor independent of the drifting dev pin.

## Consequences

- Bumping the dev toolchain does not silently raise the published crates' MSRV
  promise; the two move deliberately and separately.
- The declared floor is `1.85`, higher than the fleet's usual `1.75`/`1.80`
  library guidance. The specific newer-Rust feature or dependency
  (e.g. `forensicnomicon` / `forensic-vfs`) that forced `1.85` is **not recovered
  from available history — rationale reconstructed from structure; original
  intent not recovered.** If no genuine `1.85`-only requirement exists, the floor
  could be lowered and CI-verified to widen the audience.
