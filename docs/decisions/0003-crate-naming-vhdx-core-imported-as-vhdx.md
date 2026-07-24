# 3. Reader published as `vhdx-core`, imported as `vhdx`

Date: 2026-07-24
Status: Accepted

## Context

The fleet naming grammar (`ronin-issen/CLAUDE.md` → "Crate naming grammar")
requires a single-format reader to be `<x>-core` and its analyzer `<x>-forensic`.
The bare crate name `vhdx` on crates.io was not available for our reader, so
publishing under the bare word was not an option. Commit `7975ed4`
("docs: point the reader link at vhdx-core (renamed crate/repo)") records the
rename from the pre-split single crate to the `-core` form.

## Decision

- Publish the reader as **`vhdx-core`** (`core/Cargo.toml` →
  `name = "vhdx-core"`), and keep the ergonomic import path via
  `[lib] name = "vhdx"` so consumers write `use vhdx::VhdxReader;` unchanged.
- Publish the analyzer as **`vhdx-forensic`** (`forensic/Cargo.toml`).
- The `cli` binary is named `vhdx` (`[[bin]] name = "vhdx"`) — the debug tool's
  invocation, independent of the published crate name.
- The inter-crate dependency is declared once in `[workspace.dependencies]`:
  `vhdx = { path = "core", version = "0.3.0", package = "vhdx-core" }`, so a
  version bump is one line and the import name stays `vhdx`.

## Consequences

- `vhdx-core` is self-describing on crates.io (reader half of the
  `vhdx-forensic` suite) while consumer code keeps the short `vhdx::` path — the
  naming-grammar recipe for a taken bare name.
- The reader is versioned and published independently of the analyzer; dependents
  should prefer the registry version over the workspace `path` once published
  (Dependency Preference).
