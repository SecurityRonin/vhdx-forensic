# 5. Panic-free parsing: deny lints + bounds-checked byte readers

Date: 2026-07-24
Status: Accepted

## Context

A VHDX file is untrusted input; a length or offset field can point anywhere. The
fleet's panic-free posture (Rust Lint Posture + Paranoid Gatekeeper) requires
untrusted-input parsers to deny `unwrap`/`expect` and to read integer fields
through bounds-checked helpers that never panic. Commit `0b98ed6`
("refactor: enforce panic-free parsing with unwrap_used/expect_used deny lints")
established this posture.

## Decision

- Deny the panic lints workspace-wide (`Cargo.toml` → `[workspace.lints.clippy]`
  `unwrap_used = "deny"`, `expect_used = "deny"`; `correctness`/`suspicious`
  denied), with the standard `#![cfg_attr(test, allow(...))]` escape for tests.
- Every integer/array field read goes through bounds-checked helpers that return
  `0` (or an all-zero array) out of range rather than indexing past the slice
  (`core/src/bytes.rs` `le_u16/le_u32/le_u64/le_arr16`; the analyzer's in-situ
  `r16/r32/r64` in `forensic/src/integrity.rs`). A zero on truncated input is a
  safe non-matching sentinel because callers range-check before acting.
- BAT addressing uses `checked_mul`/`checked_add`; all length/offset/count fields
  are validated before arithmetic (README "Trust but verify"). A `cargo-fuzz`
  target (`forensic/fuzz/parse_vhdx`) exercises the analyzer's in-situ
  parse-and-analyse path (`VhdxIntegrity::analyse` + `check_bat_ghost_data`) with
  the invariant "must not panic." The `vhdx-core` reader's structural decode path
  is not yet fuzzed — a gap against the fleet "one target per parsed structure"
  standard.

## Consequences

- Crafted input yields graded findings, never a panic — the analyzer path
  verified empirically by fuzzing, and both paths structurally by the deny lints
  (the `vhdx-core` reader is covered by the lints but not yet by a fuzz target).
- **Divergence from the fleet `safe-read` standard, recorded honestly:** the
  fleet standard says route fixed-width reads through the published `safe-read`
  crate and never hand-roll a per-crate `bytes.rs`. This repo currently hand-rolls
  bounds-checked readers in two places (`core/src/bytes.rs` and the analyzer's
  `r*` helpers). The behavior matches `safe-read`'s 0-out-of-range contract, but
  migrating both onto `safe-read` (re-exported transitively via `forensic-vfs`)
  remains open technical debt. Rationale for the original hand-roll is not
  recovered from history; it predates or diverges from the `safe-read` policy.
