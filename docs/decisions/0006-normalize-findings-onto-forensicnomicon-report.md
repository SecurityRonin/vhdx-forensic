# 6. Findings normalized onto `forensicnomicon::report`

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the fleet emits its findings through the single
`forensicnomicon::report` model so ORCHESTRATION (Issen, disk4n6) and a future
GUI render them uniformly, instead of N bespoke `XxxAnalysis` types (the
Reporting Model in `ronin-issen/CLAUDE.md`). VHDX originally used a native 4-level
severity scale. Commits `3f3bd94` (RED) / `e2f1433`
("feat(vhdx-forensic)!: normalize onto forensicnomicon::report (4->5 re-grade)")
migrated it — a breaking change, hence the `!`.

## Decision

- Depend on `forensicnomicon` (`forensic/Cargo.toml`) and implement
  `forensicnomicon::report::Observation for VhdxIntegrityAnomaly`
  (`forensic/src/integrity.rs` ~line 2381), so each of the 63 anomaly variants
  converts to a canonical `Finding` in one place while the crate keeps its typed
  `VhdxIntegrityAnomaly` domain enum.
- Adopt the canonical 5-level `forensicnomicon::report::Severity`
  (`Info < Low < Medium < High < Critical`); the native 4-level scale is
  re-graded per variant (e.g. `LogSequenceNumberGap → High`,
  `GhostDataInAbsentBlock → Medium`, `DirtyLog → Info`) — a forensic judgment per
  code, not a blanket rename.
- Each anomaly carries a stable scheme-prefixed `code`
  (`VHDX-BAD-MAGIC`, `VHDX-REGIONS-OVERLAP`, `VHDX-FILE-WRITE-GUID-ALL-ZEROS`, …),
  a `forensic_significance()` narrative, and `mitre_techniques()` surfaced as
  "consistent with" — observations, never legal conclusions.

## Consequences

- VHDX findings aggregate into one `forensicnomicon::report::Report` alongside
  every other analyzer; no bespoke rendering.
- `code` strings are a published contract (never change a shipped code; new
  variants get new codes).
- The `!` re-grade was a deliberate breaking change gated behind a RED→GREEN test
  pair, versioned accordingly.
