# 7. Validate against independent oracles (qemu-img, dfvfs)

Date: 2026-07-24
Status: Accepted

## Context

A parser validated only with fixtures the author encoded inherits the author's
blind spots (the Doer-Checker / Evidence-Based Rigor disciplines; the fleet
Test-Data Provenance standard). VHDX correctness must be proven against artifacts
produced by an independent codebase. Commits `6928014` (RED) / `44aca4b`
("fix(compat): parse real QEMU v5.2 VHDX files correctly") show real QEMU images
driving a compatibility fix, and `37a80c3` added `docs/validation.md`.

## Decision

- Validate the reader against **independently produced** images: the
  `log2timeline/dfvfs` corpus and QEMU output, documented in `docs/validation.md`
  with provenance (source, download, hash) per the fleet catalog.
- Prove the decoded stream **byte-identical to `qemu-img convert -O raw`** (an
  independent C codebase) and cross-check virtual disk sizes against
  `qemu-img info` — a tier-1 external oracle, not a self-authored round-trip.
- Prove *detection* by injecting corruptions at spec-mandated MS-VHDX §2.0 byte
  offsets into real QEMU images and asserting the expected anomaly codes.
- Keep the one repo-root `tests/data/` (consolidated in `250f513`/`140f272`);
  large corpora are gitignored and documented, small licensed fixtures committed.

## Consequences

- Reader correctness rests on an independent oracle, not on fixtures we encoded —
  the LZNT1-trap failure mode is avoided.
- Real-world QEMU quirks (e.g. v5.2 layout) are caught, as the `44aca4b` fix
  demonstrates.
- `docs/validation.md` is the standing Doer-Checker evidence backing the README's
  "Validated against real artifacts" claim.
