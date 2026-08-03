# Validation

`vhdx-forensic` parses untrusted VHDX containers from potentially compromised
disk images. Correctness is therefore established the way forensic tooling must
be: against **independent oracles** (a different tool, or a different code path,
that already decodes the same bytes correctly) on **real third-party corpora**
with known ground truth — never against fixtures we hand-encoded and then graded
ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. Per-file provenance (source, download
URL, hashes, license) lives in [`tests/data/SOURCES.md`](https://github.com/SecurityRonin/vhdx-forensic/blob/main/core/tests/data/SOURCES.md);
the fleet-wide machine index is `issen/docs/corpus-catalog.md`. This page
cross-references both rather than duplicating them.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **`qemu-img convert -O raw`** | Yes — separate C codebase (QEMU) | The decoded virtual byte stream: `VhdxReader` output sampled every 64 KiB (plus near-end) must be **byte-identical** to QEMU's raw conversion of the same image | 1 |
| **`qemu-img info`** | Yes — same separate codebase | `virtual_disk_size()` (metadata `VirtualDiskSize` parsing) matches QEMU's reported virtual size, image-by-image | 1 |

The byte-level `qemu-img convert -O raw` differential is the load-bearing
correctness oracle: a reader that mis-decodes the BAT, sector bitmap, or block
state would diverge from QEMU's raw stream at some sampled offset and fail. It is
gated on `qemu-img` being installed and skips cleanly otherwise.

No third-party *forensic-analysis* oracle is wired in for the anomaly detector
itself. Detection capability is instead established by injection at
spec-mandated offsets (Tier 2, below); an independent corpus oracle (e.g. a
`libvhdi` differential decode) is a documented gap — see *Gaps and in-progress
work*.

## Independent test corpora

The dfvfs images are third-party, publicly distributed, and carry independently
established ground truth; the QEMU images are generated locally from a documented
command line (their ground truth derives from the construction). All committed
images are tracked in [`tests/data/SOURCES.md`](https://github.com/SecurityRonin/vhdx-forensic/blob/main/core/tests/data/SOURCES.md)
with SHA-256 hashes.

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **log2timeline/dfvfs** (`ext2.vhdx`, `fat-parent.vhdx`, `fat-differential.vhdx`, `ext2.vhd`) | [github.com/log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) `test_data/` (QEMU- and dfvfs-toolchain-generated) | Zero-false-positive baseline, differencing-disk + parent-chain handling, VHD-format rejection; `qemu-img` byte/size differential | **Apache-2.0** (committed with attribution) |
| **QEMU v11.0.0** (`qemu_empty_dynamic.vhdx`, `qemu_fixed.vhdx`) | Generated locally — `qemu-img create -f vhdx …` | Zero-FP baseline on dynamic + fixed provisioning; base image for spec-offset injection detection tests | Generated; redistribution unrestricted (committed) |

## Per-capability validation

### Virtual byte-stream decode (BAT / blocks / sectors) — Tier 1

`core/tests/corpus_differential.rs` opens each committed image with `VhdxReader`
and asserts the decoded stream is **byte-identical to `qemu-img convert -O raw`**
of the same image — first that `virtual_disk_size()` equals the reference raw
length, then sampling every 64 KiB across block and sector boundaries plus a
near-end read (`corpus_ext2_vhdx_matches_qemu_raw`,
`corpus_qemu_fixed_vhdx_matches_qemu_raw`,
`corpus_fat_parent_vhdx_matches_qemu_raw`). QEMU and `vhdx-core` share no code, so
a decode bug surfaces as a mismatch. The test skips when `qemu-img` is absent.

### `VirtualDiskSize` metadata parsing — Tier 1

`virtual_disk_size()` is cross-validated against **`qemu-img info`** image-by-image:
`ext2.vhdx` → 4 MiB, `qemu_empty_dynamic.vhdx` → 16 MiB, `qemu_fixed.vhdx` → 8 MiB
(`forensic/tests/real_images.rs`, `forensic/tests/libvhdi_compat.rs`,
`core/tests/compat.rs`, `core/tests/real_images.rs`). Agreement with an
independent tool establishes the metadata table walk decodes the right item.

### Zero false positives on real images — Tier 1 input

`VhdxIntegrity::analyse()` produces **no Error/Critical anomaly** on any image a
separate tool created. `forensic/tests/libvhdi_compat.rs` asserts this for the
dfvfs `ext2.vhdx` and `fat-parent.vhdx`; `forensic/tests/real_images.rs` asserts
it for the QEMU `qemu_empty_dynamic.vhdx` and `qemu_fixed.vhdx`
(`*_no_error_anomalies`), and `dfvfs_ext2_vhdx_ghost_data_clean` confirms
`check_bat_ghost_data()` is clean. Flagging a valid third-party image as corrupt
would be a false positive; these tests forbid it. The corpus is independent
(Tier 1); the "clean" expectation derives from the images being known-good.

### Differencing-disk + parent-chain handling — Tier 1 input

On the dfvfs differencing image (`fat-differential.vhdx`, which references
`fat-parent.vhdx`): `core/tests/compat.rs::fat_differential_vhdx_refused` and
`core/tests/differential.rs::from_bytes_still_refuses_differencing_disk` confirm
`from_bytes` refuses a child with no parent (preventing silent data loss);
`core/tests/differential.rs` confirms `from_bytes_with_parent` opens the chain,
reads sector 0, and reports the parent's virtual size. The same test reads three
sectors across the child's first partially-present payload block: bitmap sectors
133 and 135 resolve to the parent, while sector 134 resolves to the child and
contains the corpus byte `0xff` at virtual offset `0x10c06`. This prevents a
partial block from being incorrectly collapsed to the parent as a whole.
`bulk_read_of_partial_block_matches_sector_at_a_time` reads 96 sectors spanning
the same block in one call and asserts the result is byte-identical to resolving
each sector individually, so serving a run of same-owner sectors per bitmap byte
cannot change what is read.

Every block in this fixture lives in chunk 0, which reduces the chunk arithmetic
to multiplication by zero. `core/src/bat.rs::tests` therefore drives a synthetic
BAT at the largest legal block size (256 MB, chunk ratio 16) so payload and
sector-bitmap entries resolve in chunk 1: block 17 is BAT index 18 and its chunk
bitmap is index 33. The same tests pin the payload-state routing — only
`PAYLOAD_BLOCK_NOT_PRESENT` defers to the parent, while `PAYLOAD_BLOCK_UNDEFINED`,
`PAYLOAD_BLOCK_ZERO`, and `PAYLOAD_BLOCK_UNMAPPED` read as zeros, since consulting
the parent for a block the child describes as empty would resurrect replaced data.
A BAT too short to describe a block is treated as not-present rather than failing
the read.

`VhdxIntegrity` still analyses the raw child and emits `DifferencingDisk`
(Warning), asserted in `libvhdi_compat.rs`. The fixtures are independently
created; the expected behaviour follows from the differencing-disk format and
its sector bitmap.

### Legacy-VHD rejection — Tier 1 input

`core/tests/compat.rs::ext2_vhd_rejected` and
`core/tests/real_images.rs::ext2_vhd_is_rejected_by_vhdx_reader` reject the dfvfs
`ext2.vhd` (a legacy VHD `conectix` footer, not a VHDX `vhdxfile` header) with
`Err`, not a panic or silent misread.

### Log replay (dirty-log recovery) — Tier 2

`core/tests/log_replay.rs` builds a 5 MB image carrying one `loge` entry that
patches the first data byte from `0x00` to `0xAB`, then asserts the reader returns
`0xAB` (`log_replay_patches_data_byte`) and that an identical image with `LogGuid`
zeroed returns `0x00` (`clean_image_unaffected_by_log_module`). Ground truth is
derivable from the documented construction (we know the patch byte), and the test
exercises the real replay path — but we authored the scenario, so it is Tier 2,
not an independent-oracle claim.

### Anomaly detection — Tier 2 (spec-offset injection)

`forensic/tests/real_images.rs` takes a **known-good QEMU image** and injects a
single corruption at a **spec-mandated MS-VHDX §2.0 byte offset** — never a
parser-derived offset, so the injection cannot share a blind spot with the
detector — then asserts the expected anomaly fires:

| Test | Injection (MS-VHDX §2.0 offset) | Expected anomaly |
|---|---|---|
| `detect_bad_magic_in_real_image` | `[0..8]` ← `0xFF` (FileIdentifier magic, §2.1) | `BadMagic` |
| `detect_header_crc_mismatch_in_real_image` | flip bit at `0x0001_0010` (Header 1 body past CRC field, §2.2) | `HeaderChecksumMismatch { copy: 1, .. }` |
| `detect_region_table_crc_mismatch_in_real_image` | overwrite `regi` signature at `[0x0003_0000..0x0003_0004]` (§2.3) | `RegionTableChecksumMismatch` / `BothRegionTableCopiesInvalid` |
| `detect_container_truncated_in_real_image` | slice below the 5 × 64 KiB structural minimum (§2.0) | `ContainerTruncated` |

The base image is real; the injection sites come from the spec; so this is a
genuine on-real-data check of the detector — Tier 2 because we chose the
corruption rather than an independent tool authoring it.

### Adversarial field validation & repair — Tier 3

`forensic/tests/robustness_tests.rs`, `integrity_tests.rs`, and `repair_tests.rs`
drive the synthetic `VhdxBuilder` to inject one out-of-spec field per test
(`BlockSize` = 0 / non-power-of-two / outside `[1 MB, 256 MB]`; `LogicalSectorSize`
∉ {512, 4096}; `VirtualDiskSize` = 0 or > 64 TiB; BAT/region offsets beyond the
container) and assert a clean typed `Err` or the expected anomaly, never a panic.
Both fixture and expected answer are authored here, so these are Tier 3:
per-branch coverage of the validation arms and the CRC-rebuild repair path, not a
correctness claim against real-world bytes. They are the structural complement to
the real-image and fuzzing checks above.

### Robustness — never panic, never over-read

The analyser is fuzzed: `forensic/fuzz/fuzz_targets/parse_vhdx.rs` drives both
`VhdxIntegrity::new(data).analyse()` and `check_bat_ghost_data()` on arbitrary
bytes with the invariant "must not panic"; a `fuzz.yml` CI workflow builds and
smoke-runs the target. Production code is panic-free — no `.unwrap()`/`.expect()`/
`panic!` or unchecked indexing (`unwrap_used`/`expect_used` are hard `deny`
lints) — and every length, offset, and count is bounds-checked before arithmetic,
with BAT addressing using `checked_mul`/`checked_add`.

## Gaps and in-progress work

- **No independent forensic-analysis oracle.** Detection is validated by
  spec-offset injection (Tier 2) and the dfvfs no-false-positive baseline (Tier 1
  corpus), but no third-party analyser cross-checks the *findings* themselves. A
  `libvhdi` ([libyal/libvhdi](https://github.com/libyal/libvhdi)) differential —
  decoding the same images and reconciling structure — would lift the detector's
  evidence to a third-party Tier 1 oracle. Recommended.
- **Log replay is Tier 2 only.** A real dirty-log VHDX captured from Hyper-V (with
  an independent tool confirming the post-replay bytes) would lift log replay to
  Tier 1; the current evidence is a self-authored construction.

## Reproducing the validation

The committed corpus tests run with `cargo test`. The byte-level `qemu-img`
differential additionally requires `qemu-img` on `PATH` (Homebrew
`/opt/homebrew/bin/qemu-img`); those tests skip cleanly when it is absent.

```bash
# Verify committed image checksums (hashes in core/tests/data/SOURCES.md)
shasum -a 256 core/tests/data/*.vhdx core/tests/data/*.vhd

# Reader compat + real-image suite (always-on; size cross-checks)
cargo test -p vhdx-core --test compat --test real_images --test differential

# Byte-identical differential vs `qemu-img convert -O raw` (needs qemu-img)
cargo test -p vhdx-core --test corpus_differential

# Forensic zero-FP + spec-offset injection detection on real images
cargo test -p vhdx-forensic --test libvhdi_compat --test real_images

# Adversarial field validation + repair (synthetic builder)
cargo test -p vhdx-forensic --test robustness_tests --test integrity_tests --test repair_tests

# Optional external corpus directory (set CORPUS_DIR to a dir with dynamic.vhdx)
CORPUS_DIR=/path/to/corpus cargo test -p vhdx-core --test corpus

# Re-cross-validate sizes by hand
qemu-img info core/tests/data/ext2.vhdx
qemu-img info core/tests/data/qemu_empty_dynamic.vhdx
qemu-img info core/tests/data/qemu_fixed.vhdx
```

To re-fetch the dfvfs corpus or regenerate the QEMU images, follow
[`core/tests/data/SOURCES.md`](https://github.com/SecurityRonin/vhdx-forensic/blob/main/core/tests/data/SOURCES.md#re-downloading).

## Coverage & fuzzing as backstops

Line coverage is enforced in CI (`cargo llvm-cov`, failing on any zero-hit line
not annotated `// cov:unreachable`). Coverage is a regression backstop that proves
behavior is exercised — it is not the correctness claim. The oracles above are.
