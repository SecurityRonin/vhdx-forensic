# vhdx-forensic — Validation Report

This document records the ground-truth validation of the `vhdx-forensic` parser against
independently created disk images and an independent reference tool (`qemu-img`).

**Validation date**: 2026-05-21  
**Crate version**: 0.1.x  
**Rust toolchain**: stable (1.85+)  
**Platform**: macOS Darwin 24.6.0 (Apple Silicon)

---

## Methodology

### Doer-checker principle

Tests written against images created by the same codebase can share the same blind spots —
both the image builder and the parser encode the same incorrect assumption, so the tests
pass while the implementation is wrong against real-world inputs.

To avoid this, all validation images were created by independent tools:

- **log2timeline/dfvfs corpus** — images created by the dfvfs toolchain, not by vhdx-forensic
- **QEMU v11.0.0** — images created by `qemu-img create`, not by vhdx-forensic

### Zero false-positive baseline

For every real image, we assert that `VhdxIntegrity::analyse()` produces no `Error` or
`Critical` anomalies. A false positive here would mean our analyser incorrectly flags a
legitimate, tool-created image as corrupt.

### Cross-tool field validation

For images that `qemu-img info` can open, we cross-validate the `VirtualDiskSize` field
reported by our parser against the value reported by qemu-img. Agreement proves our
metadata parsing is correct against at least one independent implementation.

### Detection capability via injection

We inject corruptions at spec-mandated byte offsets (MS-VHDX §2.0) into known-good QEMU
images and assert that `VhdxIntegrity::analyse()` detects the expected anomaly variant.
Using spec-mandated offsets (not parser-derived offsets) eliminates circular dependency
between the injection and the detection.

---

## Test environment

| Component | Version |
|---|---|
| Rust toolchain | stable 1.85+ |
| qemu-img (cross-validator) | QEMU v11.0.0 (Homebrew) |
| Platform | macOS Darwin 24.6.0 |
| Test runner | `cargo test` |

---

## Test images — provenance and checksums

All images are committed to `tests/data/`. SHA-256 checksums:

| Filename | Source | SHA-256 |
|---|---|---|
| `ext2.vhdx` | log2timeline/dfvfs | `d729323aafb2a7473e39abe9382076014d99a0c16e8333b9decbd81d355b1087` |
| `fat-parent.vhdx` | log2timeline/dfvfs | `4b2a44f5db544a36c234c2901263107ca18618988c41f6a92b9e264ca8c955ff` |
| `fat-differential.vhdx` | log2timeline/dfvfs | `6e8d17db1be6c7390c2123f4c46ce57e9ad8391b2a74841973e0d07293bcb873` |
| `ext2.vhd` | log2timeline/dfvfs | `225f16a8d65ba442fbd9958606b60bb6001b33be024b90661baffd67f3210230` |
| `qemu_empty_dynamic.vhdx` | QEMU v11.0.0 | `9538ddee49e5d213564d3356b5ebc5422d08e4cdd96b868c28ab67951f6160af` |
| `qemu_fixed.vhdx` | QEMU v11.0.0 | `918b40b57e9b2302e6c178fa6141cd6da369231d8e3a42a955f4840d27acee71` |

Verify with: `shasum -a 256 tests/data/*.vhdx tests/data/*.vhd`

---

## Per-image validation results

### ext2.vhdx — QEMU v5.2, ext2 filesystem, 512-byte logical sectors, dynamic

**Origin**: log2timeline/dfvfs Apache-2.0 corpus  
**Generation**: `qemu` v5.2 (independent of vhdx-forensic)

| Check | Expected | Result |
|---|---|---|
| `VhdxReader::from_bytes()` opens without error | yes | PASS |
| `VirtualDiskSize` reported by our parser | 4,194,304 bytes (4 MiB) | PASS |
| `VirtualDiskSize` reported by `qemu-img info` | 4,194,304 bytes (4 MiB) | agree |
| `VhdxIntegrity::analyse()` — no Error/Critical anomalies | zero | PASS |
| `VhdxIntegrity::check_bat_ghost_data()` — no ghost-data anomalies | zero | PASS |

qemu-img cross-validation:
```
$ qemu-img info tests/data/ext2.vhdx
image: ext2.vhdx
file format: vhdx
virtual size: 4 MiB (4194304 bytes)
disk size: 14 MiB
cluster_size: 8388608
```

---

### fat-parent.vhdx — FAT filesystem, standalone parent disk

**Origin**: log2timeline/dfvfs Apache-2.0 corpus  
**Generation**: dfvfs toolchain (independent of vhdx-forensic)

| Check | Expected | Result |
|---|---|---|
| `VhdxReader::from_bytes()` opens without error | yes | PASS |
| `VirtualDiskSize` reported by our parser | 4,194,304 bytes (4 MiB) | PASS |
| `VirtualDiskSize` reported by `qemu-img info` | 4,194,304 bytes (4 MiB) | agree |
| `VhdxIntegrity::analyse()` — no Error/Critical anomalies | zero | PASS |

qemu-img cross-validation:
```
$ qemu-img info tests/data/fat-parent.vhdx
image: fat-parent.vhdx
file format: vhdx
virtual size: 4 MiB (4194304 bytes)
disk size: 6 MiB
cluster_size: 2097152
```

---

### fat-differential.vhdx — FAT differencing disk, references fat-parent.vhdx

**Origin**: log2timeline/dfvfs Apache-2.0 corpus  
**Generation**: dfvfs toolchain (independent of vhdx-forensic)  
**Note**: `qemu-img` v11 cannot open this image ("Operation not supported") — it was
created by a tool that uses a parent-locator format qemu does not support.

| Check | Expected | Result |
|---|---|---|
| `VhdxReader::from_bytes()` returns an error | yes (`DifferencingNotSupported`) | PASS |
| `VhdxIntegrity::analyse()` — no Error/Critical anomalies | zero | PASS |
| `VhdxIntegrity::analyse()` emits `DifferencingDisk` (Warning) | yes | PASS |

`VhdxReader` correctly refuses differencing disks because it cannot serve accurate logical
data without the parent chain. `VhdxIntegrity` still analyses the raw bytes and correctly
identifies the disk as a differencing disk via the `HasParent` metadata flag.

---

### ext2.vhd — Legacy VHD format (not VHDX)

**Origin**: log2timeline/dfvfs Apache-2.0 corpus

| Check | Expected | Result |
|---|---|---|
| `VhdxReader::from_bytes()` returns an error | yes (`InvalidMagic`) | PASS |

VHD files begin with `conectix` (footer) rather than `vhdxfile\0\0...`. The parser
correctly rejects this without panicking.

---

### qemu_empty_dynamic.vhdx — QEMU v11.0.0, empty dynamic, 16 MiB virtual

**Origin**: Generated locally  
**Command**: `qemu-img create -f vhdx qemu_empty_dynamic.vhdx 16M`

| Check | Expected | Result |
|---|---|---|
| `VhdxReader::from_bytes()` opens without error | yes | PASS |
| `VirtualDiskSize` reported by our parser | 16,777,216 bytes (16 MiB) | PASS |
| `VirtualDiskSize` reported by `qemu-img info` | 16,777,216 bytes (16 MiB) | agree |
| `VhdxIntegrity::analyse()` — no Error/Critical anomalies | zero | PASS |

qemu-img cross-validation:
```
$ qemu-img info tests/data/qemu_empty_dynamic.vhdx
image: qemu_empty_dynamic.vhdx
file format: vhdx
virtual size: 16 MiB (16777216 bytes)
disk size: 6 MiB
cluster_size: 8388608
```

This image is also used as the base for all injection tests — its known-good structure
provides a clean baseline into which corruptions are injected.

---

### qemu_fixed.vhdx — QEMU v11.0.0, fixed provisioning, 8 MiB virtual

**Origin**: Generated locally  
**Command**: `qemu-img create -f vhdx -o subformat=fixed qemu_fixed.vhdx 8M`

| Check | Expected | Result |
|---|---|---|
| `VhdxReader::from_bytes()` opens without error | yes | PASS |
| `VirtualDiskSize` reported by our parser | 8,388,608 bytes (8 MiB) | PASS |
| `VirtualDiskSize` reported by `qemu-img info` | 8,388,608 bytes (8 MiB) | agree |
| `VhdxIntegrity::analyse()` — no Error/Critical anomalies | zero | PASS |

qemu-img cross-validation:
```
$ qemu-img info tests/data/qemu_fixed.vhdx
image: qemu_fixed.vhdx
file format: vhdx
virtual size: 8 MiB (8388608 bytes)
disk size: 16 MiB
cluster_size: 8388608
```

Fixed disks have a structurally different BAT layout from dynamic images: all payload BAT
entries are in `FULLY_PRESENT` state and all SectorBitmap entries are allocated. This
validates our BAT parser handles both provisioning models without false positives.

---

## Detection capability — injection tests

Each test takes `qemu_empty_dynamic.vhdx` (known-good), injects a corruption at a
**spec-mandated byte offset** (MS-VHDX §2.0 — not a parser-derived offset), then asserts
`VhdxIntegrity::analyse()` reports the expected anomaly variant.

Using spec-mandated offsets eliminates circular dependency: the injection does not depend
on our parser, so the test cannot share a blind spot with the detection.

| Test | Injected corruption | Spec offset | Expected anomaly | Result |
|---|---|---|---|---|
| `detect_bad_magic_in_real_image` | Fill `[0..8]` with `0xFF` | §2.1 — FileIdentifier magic | `BadMagic { .. }` | PASS |
| `detect_header_crc_mismatch_in_real_image` | Flip bit at `0x0001_0010` (header 1 payload, past CRC field at `0x1_0004`) | §2.2 — Header 1 at `0x0001_0000` | `HeaderChecksumMismatch { copy: 1, .. }` | PASS |
| `detect_region_table_crc_mismatch_in_real_image` | Fill `[0x0003_0000..0x0003_0004]` with `0xFF` (overwrite "regi" signature) | §2.3 — Region Table 1 at `0x0003_0000` | `RegionTableChecksumMismatch { .. }` or `BothRegionTableCopiesInvalid` | PASS |
| `detect_container_truncated_in_real_image` | Slice to 256 KiB (below 320 KiB structural minimum) | §2.0 — 5 × 64 KiB mandatory blocks | `ContainerTruncated { .. }` | PASS |

VHDX structural layout (MS-VHDX §2.0):

```
Offset          Size     Region
0x0000_0000     1 MB     File Identifier (magic "vhdxfile\0\0\0\0\0\0\0\0" at bytes 0..8)
0x0001_0000     64 KB    Header 1 (CRC32C at bytes 4..8 of the header block)
0x0002_0000     64 KB    Header 2
0x0003_0000     64 KB    Region Table 1 (signature "regi" at bytes 0..4)
0x0004_0000     64 KB    Region Table 2
0x0010_0000+             Data regions (BAT, Metadata, Log, Data blocks)
```

---

## Summary

| Image | Opens | VirtualDiskSize | No FP | Result |
|---|---|---|---|---|
| ext2.vhdx (dfvfs, QEMU v5.2) | yes | 4 MiB — agrees with qemu-img | yes | PASS |
| fat-parent.vhdx (dfvfs) | yes | 4 MiB — agrees with qemu-img | yes | PASS |
| fat-differential.vhdx (dfvfs) | refused (correct) | n/a — differencing disk | yes | PASS |
| ext2.vhd (dfvfs, VHD format) | refused (correct) | n/a — not VHDX | yes | PASS |
| qemu_empty_dynamic.vhdx (QEMU v11) | yes | 16 MiB — agrees with qemu-img | yes | PASS |
| qemu_fixed.vhdx (QEMU v11, fixed) | yes | 8 MiB — agrees with qemu-img | yes | PASS |

| Detection test | Injected at | Detected as | Result |
|---|---|---|---|
| Bad magic | §2.1 offset 0..8 | `BadMagic` | PASS |
| Header CRC mismatch | §2.2 offset 0x1_0010 | `HeaderChecksumMismatch` | PASS |
| Region table CRC mismatch | §2.3 offset 0x3_0000..0x3_0004 | `RegionTableChecksumMismatch` / `BothRegionTableCopiesInvalid` | PASS |
| Container truncated | Slice to 256 KiB | `ContainerTruncated` | PASS |

All 138 tests pass. Zero false positives on six real images from two independent sources.
Four detection capability probes all pass against real QEMU-generated images.

---

## How to reproduce

```bash
cd /path/to/vhdx-forensic

# Verify image checksums
shasum -a 256 tests/data/*.vhdx tests/data/*.vhd

# Run the full test suite
cargo test

# Run only the compatibility and real-image tests
cargo test --test libvhdi_compat
cargo test --test real_images

# Cross-validate with qemu-img (requires QEMU installed)
qemu-img info tests/data/ext2.vhdx
qemu-img info tests/data/fat-parent.vhdx
qemu-img info tests/data/qemu_empty_dynamic.vhdx
qemu-img info tests/data/qemu_fixed.vhdx
```

To re-download the dfvfs corpus images if needed:

```bash
cd tests/data
BASE=https://github.com/log2timeline/dfvfs/raw/main/test_data
curl -OL $BASE/ext2.vhdx
curl -OL $BASE/fat-parent.vhdx
curl -OL $BASE/fat-differential.vhdx
curl -OL $BASE/ext2.vhd
shasum -a 256 ext2.vhdx fat-parent.vhdx fat-differential.vhdx ext2.vhd
```
