//! Adversarial robustness tests for `vhdx-forensic`.
//!
//! Each test crafts a VHDX whose CRC32C-protected regions are valid (so the
//! parser reaches semantic parsing) but whose metadata or BAT fields contain
//! out-of-spec values that must be rejected cleanly rather than panicking.
//!
//! RED: all tests fail (parser trusts raw field values without validation).
//! GREEN: all tests pass after validation is added to reader/metadata/region.

use vhdx_forensic::{VhdxError, VhdxReader};

mod builder;
use builder::VhdxBuilder;

// Helper: open and assert the parse fails with the expected variant.
macro_rules! assert_parse_err {
    ($data:expr, $pat:pat) => {{
        let err = VhdxReader::from_bytes($data).expect_err("expected from_bytes to return Err");
        assert!(
            matches!(err, $pat),
            "expected {}, got {:?}",
            stringify!($pat),
            err
        );
    }};
}

// ── Test 1: BlockSize = 0 ─────────────────────────────────────────────────────
// Divide-by-zero in chunk_ratio() / data_block_count() if not caught at parse.

#[test]
fn block_size_zero_is_rejected() {
    let data = VhdxBuilder::new(512).with_meta_block_size(0).build();
    assert_parse_err!(data, VhdxError::InvalidMetadata(_));
}

// ── Test 2: BlockSize not a power of two ──────────────────────────────────────
// Violates MS-VHDX §2.5.5; produces a wrong chunk_ratio.

#[test]
fn block_size_not_power_of_two_is_rejected() {
    let data = VhdxBuilder::new(512)
        .with_meta_block_size(3 * 1024 * 1024) // 3 MB — not 2^n
        .build();
    assert_parse_err!(data, VhdxError::InvalidMetadata(_));
}

// ── Test 3: BlockSize below 1 MB minimum ─────────────────────────────────────
// Spec requires BlockSize ∈ [1 MB, 256 MB].

#[test]
fn block_size_below_minimum_is_rejected() {
    let data = VhdxBuilder::new(512)
        .with_meta_block_size(512 * 1024) // 512 KB — below 1 MB
        .build();
    assert_parse_err!(data, VhdxError::InvalidMetadata(_));
}

// ── Test 4: BlockSize above 256 MB maximum ────────────────────────────────────

#[test]
fn block_size_above_maximum_is_rejected() {
    let data = VhdxBuilder::new(512)
        .with_meta_block_size(512 * 1024 * 1024) // 512 MB — above 256 MB
        .build();
    assert_parse_err!(data, VhdxError::InvalidMetadata(_));
}

// ── Test 5: LogicalSectorSize = 0 ────────────────────────────────────────────
// chunk_ratio = (2^23 * 0) / block_size = 0 → division by zero in BAT index.

#[test]
fn logical_sector_size_zero_is_rejected() {
    let data = VhdxBuilder::new(512).with_meta_sector_size(0).build();
    assert_parse_err!(data, VhdxError::InvalidMetadata(_));
}

// ── Test 6: LogicalSectorSize neither 512 nor 4096 ───────────────────────────
// Spec requires exactly 512 or 4096 bytes.

#[test]
fn logical_sector_size_invalid_is_rejected() {
    let data = VhdxBuilder::new(512).with_meta_sector_size(1024).build();
    assert_parse_err!(data, VhdxError::InvalidMetadata(_));
}

// ── Test 7: VirtualDiskSize = 0 ──────────────────────────────────────────────
// Spec requires VirtualDiskSize > 0.

#[test]
fn virtual_disk_size_zero_is_rejected() {
    let data = VhdxBuilder::new(512).with_meta_vdisk_size(0).build();
    assert_parse_err!(data, VhdxError::InvalidMetadata(_));
}

// ── Test 8: VirtualDiskSize exceeds the 64 TiB spec limit ────────────────────

#[test]
fn virtual_disk_size_exceeds_limit_is_rejected() {
    let beyond_64tib: u64 = 64 * (1u64 << 40) + 1;
    let data = VhdxBuilder::new(512)
        .with_meta_vdisk_size(beyond_64tib)
        .build();
    assert_parse_err!(data, VhdxError::InvalidMetadata(_));
}

// ── Test 9: BAT region file_offset pointing beyond the container ──────────────
// Region table CRC is valid (re-CRC'd by builder), but BAT is beyond EOF.
// Should fail with OffsetOutOfBounds, not the misleading BatRegionMissing.

#[test]
fn bat_region_offset_beyond_container_is_rejected() {
    // 0x0100_0000_0000 ≈ 1 TiB — safely beyond any in-memory test image.
    let data = VhdxBuilder::new(512)
        .with_region_bat_offset(0x0100_0000_0000)
        .build();
    assert_parse_err!(data, VhdxError::OffsetOutOfBounds);
}

// ── Test 10: Container too small to hold required VHDX structures ─────────────
// A file that passes the magic check but is missing headers/region tables.

#[test]
fn container_too_small_is_rejected() {
    // Just the file magic — nothing else.
    let mut tiny = vec![0u8; 512];
    tiny[0..8].copy_from_slice(b"vhdxfile");
    assert_parse_err!(tiny, VhdxError::ContainerTooSmall(_));
}
