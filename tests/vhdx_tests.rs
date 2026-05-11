//! Integration tests for `vhdx-forensic`.
//!
//! Uses an in-memory `VhdxBuilder` that produces valid VHDX byte vectors,
//! allowing TDD without external disk images.

use std::io::{Read, Seek, SeekFrom};
use vhdx_forensic::{VhdxError, VhdxReader};

mod builder;
use builder::VhdxBuilder;

// ── Test 1: bad magic is rejected ────────────────────────────────────────────

#[test]
fn rejects_bad_magic() {
    let mut data = vec![0u8; 0x50_0000];
    data[0..8].copy_from_slice(b"notvalid");
    let err = VhdxReader::from_bytes(data).unwrap_err();
    assert!(
        matches!(err, VhdxError::BadMagic),
        "expected BadMagic, got {err:?}"
    );
}

// ── Test 2: minimal valid VHDX is accepted ────────────────────────────────────

#[test]
fn accepts_minimal_valid_vhdx() {
    let data = VhdxBuilder::new(64 * 1024).build();
    VhdxReader::from_bytes(data).expect("minimal VHDX should parse without error");
}

// ── Test 3: virtual_disk_size matches what was specified ───────────────────

#[test]
fn virtual_disk_size_matches() {
    let disk_size = 64 * 1024u64; // 64 KB virtual disk
    let data = VhdxBuilder::new(disk_size).build();
    let reader = VhdxReader::from_bytes(data).unwrap();
    assert_eq!(reader.virtual_disk_size(), disk_size);
}

// ── Test 4: logical sector size is 512 by default ────────────────────────────

#[test]
fn logical_sector_size_is_512() {
    let data = VhdxBuilder::new(64 * 1024).build();
    let reader = VhdxReader::from_bytes(data).unwrap();
    assert_eq!(reader.logical_sector_size(), 512);
}

// ── Test 5: reading all zeros from a sparse block ────────────────────────────

#[test]
fn read_sparse_block_returns_zeros() {
    let data = VhdxBuilder::new(512).build_sparse(); // no data blocks allocated
    let mut reader = VhdxReader::from_bytes(data).unwrap();
    let mut buf = [0xFFu8; 512];
    reader.read_exact(&mut buf).expect("read should succeed");
    assert!(
        buf.iter().all(|&b| b == 0),
        "sparse block should read as zeros"
    );
}

// ── Test 6: seek then read ────────────────────────────────────────────────────

#[test]
fn seek_then_read() {
    let sector_size = 512u64;
    let pattern = 0xABu8;
    let data = VhdxBuilder::new(sector_size * 4)
        .with_sector_data(1, vec![pattern; 512])
        .build();
    let mut reader = VhdxReader::from_bytes(data).unwrap();
    reader.seek(SeekFrom::Start(sector_size)).unwrap();
    let mut buf = [0u8; 512];
    reader
        .read_exact(&mut buf)
        .expect("read at sector 1 should succeed");
    assert!(
        buf.iter().all(|&b| b == pattern),
        "sector 1 should contain 0xAB pattern"
    );
}

// ── Test 7: read returns 0 at EOF ─────────────────────────────────────────────

#[test]
fn read_at_eof_returns_zero() {
    let data = VhdxBuilder::new(512).build();
    let mut reader = VhdxReader::from_bytes(data).unwrap();
    reader.seek(SeekFrom::End(0)).unwrap();
    let mut buf = [0u8; 512];
    let n = reader.read(&mut buf).unwrap();
    assert_eq!(n, 0, "read at EOF should return 0");
}

// ── Test 8: seek before start returns error ───────────────────────────────────

#[test]
fn seek_before_start_is_error() {
    let data = VhdxBuilder::new(512).build();
    let mut reader = VhdxReader::from_bytes(data).unwrap();
    let result = reader.seek(SeekFrom::Current(-1));
    assert!(result.is_err(), "seeking before start should fail");
}

// ── Test 9: data written into a block is read back correctly ──────────────────

#[test]
fn written_data_reads_back() {
    let mut payload = vec![0u8; 512];
    payload[0] = 0xDE;
    payload[1] = 0xAD;
    payload[510] = 0xBE;
    payload[511] = 0xEF;

    let data = VhdxBuilder::new(512)
        .with_sector_data(0, payload.clone())
        .build();
    let mut reader = VhdxReader::from_bytes(data).unwrap();
    let mut buf = vec![0u8; 512];
    reader.read_exact(&mut buf).unwrap();
    assert_eq!(
        &buf[..],
        &payload[..],
        "read-back data must match written data"
    );
}

// ── Test 10: multiple sequential reads span block boundaries ──────────────────

#[test]
fn sequential_reads_span_boundary() {
    // Two 512-byte sectors in the same data block, each with distinct patterns.
    let disk_size = 1024u64;
    let data = VhdxBuilder::new(disk_size)
        .with_sector_data(0, vec![0xAAu8; 512])
        .with_sector_data(1, vec![0xBBu8; 512])
        .build();
    let mut reader = VhdxReader::from_bytes(data).unwrap();
    let mut buf0 = [0u8; 512];
    let mut buf1 = [0u8; 512];
    reader.read_exact(&mut buf0).unwrap();
    reader.read_exact(&mut buf1).unwrap();
    assert!(buf0.iter().all(|&b| b == 0xAA), "sector 0 should be 0xAA");
    assert!(buf1.iter().all(|&b| b == 0xBB), "sector 1 should be 0xBB");
}
