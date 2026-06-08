/// Corpus differential tests: bytes from VhdxReader must match `qemu-img convert -O raw`.
///
/// These tests skip automatically if qemu-img is not installed, so they run in CI
/// only on machines with QEMU available (the dev machine). They verify correctness
/// against an independent authoritative reference rather than against the library's
/// own synthetic fixtures (which share the same blind spots).
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use vhdx::VhdxReader;

const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";

fn corpus_vhdx_matches_qemu_raw(corpus: &Path) {
    if !Path::new(QEMU_IMG).exists() || !corpus.exists() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let raw_path = tmp.path().join("reference.raw");

    let ok = std::process::Command::new(QEMU_IMG)
        .args([
            "convert",
            "-O",
            "raw",
            corpus.to_str().unwrap(),
            raw_path.to_str().unwrap(),
        ])
        .status()
        .expect("spawn qemu-img")
        .success();
    assert!(
        ok,
        "qemu-img convert failed for {}",
        corpus.display()
    );
    let ref_data = std::fs::read(&raw_path).expect("read reference raw");

    let mut reader = VhdxReader::open(corpus).expect("open vhdx");
    let vhdx_size = reader.virtual_disk_size() as usize;
    assert_eq!(
        vhdx_size,
        ref_data.len(),
        "virtual_disk_size must match qemu-img reference raw length for {}",
        corpus.display()
    );

    // Sample every 64 KiB, covering block and sector boundaries, plus near-end.
    let step = 65536usize;
    let mut offset = 0usize;
    while offset < vhdx_size {
        let len = 512.min(vhdx_size - offset);
        let mut buf = vec![0u8; len];
        reader
            .seek(SeekFrom::Start(offset as u64))
            .expect("seek");
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(
            buf,
            ref_data[offset..offset + len],
            "byte mismatch at offset {offset:#x} in {}",
            corpus.display()
        );
        offset += step;
    }

    // Near-end check.
    if vhdx_size >= 512 {
        let end = vhdx_size - 512;
        let mut buf = vec![0u8; 512];
        reader
            .seek(SeekFrom::Start(end as u64))
            .expect("seek near-end");
        reader.read_exact(&mut buf).expect("read near-end");
        assert_eq!(
            buf,
            ref_data[end..end + 512],
            "byte mismatch near end of {}",
            corpus.display()
        );
    }
}

#[test]
fn corpus_ext2_vhdx_matches_qemu_raw() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ext2.vhdx");
    corpus_vhdx_matches_qemu_raw(&p);
}

#[test]
fn corpus_qemu_fixed_vhdx_matches_qemu_raw() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/qemu_fixed.vhdx");
    corpus_vhdx_matches_qemu_raw(&p);
}

#[test]
fn corpus_fat_parent_vhdx_matches_qemu_raw() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/fat-parent.vhdx");
    corpus_vhdx_matches_qemu_raw(&p);
}
