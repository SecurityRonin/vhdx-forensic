use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use vhdx::VhdxReader;

fn corpus_dir() -> Option<PathBuf> {
    std::env::var("CORPUS_DIR").ok().map(PathBuf::from)
}

#[test]
fn corpus_dynamic_vhdx_opens_and_has_nonzero_size() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("dynamic.vhdx");
    if !path.exists() {
        return;
    }
    let reader = VhdxReader::open(&path).expect("open dynamic.vhdx");
    assert!(reader.virtual_disk_size() > 0, "virtual_disk_size must be > 0");
}

#[test]
fn corpus_dynamic_vhdx_read_is_stable() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("dynamic.vhdx");
    if !path.exists() {
        return;
    }
    let mut reader = VhdxReader::open(&path).expect("open");
    let mut buf = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut buf).expect("read sector 0");
    assert_eq!(buf, [0u8; 512], "sector 0 of an empty VHDX must be all zeros");
}
