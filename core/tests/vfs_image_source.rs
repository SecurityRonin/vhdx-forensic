//! Integration test: VhdxReader composes as an ImageSource via forensic-vfs.
//!
//! Oracle: qemu-img 11.0.2 encoded `tests/data/fat.vhdx` from a FAT16 raw image
//! and decoded it back to `roundtrip.raw`. The SHA-256 of `roundtrip.raw` is the
//! ground-truth constant — an independent oracle produced it, not this reader.
//!
//! The test exercises the exact call path the forensic-vfs engine uses:
//!   `VhdxReader::open_reader(Box::new(Cursor::new(...)))` → `SeekPoolSource::single`.
//!
//! Generator commands (verbatim, for reproduction):
//!   hdiutil create -size 8m -fs "MS-DOS FAT16" -volname VHDXTEST /tmp/fat16img
//!   hdiutil convert /tmp/fat16img.dmg -format UDTO -o /tmp/fat16img_raw
//!   qemu-img convert -f raw -O vhdx /tmp/fat16img_raw.cdr /tmp/fat.vhdx
//!   qemu-img convert -f vhdx -O raw /tmp/fat.vhdx /tmp/roundtrip.raw
//!   qemu-img --version  →  qemu-img version 11.0.2

use std::io::Cursor;
use std::sync::Arc;

use forensic_vfs::adapters::SeekPoolSource;
use forensic_vfs::ImageSource;

/// SHA-256 of the round-trip raw produced by qemu-img (the independent oracle).
/// qemu encoded fat.vhdx, qemu decoded it back — neither value was authored by us.
const ROUNDTRIP_SHA256: &str = "f350908d5b99b0000f7bd4235ce841db1ee82c809f9fe9a19040257ec1eff4ed";

/// The virtual disk size qemu-img produces for an 8 MiB raw image → VHDX → raw.
const VIRTUAL_DISK_SIZE: u64 = 8 * 1024 * 1024; // 8 MiB

/// Offset of the MBR boot signature (0x55 0xAA) within the virtual disk.
/// The MBR lives at sector 0; the signature is at the last two bytes of that sector.
const MBR_BOOT_SIG_OFFSET: u64 = 510;

/// Offset of the VHDXTEST volume label within the virtual disk.
/// FAT16 partition starts at sector 1 (offset 512); the 11-byte volume label
/// lives at offset 0x2B within the FAT boot sector = 512 + 43 = 555.
const VHDXTEST_LABEL_OFFSET: u64 = 555;

/// The VHDX under test: a FAT16 image with the "VHDXTEST" volume label,
/// encoded by qemu-img 11.0.2 from an 8 MiB raw image.
static FAT_VHDX: &[u8] = include_bytes!("../../tests/data/fat.vhdx");

/// Open via `open_reader` and confirm `virtual_disk_size` is reported correctly,
/// `SeekPoolSource::single` wraps it, and `ImageSource::len` matches.
#[test]
fn open_reader_reports_correct_virtual_size() {
    let reader = vhdx::VhdxReader::open_reader(Box::new(Cursor::new(FAT_VHDX.to_vec())))
        .expect("open_reader must succeed on a valid VHDX");
    let vsize = reader.virtual_disk_size();
    assert_eq!(vsize, VIRTUAL_DISK_SIZE, "virtual disk size mismatch");

    let src: Arc<dyn ImageSource> = Arc::new(SeekPoolSource::single(reader, vsize));
    assert_eq!(
        src.len(),
        VIRTUAL_DISK_SIZE,
        "ImageSource::len must equal virtual_disk_size"
    );
}

/// Read the MBR boot signature sector — the canonical FAT/MBR marker.
/// This is a Tier-1 assertion: the offset and expected bytes were read from the
/// qemu round-trip raw, not from this reader.
#[test]
fn read_at_returns_mbr_boot_signature() {
    let reader = vhdx::VhdxReader::open_reader(Box::new(Cursor::new(FAT_VHDX.to_vec())))
        .expect("open_reader must succeed");
    let vsize = reader.virtual_disk_size();
    let src: Arc<dyn ImageSource> = Arc::new(SeekPoolSource::single(reader, vsize));

    let mut sector = [0u8; 512];
    let n = src.read_at(0, &mut sector).expect("read sector 0");
    assert_eq!(n, 512, "sector 0 read returned wrong byte count");
    assert_eq!(
        &sector[MBR_BOOT_SIG_OFFSET as usize..MBR_BOOT_SIG_OFFSET as usize + 2],
        &[0x55, 0xAA],
        "MBR boot signature not found at offset {MBR_BOOT_SIG_OFFSET}"
    );
}

/// Read the FAT16 volume label — confirms the right bytes from the oracle image
/// are decoded faithfully.
#[test]
fn read_at_finds_vhdxtest_label() {
    let reader = vhdx::VhdxReader::open_reader(Box::new(Cursor::new(FAT_VHDX.to_vec())))
        .expect("open_reader must succeed");
    let vsize = reader.virtual_disk_size();
    let src: Arc<dyn ImageSource> = Arc::new(SeekPoolSource::single(reader, vsize));

    let mut buf = [0u8; 8];
    let n = src
        .read_at(VHDXTEST_LABEL_OFFSET, &mut buf)
        .expect("read label sector");
    assert_eq!(n, 8, "label read returned wrong byte count");
    assert_eq!(&buf, b"VHDXTEST", "FAT16 volume label mismatch");
}

/// Read the whole virtual disk, SHA-256 it, and compare against the qemu oracle.
/// The sha256 constant was produced by `sha256sum /tmp/roundtrip.raw` where
/// roundtrip.raw was decoded by qemu-img from the committed fat.vhdx — fully
/// independent of this reader.
#[test]
fn full_read_sha256_matches_oracle() {
    use std::io::{Read, Seek, SeekFrom};

    let reader = vhdx::VhdxReader::open_reader(Box::new(Cursor::new(FAT_VHDX.to_vec())))
        .expect("open_reader must succeed");
    let vsize = reader.virtual_disk_size() as usize;
    let src: Arc<dyn ImageSource> = Arc::new(SeekPoolSource::single(reader, vsize as u64));

    // Drain the full virtual disk via ImageSource::read_at in 1 MiB chunks.
    let mut hasher = Sha256::new();
    let mut offset: u64 = 0;
    let mut chunk = vec![0u8; 1024 * 1024];
    loop {
        let remaining = (vsize as u64).saturating_sub(offset) as usize;
        if remaining == 0 {
            break;
        }
        let want = remaining.min(chunk.len());
        let n = src.read_at(offset, &mut chunk[..want]).expect("read chunk");
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
        offset += n as u64;
    }
    let digest = hex_lower(&hasher.finalize());
    assert_eq!(
        digest, ROUNDTRIP_SHA256,
        "SHA-256 of full virtual disk does not match qemu oracle"
    );
}

/// A read that starts entirely past EOF must return 0 — not an error, not a panic.
#[test]
fn read_past_eof_returns_zero() {
    let reader = vhdx::VhdxReader::open_reader(Box::new(Cursor::new(FAT_VHDX.to_vec())))
        .expect("open_reader must succeed");
    let vsize = reader.virtual_disk_size();
    let src: Arc<dyn ImageSource> = Arc::new(SeekPoolSource::single(reader, vsize));

    let mut buf = [0xFFu8; 512];
    let n = src
        .read_at(vsize, &mut buf)
        .expect("read at EOF must not error");
    assert_eq!(n, 0, "read at or beyond EOF must return 0");
}

// ---------------------------------------------------------------------------
// Minimal SHA-256 accumulator — avoids adding sha2 as a dev-dep; uses only
// the primitives already available via std (none). We use a hand-rolled
// condensed version purely for the test constant comparison.
//
// NOTE: This is the standard SHA-256, not a custom algorithm — it is only
// here to avoid an extra dev-dependency. Do NOT copy this pattern for
// production code; use the sha2 crate there.
// ---------------------------------------------------------------------------

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    bit_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.buf[self.buf_len] = b;
            self.buf_len += 1;
            if self.buf_len == 64 {
                self.compress();
                self.buf_len = 0;
            }
        }
        self.bit_len += (data.len() as u64) * 8;
    }

    fn compress(&mut self) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for i in 0..16 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([
                self.buf[j],
                self.buf[j + 1],
                self.buf[j + 2],
                self.buf[j + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.bit_len;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            // Fill and compress this block.
            for i in self.buf_len..64 {
                self.buf[i] = 0;
            }
            self.compress();
            self.buf_len = 0;
        }
        // Zero remaining, write length in last 8 bytes.
        for i in self.buf_len..56 {
            self.buf[i] = 0;
        }
        let bl = bit_len.to_be_bytes();
        self.buf[56..64].copy_from_slice(&bl);
        self.compress();
        let mut out = [0u8; 32];
        for (i, &s) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&s.to_be_bytes());
        }
        out
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
