# vhdx-forensic

[![crates.io](https://img.shields.io/crates/v/vhdx-forensic.svg)](https://crates.io/crates/vhdx-forensic)
[![docs.rs](https://img.shields.io/docsrs/vhdx-forensic)](https://docs.rs/vhdx-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml)

Pure-Rust read-only VHDX container reader for forensic analysis.

Decodes the [MS-VHDX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83f6b700-6216-40f0-aa99-9fcb421206e2) outer container format and exposes a `Read + Seek` interface over the virtual sector stream. Hand it directly to a filesystem analysis crate — no unsafe code, no C bindings, no GPL.

## When to use this

You have a VHDX disk image (the native Windows virtual disk format used by Hyper-V and WSL2's `ext4.vhdx`) and you want to read raw sectors from it in a forensic context — offline, read-only, with no risk of side-effects from the Windows storage stack.

This crate is the **CONTAINER** layer in the [Issen](https://github.com/SecurityRonin/issen) forensic stack: it sits between raw byte sources (E01/EWF via [`ewf`](https://crates.io/crates/ewf), raw files) and filesystem parsers (`ext4fs-forensic`, `ntfs-forensic`).

## Usage

```toml
[dependencies]
vhdx-forensic = "0.1"
```

```rust
use std::io::{Read, Seek, SeekFrom};
use vhdx_forensic::VhdxReader;

// Open a VHDX and read the first sector.
let mut reader = VhdxReader::open("disk.vhdx")?;
println!("virtual disk size: {} bytes", reader.virtual_disk_size());

let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

// Seek to a known offset and read.
reader.seek(SeekFrom::Start(1024 * 1024))?;
reader.read_exact(&mut sector)?;
```

The reader implements `std::io::Read + std::io::Seek`, so it can be dropped in anywhere an ordinary file handle is expected.

## Hardening against crafted images

VHDX headers and region tables are CRC32C-protected, but the **BAT** (Block Allocation Table) and **metadata** fields are not. A crafted image can carry semantically invalid values while maintaining valid CRCs. This crate validates all of the following before any arithmetic that depends on them:

| Field | Constraint enforced |
|-------|---------------------|
| `BlockSize` | Power-of-two in \[1 MB, 256 MB\] |
| `LogicalSectorSize` | Exactly 512 or 4096 |
| `VirtualDiskSize` | Non-zero, ≤ 64 TiB, multiple of sector size |
| Region entry `file_offset + length` | Within container bounds |
| Region `entry_count` | Capped at 2048 (DoS guard) |
| Container size | Minimum 2.5 MB before any offset arithmetic |
| BAT offset arithmetic | `checked_mul`/`checked_add` — `AddressOverflow` instead of panic |

Differencing disks (`HasParent = true`) are not supported and are rejected at open time.

## Supported formats

- VHDX Version 1 (Windows 8 / Server 2012 and later)
- Dynamic disks (sparse BAT-addressed data blocks)
- Fixed disks

Log replay is not performed. Offline forensic snapshots are expected to be consistent; replaying an uncommitted log is out of scope.

## License

MIT — see [LICENSE](LICENSE).  
Copyright © 2026 Security Ronin Ltd.
