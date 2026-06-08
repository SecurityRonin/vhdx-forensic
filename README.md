[![Crates.io](https://img.shields.io/crates/v/vhdx-core.svg)](https://crates.io/crates/vhdx-core)
[![Docs.rs](https://img.shields.io/docsrs/vhdx-core)](https://docs.rs/vhdx-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust VHDX (Hyper-V) virtual-disk container library (reader; writer planned) — dynamic, fixed, differencing, and dirty-log recovery.**

Decodes the Microsoft VHDX container format (Hyper-V, Windows 8+, WSL2, Azure) and exposes a `Read + Seek` interface over the virtual sector stream. Replays dirty logs automatically on open and supports differencing-disk parent chains — zero unsafe code, no C bindings, no external tools required.

```toml
[dependencies]
vhdx-core = "0.2"   # published as vhdx-core, imported as `vhdx`
```

---

## Usage

### Open a VHDX and read sectors

```rust
use vhdx::VhdxReader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = VhdxReader::open("disk.vhdx")?;

println!("Virtual disk size: {} bytes", reader.virtual_disk_size());
println!("Logical sector size: {} bytes", reader.logical_sector_size());

// Read the first sector
let mut sector = vec![0u8; reader.logical_sector_size() as usize];
reader.seek(SeekFrom::Start(0))?;
reader.read_exact(&mut sector)?;
```

### Pass to a filesystem crate

`VhdxReader` implements `Read + Seek`, so it drops directly into any crate that accepts a reader:

```rust
use vhdx::VhdxReader;

let reader = VhdxReader::open("disk.vhdx")?;
// e.g. ext4fs_forensic::Filesystem::open(reader)?;
```

### Read from an in-memory buffer

```rust
use vhdx::VhdxReader;

let data: Vec<u8> = std::fs::read("disk.vhdx")?;
let reader = VhdxReader::from_bytes(data)?;
```

### Open a differencing (child) disk with its parent

```rust
use vhdx::VhdxReader;

let parent = VhdxReader::from_bytes(std::fs::read("base.vhdx")?)?;
let reader = VhdxReader::from_bytes_with_parent(std::fs::read("child.vhdx")?, parent)?;
// Reads absent blocks in the child are transparently served from parent.
```

---

## CLI

The `vhdx-cli` crate (included in this workspace) provides a `vhdx info` command:

```
$ vhdx info disk.vhdx
File:              disk.vhdx
Format:            VHDX v1 (dynamic)
Virtual disk size: 16,777,216 bytes (16.00 MiB)
Logical sectors:   512 bytes
```

---

## Supported formats

| Format | Supported |
|--------|:---------:|
| VHDX Version 1 (Windows 8 / Server 2012+) | ✓ |
| Dynamic disks (sparse, BAT-addressed) | ✓ |
| Fixed disks (pre-allocated) | ✓ |
| Differencing disks (single-level parent chain) | ✓ |
| Log replay (dirty-log recovery) | ✓ |

Read-only. Differencing disks require the parent image to be supplied via `VhdxReader::from_bytes_with_parent`. Log replay is applied automatically on open when the active header carries a non-zero LogGuid.

---

## Related crates

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 | Evimetry / aff4-imager forensic disk images with Map streams |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK | Monolithic sparse disk images from VMware Workstation / ESXi |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD | Virtual PC / Hyper-V Generation-1 fixed and dynamic disk images |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED | Physical mobile device dumps with UFD XML segment mapping |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / gz | dd, dcfldd, and gzip-wrapped raw images |
| [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) | ISO 9660 | Optical disc images: multi-session, UDF bridge, Rock Ridge, Joliet, El Torito |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF | macOS disk images with koly trailer, mish block tables, zlib decompression |
| [`dar`](https://github.com/SecurityRonin/dar) | DAR archive | Disk ARchiver archives with catalog index and CRC32 validation |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool built on this crate |
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |

---

[Privacy Policy](https://securityronin.github.io/vhdx-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/vhdx-forensic/terms/) · © 2026 Security Ronin Ltd
