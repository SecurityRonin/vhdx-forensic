# VHDX Test Data

## dfvfs_ext2.vhdx

- **Source**: https://github.com/log2timeline/dfvfs/raw/main/test_data/ext2.vhdx
- **License**: Apache-2.0 (dfvfs project, log2timeline)
- **SHA-256**: `d729323aafb2a7473e39abe9382076014d99a0c16e8333b9decbd81d355b1087`
- **Size**: 16,777,216 bytes (16 MiB)
- **Description**: Native Hyper-V VHDX image containing an ext2 filesystem, used as an authoritative real-world corpus file for VHDX container reader testing.

## Pre-existing files

The following files were already present in this directory before corpus import:

| File | Description |
|------|-------------|
| ext2.vhd | VHD image with ext2 filesystem |
| ext2.vhdx | VHDX image with ext2 filesystem |
| fat-differential.vhdx | Differencing VHDX (FAT child) |
| fat-parent.vhdx | Parent VHDX (FAT) |
| qemu_empty_dynamic.vhdx | QEMU-generated dynamic VHDX (empty) |
| qemu_fixed.vhdx | QEMU-generated fixed VHDX |
