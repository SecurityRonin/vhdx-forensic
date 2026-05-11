use crate::error::{Result, VhdxError};

pub const METADATA_TABLE_SIGNATURE: &[u8; 8] = b"metadata";

// Validation bounds from MS-VHDX §2.5.5.
const BLOCK_SIZE_MIN: u32 = 1 << 20; // 1 MB
const BLOCK_SIZE_MAX: u32 = 256 << 20; // 256 MB
const VALID_SECTOR_SIZES: [u32; 2] = [512, 4096];
const VIRTUAL_DISK_SIZE_MAX: u64 = 64 * (1u64 << 40); // 64 TiB

// Well-known metadata item GUIDs (MS-VHDX §2.5.5).
pub const GUID_FILE_PARAMETERS: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];
pub const GUID_VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5B, 0xE0, 0x7A, 0x6C, 0xE3, 0x2C,
];
pub const GUID_LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];

#[derive(Debug, Clone)]
pub struct VhdxMetadata {
    /// Data block size in bytes (default 32 MB).
    pub block_size: u32,
    /// True if this is a differencing disk (not supported for forensics).
    pub has_parent: bool,
    /// Total virtual disk size in bytes.
    pub virtual_disk_size: u64,
    /// Logical sector size (typically 512).
    pub logical_sector_size: u32,
}

impl VhdxMetadata {
    /// Chunk ratio: how many data block BAT entries precede each sector bitmap entry.
    /// Formula from MS-VHDX §2.3.5: `(2^23 * LogicalSectorSize) / BlockSize`.
    pub fn chunk_ratio(&self) -> u64 {
        (1u64 << 23) * u64::from(self.logical_sector_size) / u64::from(self.block_size)
    }

    /// Validate all metadata fields against MS-VHDX spec bounds.
    ///
    /// Must be called before any arithmetic that uses `block_size` or
    /// `logical_sector_size` to prevent divide-by-zero and range violations.
    pub fn validate(&self) -> Result<()> {
        if self.block_size < BLOCK_SIZE_MIN || self.block_size > BLOCK_SIZE_MAX {
            return Err(VhdxError::InvalidMetadata(
                "BlockSize must be in [1 MB, 256 MB]",
            ));
        }
        if self.block_size.count_ones() != 1 {
            return Err(VhdxError::InvalidMetadata(
                "BlockSize must be a power of two",
            ));
        }
        if !VALID_SECTOR_SIZES.contains(&self.logical_sector_size) {
            return Err(VhdxError::InvalidMetadata(
                "LogicalSectorSize must be 512 or 4096",
            ));
        }
        if self.virtual_disk_size == 0 {
            return Err(VhdxError::InvalidMetadata("VirtualDiskSize cannot be zero"));
        }
        if self.virtual_disk_size > VIRTUAL_DISK_SIZE_MAX {
            return Err(VhdxError::InvalidMetadata(
                "VirtualDiskSize exceeds the 64 TiB spec limit",
            ));
        }
        if self.virtual_disk_size % u64::from(self.logical_sector_size) != 0 {
            return Err(VhdxError::InvalidMetadata(
                "VirtualDiskSize must be a multiple of LogicalSectorSize",
            ));
        }
        Ok(())
    }
}

pub fn parse_metadata(data: &[u8], region_offset: u64, region_len: u32) -> Result<VhdxMetadata> {
    let start = region_offset as usize;
    let end = start + region_len as usize;
    if data.len() < end || end < start + 8 {
        return Err(VhdxError::MetadataMissing("region out of bounds"));
    }
    let region = &data[start..end];
    if &region[0..8] != METADATA_TABLE_SIGNATURE {
        return Err(VhdxError::MetadataMissing("bad metadata signature"));
    }
    let entry_count = u16::from_le_bytes(region[10..12].try_into().unwrap()) as usize;

    let mut block_size: Option<u32> = None;
    let mut has_parent = false;
    let mut virtual_disk_size: Option<u64> = None;
    let mut logical_sector_size: Option<u32> = None;

    for i in 0..entry_count {
        let base = 32 + i * 32;
        if base + 32 > region.len() {
            break;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&region[base..base + 16]);
        let item_offset =
            u32::from_le_bytes(region[base + 16..base + 20].try_into().unwrap()) as usize;
        let item_len =
            u32::from_le_bytes(region[base + 20..base + 24].try_into().unwrap()) as usize;

        // Item data is at region_start + 0x10000 (metadata table is 64KB) + item_offset.
        let data_start = start + 0x10000 + item_offset;
        let data_end = data_start + item_len;
        if data.len() < data_end {
            continue;
        }
        let item_data = &data[data_start..data_end];

        if guid == GUID_FILE_PARAMETERS && item_data.len() >= 8 {
            block_size = Some(u32::from_le_bytes(item_data[0..4].try_into().unwrap()));
            let flags = u32::from_le_bytes(item_data[4..8].try_into().unwrap());
            has_parent = flags & 2 != 0;
        } else if guid == GUID_VIRTUAL_DISK_SIZE && item_data.len() >= 8 {
            virtual_disk_size = Some(u64::from_le_bytes(item_data[0..8].try_into().unwrap()));
        } else if guid == GUID_LOGICAL_SECTOR_SIZE && item_data.len() >= 4 {
            logical_sector_size = Some(u32::from_le_bytes(item_data[0..4].try_into().unwrap()));
        }
    }

    Ok(VhdxMetadata {
        block_size: block_size.ok_or(VhdxError::MetadataMissing("BlockSize"))?,
        has_parent,
        virtual_disk_size: virtual_disk_size
            .ok_or(VhdxError::MetadataMissing("VirtualDiskSize"))?,
        logical_sector_size: logical_sector_size.unwrap_or(512),
    })
}
