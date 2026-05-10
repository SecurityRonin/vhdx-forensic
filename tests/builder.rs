//! In-memory VHDX builder for tests.
//!
//! Constructs the minimal valid VHDX byte structure per MS-VHDX spec,
//! including correct CRC32C checksums in headers and region tables.

use std::collections::HashMap;

// Castagnoli CRC32C (same as in header.rs — duplicated here to avoid
// depending on crate-internal items from tests).
fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

fn write_crc32c(block: &mut [u8], crc_offset: usize) {
    block[crc_offset..crc_offset + 4].fill(0);
    let crc = crc32c(block);
    block[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
}

pub struct VhdxBuilder {
    virtual_disk_size: u64,
    block_size: u32,
    logical_sector_size: u32,
    sector_data: HashMap<u64, Vec<u8>>,
    sparse: bool,
}

impl VhdxBuilder {
    pub fn new(virtual_disk_size: u64) -> Self {
        Self {
            virtual_disk_size,
            block_size: 32 * 1024 * 1024, // 32 MB default
            logical_sector_size: 512,
            sector_data: HashMap::new(),
            sparse: false,
        }
    }

    /// Mark all data blocks as not-present (sparse). Reads return zeros.
    pub fn build_sparse(mut self) -> Vec<u8> {
        self.sparse = true;
        self.build()
    }

    /// Add payload for a specific logical sector (0-indexed).
    pub fn with_sector_data(mut self, sector: u64, data: Vec<u8>) -> Self {
        self.sector_data.insert(sector, data);
        self
    }

    /// Build the VHDX byte image.
    pub fn build(self) -> Vec<u8> {
        // Fixed layout for test images:
        //   0x000000 - 0x0FFFFF : File Identifier (1 MB)
        //   0x100000 - 0x13FFFF : Header 1 (64 KB, rest zeroed to 1MB)
        //   0x140000 - 0x1FFFFF : Header 2 (at 0x140000)
        //   0x200000 - 0x23FFFF : Region Table 1
        //   0x240000 - 0x2FFFFF : Region Table 2
        //   0x300000 - 0x30FFFF : Metadata region (64 KB table + 64 KB items)
        //   0x310000 - ...      : BAT region
        //   <bat-addressed>      : Data blocks

        let metadata_offset: u64 = 0x0030_0000; // 3 MB (1MB-aligned)
        let metadata_len: u32 = 0x0002_0000;   // 128 KB

        // Compute BAT size.
        let block_size = u64::from(self.block_size);
        let data_block_count = self.virtual_disk_size.div_ceil(block_size);
        let chunk_ratio = (1u64 << 23) * u64::from(self.logical_sector_size) / block_size;
        let total_bat_entries = data_block_count
            + (data_block_count + chunk_ratio - 1) / chunk_ratio;
        let bat_len = (total_bat_entries * 8).next_multiple_of(0x0010_0000) as u32;
        // BAT must be at a 1MB-aligned offset (BAT entries encode offsets in MB units).
        let bat_offset: u64 = (metadata_offset + u64::from(metadata_len))
            .next_multiple_of(0x0010_0000);
        // Data blocks must also start at a 1MB-aligned offset.
        let data_start: u64 = (bat_offset + u64::from(bat_len))
            .next_multiple_of(0x0010_0000);

        // Allocate file buffer.
        // Each data block is block_size bytes at data_start + index * block_size.
        let file_size = if self.sparse || self.sector_data.is_empty() {
            data_start
        } else {
            data_start + data_block_count * block_size
        };
        let file_size = file_size.next_multiple_of(0x0010_0000) as usize; // align to 1MB
        let mut buf = vec![0u8; file_size];

        // File Identifier at offset 0.
        buf[0..8].copy_from_slice(b"vhdxfile");
        // Creator string (UTF-16LE "vhdx-forensic-test\0" padded to 512 bytes).
        let creator = "vhdx-forensic-test";
        let mut creator_utf16: Vec<u8> = creator.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        creator_utf16.extend_from_slice(&[0, 0]); // null terminator
        let copy_len = creator_utf16.len().min(504);
        buf[8..8 + copy_len].copy_from_slice(&creator_utf16[..copy_len]);

        // Header 1 at 0x100000.
        Self::write_header(&mut buf, 0x0010_0000, 1);
        // Header 2 at 0x140000 (sequence 0 — header 1 wins).
        Self::write_header(&mut buf, 0x0014_0000, 0);

        // Region Table 1 at 0x200000.
        Self::write_region_table(
            &mut buf,
            0x0020_0000,
            bat_offset,
            bat_len,
            metadata_offset,
            metadata_len,
        );
        // Region Table 2 at 0x240000 (identical copy).
        Self::write_region_table(
            &mut buf,
            0x0024_0000,
            bat_offset,
            bat_len,
            metadata_offset,
            metadata_len,
        );

        // Metadata region.
        Self::write_metadata(
            &mut buf,
            metadata_offset as usize,
            self.block_size,
            self.virtual_disk_size,
            self.logical_sector_size,
        );

        // BAT entries and data blocks.
        if !self.sparse {
            for block_idx in 0..data_block_count {
                let bat_entry_idx = (block_idx + block_idx / chunk_ratio) as usize;
                // File offset for this data block in units of 1 MB.
                let block_file_offset = data_start + block_idx * block_size;
                let offset_mb = block_file_offset / 0x0010_0000;
                // State = PAYLOAD_BLOCK_FULLY_PRESENT (6), bits 0-2.
                let bat_entry: u64 = (offset_mb << 20) | 6;
                let bat_pos = bat_offset as usize + bat_entry_idx * 8;
                if bat_pos + 8 <= buf.len() {
                    buf[bat_pos..bat_pos + 8].copy_from_slice(&bat_entry.to_le_bytes());
                }

                // Write any sector payloads that fall in this block.
                let sectors_per_block = block_size / u64::from(self.logical_sector_size);
                let first_sector = block_idx * sectors_per_block;
                for sector_off in 0..sectors_per_block {
                    let sector = first_sector + sector_off;
                    if let Some(payload) = self.sector_data.get(&sector) {
                        let sector_file_offset =
                            block_file_offset + sector_off * u64::from(self.logical_sector_size);
                        let dst = sector_file_offset as usize;
                        let copy_len = payload.len().min(self.logical_sector_size as usize);
                        if dst + copy_len <= buf.len() {
                            buf[dst..dst + copy_len].copy_from_slice(&payload[..copy_len]);
                        }
                    }
                }
            }
        }

        buf
    }

    fn write_header(buf: &mut [u8], offset: usize, seq: u64) {
        let slice = &mut buf[offset..offset + 4096];
        slice[0..4].copy_from_slice(b"head");
        // Checksum at [4..8] — written last.
        slice[8..16].copy_from_slice(&seq.to_le_bytes()); // SequenceNumber
        // FileWriteGuid, DataWriteGuid, LogGuid: all zeros (acceptable for test).
        // LogVersion = 0, Version = 1.
        slice[64..66].copy_from_slice(&0u16.to_le_bytes()); // LogVersion
        slice[66..68].copy_from_slice(&1u16.to_le_bytes()); // Version
        slice[68..72].copy_from_slice(&0u32.to_le_bytes()); // LogLength
        slice[72..80].copy_from_slice(&0u64.to_le_bytes()); // LogOffset
        write_crc32c(slice, 4);
    }

    fn write_region_table(
        buf: &mut [u8],
        offset: usize,
        bat_offset: u64,
        bat_len: u32,
        metadata_offset: u64,
        metadata_len: u32,
    ) {
        let slice = &mut buf[offset..offset + 65536];
        slice[0..4].copy_from_slice(b"regi");
        // Checksum at [4..8] — written last.
        slice[8..12].copy_from_slice(&2u32.to_le_bytes()); // EntryCount = 2
        slice[12..16].fill(0); // Reserved

        // Entry 0: BAT  (GUID: 2DC27766-F623-4200-9D64-115E9BFD4A08)
        let bat_guid: [u8; 16] = [
            0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42,
            0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
        ];
        slice[16..32].copy_from_slice(&bat_guid);
        slice[32..40].copy_from_slice(&bat_offset.to_le_bytes());
        slice[40..44].copy_from_slice(&bat_len.to_le_bytes());
        slice[44..48].copy_from_slice(&1u32.to_le_bytes()); // Required

        // Entry 1: Metadata (GUID: 8B7CA206-4790-4B9A-B8FE-575F050F886E)
        let meta_guid: [u8; 16] = [
            0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B,
            0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
        ];
        slice[48..64].copy_from_slice(&meta_guid);
        slice[64..72].copy_from_slice(&metadata_offset.to_le_bytes());
        slice[72..76].copy_from_slice(&metadata_len.to_le_bytes());
        slice[76..80].copy_from_slice(&1u32.to_le_bytes()); // Required

        write_crc32c(slice, 4);
    }

    fn write_metadata(
        buf: &mut [u8],
        region_start: usize,
        block_size: u32,
        virtual_disk_size: u64,
        logical_sector_size: u32,
    ) {
        // Metadata table occupies the first 64 KB of the metadata region.
        // Metadata items live at region_start + 0x10000 + item_offset.
        let table = &mut buf[region_start..region_start + 0x10000];
        table[0..8].copy_from_slice(b"metadata");
        // Reserved: u16 at [8..10].
        table[10..12].copy_from_slice(&3u16.to_le_bytes()); // EntryCount = 3

        // Item offsets within the item area (relative to 0x10000 within region).
        let off_file_params: u32 = 0;
        let off_vdisk_size: u32 = 8;
        let off_sector_size: u32 = 16;

        // Entry 0: FileParameters (GUID: CAA16737-FA36-4D43-B3B6-33F0AA44E76B)
        let guid_fp: [u8; 16] = [
            0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D,
            0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
        ];
        table[32..48].copy_from_slice(&guid_fp);
        table[48..52].copy_from_slice(&off_file_params.to_le_bytes()); // Offset
        table[52..56].copy_from_slice(&8u32.to_le_bytes()); // Length = 8
        table[56..60].copy_from_slice(&0b110u32.to_le_bytes()); // IsVirtualDisk|IsRequired

        // Entry 1: VirtualDiskSize (GUID: 2FA54224-CD1B-4876-B211-5BE07A6CE32C)
        let guid_vds: [u8; 16] = [
            0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48,
            0xB2, 0x11, 0x5B, 0xE0, 0x7A, 0x6C, 0xE3, 0x2C,
        ];
        table[64..80].copy_from_slice(&guid_vds);
        table[80..84].copy_from_slice(&off_vdisk_size.to_le_bytes());
        table[84..88].copy_from_slice(&8u32.to_le_bytes()); // Length = 8
        table[88..92].copy_from_slice(&0b110u32.to_le_bytes());

        // Entry 2: LogicalSectorSize (GUID: 8141BF1D-A96F-4709-BA47-F233A8FAAB5F)
        let guid_lss: [u8; 16] = [
            0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47,
            0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
        ];
        table[96..112].copy_from_slice(&guid_lss);
        table[112..116].copy_from_slice(&off_sector_size.to_le_bytes());
        table[116..120].copy_from_slice(&4u32.to_le_bytes()); // Length = 4
        table[120..124].copy_from_slice(&0b110u32.to_le_bytes());

        // Write item data at region_start + 0x10000.
        let items = &mut buf[region_start + 0x10000..region_start + 0x10000 + 64];

        // FileParameters: BlockSize (u32) + Flags (u32, bit1=HasParent=0).
        items[0..4].copy_from_slice(&block_size.to_le_bytes());
        items[4..8].copy_from_slice(&0u32.to_le_bytes()); // HasParent=false

        // VirtualDiskSize: u64.
        items[8..16].copy_from_slice(&virtual_disk_size.to_le_bytes());

        // LogicalSectorSize: u32.
        items[16..20].copy_from_slice(&logical_sector_size.to_le_bytes());
    }
}
