use crate::bytes::le_u64;
use crate::error::{Result, VhdxError};
use crate::metadata::VhdxMetadata;

const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;
const SECTOR_BITMAP_BLOCK_PRESENT: u64 = 6;
const MIB: u64 = 0x0010_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadTarget {
    File(u64),
    Fallback,
    Partial {
        file_offset: u64,
        bitmap_byte_file_offset: u64,
        bitmap_mask: u8,
    },
}

#[derive(Debug, Clone)]
pub struct Bat {
    entries: Vec<u64>,
    meta: VhdxMetadata,
    #[allow(dead_code)]
    region_offset: u64,
}

impl Bat {
    pub fn parse(data: &[u8], bat_offset: u64, bat_len: u32, meta: VhdxMetadata) -> Result<Self> {
        let start = bat_offset as usize;
        let end = start + bat_len as usize;
        if data.len() < end {
            return Err(VhdxError::BatRegionMissing);
        }
        let bat_bytes = &data[start..end];
        let entry_count = bat_bytes.len() / 8;
        let mut entries = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let e = le_u64(bat_bytes, i * 8);
            entries.push(e);
        }
        Ok(Self {
            entries,
            meta,
            region_offset: bat_offset,
        })
    }

    pub(crate) fn read_target_for_byte(&self, virtual_byte: u64) -> Result<ReadTarget> {
        if virtual_byte >= self.meta.virtual_disk_size {
            return Err(VhdxError::SectorOutOfRange {
                sector: virtual_byte / u64::from(self.meta.logical_sector_size),
                size: self.meta.virtual_disk_size,
            });
        }
        let block_size = u64::from(self.meta.block_size);
        let data_block_index = virtual_byte / block_size;
        let offset_within_block = virtual_byte % block_size;
        let chunk_ratio = self.meta.chunk_ratio();

        let bat_index = data_block_index + data_block_index / chunk_ratio;

        let bat_entry = *self
            .entries
            .get(bat_index as usize)
            .ok_or(VhdxError::BlockNotPresent(data_block_index))?;

        let state = bat_entry & 0b111;
        if state == PAYLOAD_BLOCK_NOT_PRESENT {
            return Ok(ReadTarget::Fallback);
        }
        if state != PAYLOAD_BLOCK_FULLY_PRESENT && state != PAYLOAD_BLOCK_PARTIALLY_PRESENT {
            return Ok(ReadTarget::Fallback);
        }

        let file_offset = (bat_entry >> 20)
            .checked_mul(MIB)
            .and_then(|o| o.checked_add(offset_within_block))
            .ok_or(VhdxError::AddressOverflow)?;
        if state == PAYLOAD_BLOCK_FULLY_PRESENT {
            return Ok(ReadTarget::File(file_offset));
        }

        let chunk_index = data_block_index / chunk_ratio;
        let bitmap_bat_index = chunk_ratio
            .checked_add(1)
            .and_then(|entries_per_chunk| chunk_index.checked_mul(entries_per_chunk))
            .and_then(|index| index.checked_add(chunk_ratio))
            .ok_or(VhdxError::AddressOverflow)?;
        let bitmap_entry = *self
            .entries
            .get(bitmap_bat_index as usize)
            .ok_or(VhdxError::SectorBitmapNotPresent(data_block_index))?;
        if bitmap_entry & 0b111 != SECTOR_BITMAP_BLOCK_PRESENT {
            return Err(VhdxError::SectorBitmapNotPresent(data_block_index));
        }

        let logical_sector_size = u64::from(self.meta.logical_sector_size);
        let sectors_per_block = block_size / logical_sector_size;
        let sector_in_chunk = (data_block_index % chunk_ratio)
            .checked_mul(sectors_per_block)
            .and_then(|base| base.checked_add(offset_within_block / logical_sector_size))
            .ok_or(VhdxError::AddressOverflow)?;
        let bitmap_byte_file_offset = (bitmap_entry >> 20)
            .checked_mul(MIB)
            .and_then(|offset| offset.checked_add(sector_in_chunk / 8))
            .ok_or(VhdxError::AddressOverflow)?;
        let bitmap_mask = 1u8 << (sector_in_chunk % 8);

        Ok(ReadTarget::Partial {
            file_offset,
            bitmap_byte_file_offset,
            bitmap_mask,
        })
    }
}
