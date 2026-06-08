use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::bat::Bat;
use crate::error::{Result, VhdxError};
use crate::header::{parse_active_header, REGION_TABLE1_OFFSET, REGION_TABLE2_OFFSET};
use crate::metadata::{parse_metadata, VhdxMetadata};
use crate::region::parse_region_table;
use crate::FILE_MAGIC;

/// Read-only VHDX container reader.
///
/// Implements `Read + Seek` over the virtual sector stream.
#[derive(Debug)]
pub struct VhdxReader {
    data: Vec<u8>,
    bat: Bat,
    meta: VhdxMetadata,
    pos: u64,
    parent: Option<Box<VhdxReader>>,
}

impl VhdxReader {
    pub fn open(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }

    /// Minimum container size: covers magic, both headers, and both region tables.
    const MIN_CONTAINER_SIZE: u64 = 0x0025_0000;

    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        Self::parse(data, None)
    }

    /// Open a differencing (child) disk with its parent chain.
    ///
    /// Reads absent blocks from `parent` instead of returning zeros.
    pub fn from_bytes_with_parent(data: Vec<u8>, parent: VhdxReader) -> Result<Self> {
        Self::parse(data, Some(Box::new(parent)))
    }

    fn parse(mut data: Vec<u8>, parent: Option<Box<VhdxReader>>) -> Result<Self> {
        if data.len() < 8 || &data[0..8] != FILE_MAGIC {
            return Err(VhdxError::BadMagic);
        }
        if (data.len() as u64) < Self::MIN_CONTAINER_SIZE {
            return Err(VhdxError::ContainerTooSmall(Self::MIN_CONTAINER_SIZE));
        }
        crate::log::apply(&mut data)?;
        let _header = parse_active_header(&data)?;
        let regions = parse_region_table(&data, REGION_TABLE1_OFFSET as usize)
            .or_else(|_| parse_region_table(&data, REGION_TABLE2_OFFSET as usize))?;
        let meta = parse_metadata(&data, regions.metadata.file_offset, regions.metadata.length)?;
        meta.validate()?;
        if meta.has_parent && parent.is_none() {
            return Err(VhdxError::DifferencingNotSupported);
        }
        let bat = Bat::parse(
            &data,
            regions.bat.file_offset,
            regions.bat.length,
            meta.clone(),
        )?;
        Ok(Self {
            data,
            bat,
            meta,
            pos: 0,
            parent,
        })
    }

    pub fn virtual_disk_size(&self) -> u64 {
        self.meta.virtual_disk_size
    }

    pub fn logical_sector_size(&self) -> u32 {
        self.meta.logical_sector_size
    }
}

impl Read for VhdxReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.meta.virtual_disk_size {
            return Ok(0);
        }
        let remaining = self.meta.virtual_disk_size - self.pos;
        let to_read = buf.len().min(remaining as usize);
        let block_size = u64::from(self.meta.block_size);
        let mut written = 0;

        while written < to_read {
            let virtual_byte = self.pos + written as u64;
            let block_end = ((virtual_byte / block_size) + 1) * block_size;
            let this_chunk = (to_read - written).min((block_end - virtual_byte) as usize);

            match self.bat.file_offset_for_byte(virtual_byte) {
                Ok(file_off) => {
                    let src_end = (file_off as usize).saturating_add(this_chunk);
                    if src_end > self.data.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VHDX data truncated",
                        ));
                    }
                    buf[written..written + this_chunk]
                        .copy_from_slice(&self.data[file_off as usize..src_end]);
                }
                Err(VhdxError::BlockNotPresent(_)) => {
                    if let Some(ref mut p) = self.parent {
                        p.seek(SeekFrom::Start(virtual_byte))
                            .map_err(io::Error::other)?;
                        p.read_exact(&mut buf[written..written + this_chunk])?;
                    } else {
                        buf[written..written + this_chunk].fill(0);
                    }
                }
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
            written += this_chunk;
        }

        self.pos += written as u64;
        Ok(written)
    }
}

impl Seek for VhdxReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.pos as i64 + n,
            SeekFrom::End(n) => self.meta.virtual_disk_size as i64 + n,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}
