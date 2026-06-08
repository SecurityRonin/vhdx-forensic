use crate::error::{Result, VhdxError};
use crate::header::{crc32c, parse_active_header};

/// Apply a dirty VHDX log to the in-memory buffer before parsing.
///
/// If the active header's LogGuid is all-zeros or LogLength is zero the image
/// is clean and this is a no-op.  Otherwise every valid log entry whose
/// LogGuid matches the header is applied to `data` in ascending sequence
/// order so that subsequent region/metadata/BAT parsing sees the committed
/// state.
pub(crate) fn apply(data: &mut Vec<u8>) -> Result<()> {
    let header = parse_active_header(data)?;
    if header.log_length == 0 || header.log_guid == [0u8; 16] {
        return Ok(());
    }
    apply_region(data, header.log_offset, header.log_length, &header.log_guid)
}

fn apply_region(
    data: &mut Vec<u8>,
    log_offset: u64,
    log_length: u32,
    expected_guid: &[u8; 16],
) -> Result<()> {
    let log_start = log_offset as usize;
    let log_end = log_start.saturating_add(log_length as usize);
    if data.len() < log_end {
        return Err(VhdxError::OffsetOutOfBounds);
    }

    let mut entries: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut pos = 0usize;

    loop {
        let abs = log_start + pos;
        if abs + 64 > log_end {
            break;
        }
        if &data[abs..abs + 4] != b"loge" {
            break;
        }
        let entry_len =
            u32::from_le_bytes(data[abs + 8..abs + 12].try_into().unwrap()) as usize;
        if entry_len < 64 || abs + entry_len > log_end {
            break;
        }

        let entry_bytes = data[abs..abs + entry_len].to_vec();

        // Validate CRC32C (computed with [4..8] zeroed).
        let stored = u32::from_le_bytes(entry_bytes[4..8].try_into().unwrap());
        let mut tmp = entry_bytes.clone();
        tmp[4..8].fill(0);
        if crc32c(&tmp) != stored {
            pos += entry_len;
            continue;
        }

        // Skip entries whose LogGuid doesn't match the active header's.
        let entry_guid: &[u8; 16] = entry_bytes[32..48].try_into().unwrap();
        if entry_guid != expected_guid {
            pos += entry_len;
            continue;
        }

        let seq = u64::from_le_bytes(entry_bytes[16..24].try_into().unwrap());
        entries.push((seq, entry_bytes));
        pos += entry_len;
    }

    entries.sort_by_key(|(seq, _)| *seq);
    for (_, entry_bytes) in entries {
        apply_entry(data, &entry_bytes);
    }
    Ok(())
}

fn apply_entry(data: &mut [u8], entry: &[u8]) {
    let descriptor_count = u32::from_le_bytes(entry[24..28].try_into().unwrap()) as usize;
    let desc_start = 64;
    let data_sector_base = desc_start + descriptor_count * 32;
    let mut sector_idx = 0usize;

    for i in 0..descriptor_count {
        let d = &entry[desc_start + i * 32..desc_start + (i + 1) * 32];
        match &d[0..4] {
            b"desc" => {
                // Data descriptor: copy 4096-byte sector to FileOffset in the container.
                let file_off = u64::from_le_bytes(d[24..32].try_into().unwrap()) as usize;
                let sector_off = data_sector_base + sector_idx * 4096;
                if sector_off + 4096 <= entry.len() && file_off + 4096 <= data.len() {
                    data[file_off..file_off + 4096]
                        .copy_from_slice(&entry[sector_off..sector_off + 4096]);
                }
                sector_idx += 1;
            }
            b"zero" => {
                // Zero descriptor: fill ZeroLength bytes at FileOffset with zeros.
                let zero_len = u64::from_le_bytes(d[8..16].try_into().unwrap()) as usize;
                let file_off = u64::from_le_bytes(d[16..24].try_into().unwrap()) as usize;
                let end = file_off.saturating_add(zero_len).min(data.len());
                if file_off < data.len() {
                    data[file_off..end].fill(0);
                }
            }
            _ => {}
        }
    }
}
