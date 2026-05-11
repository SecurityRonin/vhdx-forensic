//! Pure-Rust read-only VHDX container reader.
//!
//! Decodes the VHDX outer container (MS-VHDX spec) and exposes a
//! `Read + Seek` interface over the virtual sector stream, which can be
//! handed directly to filesystem navigation crates (e.g. ext4fs-forensic).
//!
//! # Layer
//! CONTAINER — equivalent role to `ewf` for E01 images.
//!
//! # Supported formats
//! - VHDX Version 1 (Windows 8+ / Server 2012+ native format)
//! - Dynamic disks (sparse, BAT-addressed data blocks)
//! - Fixed disks
//!
//! # Limitations
//! - Read-only
//! - Differencing disks (HasParent=true) are not supported
//! - Log replay is not performed (offline forensic snapshots are typically clean)

mod bat;
mod error;
mod header;
pub mod integrity;
mod metadata;
mod reader;
mod region;
pub mod repair;

pub use error::{Result, VhdxError};
pub use header::crc32c;
pub use integrity::{Severity, VhdxIntegrity, VhdxIntegrityAnomaly};
pub use reader::VhdxReader;
pub use repair::{CannotRepair, RepairAction, RepairReport, VhdxRepair};

// Well-known VHDX file magic.
pub const FILE_MAGIC: &[u8; 8] = b"vhdxfile";
