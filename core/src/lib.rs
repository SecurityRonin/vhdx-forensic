//! Pure-Rust read-only VHDX container reader.
//!
//! Decodes the MS-VHDX outer container format and exposes a `Read + Seek`
//! interface over the virtual sector stream.
//!
//! # Supported formats
//! - VHDX Version 1 (Windows 8+ / Server 2012+)
//! - Dynamic disks
//! - Fixed disks
//!
//! # Layer
//! CONTAINER — equivalent role to `ewf` for E01 images.

mod bat;
mod error;
pub mod header;
mod log;
pub mod metadata;
mod reader;
pub mod region;

pub use error::{Result, VhdxError};
pub use reader::VhdxReader;

/// Well-known VHDX file magic (first 8 bytes of every VHDX file).
pub const FILE_MAGIC: &[u8; 8] = b"vhdxfile";
