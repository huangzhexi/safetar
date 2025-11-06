//! Compression codec selection and helper routines.

use std::fmt;

pub mod dec;
pub mod enc;

/// Compression codecs supported by safetar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Zstd,
}

impl Compression {
    /// Guess compression from header bytes.
    #[must_use]
    pub fn detect(header: &[u8]) -> Self {
        if header.starts_with(&[0x1F, 0x8B]) {
            Self::Gzip
        } else if header.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
            Self::Xz
        } else if header.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            Self::Zstd
        } else {
            Self::None
        }
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Gzip => write!(f, "gzip"),
            Self::Xz => write!(f, "xz"),
            Self::Zstd => write!(f, "zstd"),
        }
    }
}
