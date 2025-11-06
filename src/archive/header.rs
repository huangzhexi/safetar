//! Helpers for working with tar headers.

use tar::{EntryType, Header};

use super::EntryKind;

/// Classify the entry type for convenience.
#[must_use]
pub(crate) fn classify_entry_type(header: &Header) -> EntryKind {
    match header.entry_type() {
        EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => EntryKind::File,
        EntryType::Directory => EntryKind::Directory,
        EntryType::Symlink => EntryKind::Symlink,
        EntryType::Link => EntryKind::File,
        _ => EntryKind::File,
    }
}
