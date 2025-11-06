//! Placeholder for future PAX extension support.

use std::collections::BTreeMap;

use tar::Header;

/// Extract known PAX key/value pairs from the header if present.
///
/// The current implementation does not parse extended headers; it returns an empty map so that
/// call sites can remain future-proof.
pub fn extract_pax_extensions(_header: &Header) -> BTreeMap<String, String> {
    BTreeMap::new()
}
