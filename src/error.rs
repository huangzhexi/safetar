//! Shared error helpers for consistent exit codes.

use thiserror::Error;

/// Represents a user input error (invalid flags, missing paths, etc.).
#[derive(Debug, Error)]
#[error("{0}")]
pub struct UserInputError(pub String);

impl UserInputError {
    /// Convenience constructor.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
