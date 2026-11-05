//! Revision counter used for optimistic concurrency and for sync.

use crate::DomainError;

/// A monotonically increasing revision number.
///
/// Every user has one revision that grows with each change to their data, and every cipher
/// remembers the revision at which it last changed. Sync asks "what changed after revision N".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision(u64);

impl Revision {
    /// The revision of an account that has never changed.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw counter value (for example one read from storage).
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw counter value.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    /// The revision that follows this one.
    pub fn next(self) -> Result<Self, DomainError> {
        self.0
            .checked_add(1)
            .ok_or(DomainError::RevisionOverflow)
            .map(Revision::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_zero() {
        assert_eq!(Revision::ZERO.get(), 0);
    }

    #[test]
    fn new_and_get_roundtrip() {
        assert_eq!(Revision::new(7).get(), 7);
    }

    #[test]
    fn next_adds_one() {
        assert_eq!(Revision::new(7).next(), Ok(Revision::new(8)));
        assert_eq!(Revision::ZERO.next(), Ok(Revision::new(1)));
    }

    #[test]
    fn revisions_are_ordered() {
        assert!(Revision::new(1) < Revision::new(2));
        assert!(Revision::new(5) > Revision::ZERO);
    }

    #[test]
    fn next_fails_instead_of_wrapping_around() {
        assert_eq!(
            Revision::new(u64::MAX).next(),
            Err(DomainError::RevisionOverflow)
        );
    }
}
