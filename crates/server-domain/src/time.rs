//! Time as seen by the domain.

/// A point in time, in whole seconds since the Unix epoch (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Wraps a number of seconds since the Unix epoch.
    #[must_use]
    pub fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub fn as_unix_seconds(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_unix_seconds() {
        assert_eq!(
            Timestamp::from_unix_seconds(1_762_300_000).as_unix_seconds(),
            1_762_300_000
        );
    }

    #[test]
    fn timestamps_are_ordered() {
        assert!(Timestamp::from_unix_seconds(1) < Timestamp::from_unix_seconds(2));
    }
}
