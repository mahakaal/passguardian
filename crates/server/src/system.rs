//! The real clock and the real source of identifiers.

use std::time::{SystemTime, UNIX_EPOCH};

use passguardian_server_domain::ports::{Clock, IdGenerator};
use passguardian_server_domain::Timestamp;
use uuid::Uuid;

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        // A clock set before 1970 is treated as the epoch rather than panicking.
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
            });
        Timestamp::from_unix_seconds(seconds)
    }
}

/// Random (version 4) UUIDs.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RandomIds;

impl IdGenerator for RandomIds {
    fn new_uuid(&self) -> Uuid {
        Uuid::new_v4()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_is_after_2024() {
        assert!(SystemClock.now().as_unix_seconds() > 1_704_067_200);
    }

    #[test]
    fn random_ids_are_distinct() {
        assert_ne!(RandomIds.new_uuid(), RandomIds.new_uuid());
    }
}
