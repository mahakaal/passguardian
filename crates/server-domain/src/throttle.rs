//! Limits repeated failed logins.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::{DomainError, Timestamp};

/// Counts failed attempts per key (the normalised email, known or not) in a time window.
///
/// The state lives in the process: enough for a single self-hosted node. A multi-node
/// deployment needs a shared implementation.
#[derive(Debug)]
pub struct LoginThrottle {
    max_failures: u32,
    window_seconds: i64,
    state: Mutex<HashMap<String, (u32, Timestamp)>>,
}

impl LoginThrottle {
    /// Allows `max_failures` failures every `window_seconds`.
    #[must_use]
    pub fn new(max_failures: u32, window_seconds: i64) -> Self {
        Self {
            max_failures,
            window_seconds,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Fails with [`DomainError::RateLimited`] if `key` is currently locked out.
    pub fn check(&self, key: &str, now: Timestamp) -> Result<(), DomainError> {
        let mut state = self.state.lock().map_err(|_| DomainError::Unavailable)?;
        match state.get(key) {
            Some(&(count, since)) if self.in_window(since, now) => {
                if count >= self.max_failures {
                    return Err(DomainError::RateLimited);
                }
            }
            Some(_) => {
                state.remove(key);
            }
            None => {}
        }
        Ok(())
    }

    /// Records a failed attempt.
    pub fn record_failure(&self, key: &str, now: Timestamp) -> Result<(), DomainError> {
        let mut state = self.state.lock().map_err(|_| DomainError::Unavailable)?;
        let entry = state.entry(key.to_owned()).or_insert((0, now));
        if self.in_window(entry.1, now) {
            entry.0 = entry.0.saturating_add(1);
        } else {
            *entry = (1, now);
        }
        Ok(())
    }

    /// Forgets the failures of `key` (after a successful login).
    pub fn reset(&self, key: &str) -> Result<(), DomainError> {
        self.state
            .lock()
            .map_err(|_| DomainError::Unavailable)?
            .remove(key);
        Ok(())
    }

    fn in_window(&self, since: Timestamp, now: Timestamp) -> bool {
        now.as_unix_seconds() - since.as_unix_seconds() < self.window_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_unix_seconds(seconds)
    }

    #[test]
    fn locks_out_after_the_maximum_number_of_failures() {
        let throttle = LoginThrottle::new(3, 60);
        for _ in 0..3 {
            assert_eq!(throttle.check("a", at(0)), Ok(()));
            throttle.record_failure("a", at(0)).unwrap();
        }
        assert_eq!(throttle.check("a", at(1)), Err(DomainError::RateLimited));
    }

    #[test]
    fn other_keys_are_not_affected() {
        let throttle = LoginThrottle::new(1, 60);
        throttle.record_failure("a", at(0)).unwrap();
        assert_eq!(throttle.check("b", at(0)), Ok(()));
    }

    #[test]
    fn the_lockout_ends_when_the_window_passes() {
        let throttle = LoginThrottle::new(1, 60);
        throttle.record_failure("a", at(0)).unwrap();
        assert_eq!(throttle.check("a", at(59)), Err(DomainError::RateLimited));
        assert_eq!(throttle.check("a", at(60)), Ok(()));
    }

    #[test]
    fn reset_forgets_the_failures() {
        let throttle = LoginThrottle::new(1, 60);
        throttle.record_failure("a", at(0)).unwrap();
        throttle.reset("a").unwrap();
        assert_eq!(throttle.check("a", at(1)), Ok(()));
    }
}
