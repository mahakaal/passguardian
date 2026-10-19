//! Time-based one-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238).
//!
//! This is the six-digit code an authenticator app shows and that changes every 30 seconds.
//! Both sides share a secret; the code is a truncated HMAC of a counter, and for TOTP the counter
//! is simply "how many periods have elapsed since the Unix epoch".
//!
//! The current time is always a parameter (`unix_time`), never read from the system clock, so
//! every function here is deterministic and testable against the official vectors.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;

/// The hash function behind the HMAC. SHA-1 is the default of almost every service; HMAC-SHA1 is
/// still considered safe for this use even though SHA-1 itself is broken for signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// HMAC-SHA1 (20-byte digest).
    Sha1,
    /// HMAC-SHA256 (32-byte digest).
    Sha256,
    /// HMAC-SHA512 (64-byte digest).
    Sha512,
}

/// Errors of the one-time password functions.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotpError {
    /// The number of digits must be 6, 7 or 8.
    #[error("the number of digits must be between 6 and 8")]
    InvalidDigits,
    /// The period must be at least one second.
    #[error("the period must be at least one second")]
    InvalidPeriod,
    /// The shared secret must not be empty.
    #[error("the shared secret must not be empty")]
    EmptySecret,
    /// An HMAC digest is at least 20 bytes long; a shorter one cannot be truncated.
    #[error("the digest is too short to be truncated")]
    DigestTooShort,
    /// The HMAC implementation rejected the key. HMAC accepts keys of any length, so this is not
    /// expected to happen; it exists so that no code path has to panic.
    #[error("the HMAC key was rejected")]
    InvalidKey,
}

/// Computes `HMAC(secret, message)` with the chosen hash. Provided for you: it is generic code
/// over several types, which is more advanced Rust than the exercise needs.
fn hmac_digest(algorithm: Algorithm, secret: &[u8], message: &[u8]) -> Result<Vec<u8>, TotpError> {
    fn run<M: Mac + KeyInit>(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, TotpError> {
        let mut mac = <M as Mac>::new_from_slice(secret).map_err(|_| TotpError::InvalidKey)?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }
    match algorithm {
        Algorithm::Sha1 => run::<Hmac<Sha1>>(secret, message),
        Algorithm::Sha256 => run::<Hmac<Sha256>>(secret, message),
        Algorithm::Sha512 => run::<Hmac<Sha512>>(secret, message),
    }
}

/// Dynamic truncation (RFC 4226, section 5.3): turns an HMAC digest into a 31-bit number.
///
/// The low four bits of the last byte give an `offset`; the four bytes of the digest starting at
/// that offset are read as a big-endian integer, and the top bit is cleared so the result is the
/// same on machines that treat it as signed.
///
/// # Errors
///
/// [`TotpError::DigestTooShort`] if the digest is empty or the four bytes at `offset` do not fit.
pub fn dynamic_truncate(digest: &[u8]) -> Result<u32, TotpError> {
    let last_byte = digest.last().copied().ok_or(TotpError::DigestTooShort)?;
    let offset = usize::from(last_byte & 0x0f);
    let window = digest
        .get(offset..offset + 4)
        .ok_or(TotpError::DigestTooShort)?;
    let bytes = <[u8; 4]>::try_from(window).map_err(|_| TotpError::DigestTooShort)?;
    Ok(u32::from_be_bytes(bytes) & 0x7fff_ffff)
}

/// Reduces a truncated value to `digits` decimal digits, with leading zeros kept
/// (`42` with 6 digits is `"000042"`).
///
/// # Errors
///
/// [`TotpError::InvalidDigits`] unless `digits` is 6, 7 or 8.
pub fn format_code(value: u32, digits: u32) -> Result<String, TotpError> {
    if !(6..=8).contains(&digits) {
        return Err(TotpError::InvalidDigits);
    }

    let code = value % 10_u32.pow(digits);
    Ok(format!("{code:0width$}", width = digits as usize))
}

/// The TOTP counter: how many whole `period`-second steps fit in `unix_time`.
///
/// # Errors
///
/// [`TotpError::InvalidPeriod`] if `period` is zero.
pub fn time_step(unix_time: u64, period: u64) -> Result<u64, TotpError> {
    unix_time
        .checked_div(period)
        .ok_or(TotpError::InvalidPeriod)
}

/// HOTP (RFC 4226): the one-time code for a given `counter`.
///
/// The counter is fed to the HMAC as 8 big-endian bytes.
///
/// # Errors
///
/// [`TotpError::EmptySecret`] for an empty secret, [`TotpError::InvalidDigits`] for unsupported
/// lengths, and the errors of [`dynamic_truncate`].
pub fn hotp(
    algorithm: Algorithm,
    secret: &[u8],
    counter: u64,
    digits: u32,
) -> Result<String, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    let digest = &hmac_digest(algorithm, secret, &counter.to_be_bytes())?;
    format_code(dynamic_truncate(digest)?, digits)
}

/// TOTP (RFC 6238): the code valid at `unix_time` (seconds since 1970-01-01 UTC) for codes that
/// change every `period` seconds. Authenticator apps use `period = 30` and `digits = 6`.
///
/// # Errors
///
/// [`TotpError::InvalidPeriod`] if `period` is zero, plus the errors of [`hotp`].
pub fn totp(
    algorithm: Algorithm,
    secret: &[u8],
    unix_time: u64,
    period: u64,
    digits: u32,
) -> Result<String, TotpError> {
    let counter = time_step(unix_time, period)?;
    hotp(algorithm, secret, counter, digits)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a hex string into bytes (test helper).
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // The RFC 4226 test secret, also used for SHA-1 in RFC 6238.
    const SECRET_SHA1: &[u8] = b"12345678901234567890";
    const SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SECRET_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    // --- dynamic_truncate --------------------------------------------------------------

    /// RFC 4226, appendix D: HMAC-SHA1 of counters 0..=9 and their truncated values.
    const RFC4226: [(&str, u32, &str); 10] = [
        (
            "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
            1_284_755_224,
            "755224",
        ),
        (
            "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
            1_094_287_082,
            "287082",
        ),
        (
            "0bacb7fa082fef30782211938bc1c5e70416ff44",
            137_359_152,
            "359152",
        ),
        (
            "66c28227d03a2d5529262ff016a1e6ef76557ece",
            1_726_969_429,
            "969429",
        ),
        (
            "a904c900a64b35909874b33e61c5938a8e15ed1c",
            1_640_338_314,
            "338314",
        ),
        (
            "a37e783d7b7233c083d4f62926c7a25f238d0316",
            868_254_676,
            "254676",
        ),
        (
            "bc9cd28561042c83f219324d3c607256c03272ae",
            1_918_287_922,
            "287922",
        ),
        (
            "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
            82_162_583,
            "162583",
        ),
        (
            "1b3c89f65e6c9e883012052823443f048b4332db",
            673_399_871,
            "399871",
        ),
        (
            "1637409809a679dc698207310c8c7fc07290d9e5",
            645_520_489,
            "520489",
        ),
    ];

    #[test]
    fn dynamic_truncate_matches_the_rfc_4226_vectors() {
        for (digest, truncated, _) in RFC4226 {
            assert_eq!(dynamic_truncate(&hex(digest)), Ok(truncated), "{digest}");
        }
    }

    #[test]
    fn dynamic_truncate_clears_the_top_bit() {
        // 20 bytes, last byte 0x0f => offset 15 => bytes 15..19 are all 0xff.
        let mut digest = vec![0_u8; 20];
        digest[15..19].fill(0xff);
        digest[19] = 0x0f;
        assert_eq!(dynamic_truncate(&digest), Ok(0x7fff_ffff));
    }

    #[test]
    fn dynamic_truncate_uses_the_last_byte_for_longer_digests() {
        // SHA-256 sized digest: the offset still comes from the LAST byte (index 31).
        let mut digest = vec![0_u8; 32];
        digest[31] = 0x0a; // offset 10
        digest[10..14].copy_from_slice(&[0x00, 0x00, 0x01, 0x02]);
        assert_eq!(dynamic_truncate(&digest), Ok(0x0102));
    }

    #[test]
    fn dynamic_truncate_rejects_an_empty_digest() {
        assert_eq!(dynamic_truncate(&[]), Err(TotpError::DigestTooShort));
    }

    #[test]
    fn dynamic_truncate_rejects_a_digest_too_short_for_its_offset() {
        // offset 15 needs at least 19 bytes.
        let mut digest = vec![0_u8; 10];
        digest[9] = 0x0f;
        assert_eq!(dynamic_truncate(&digest), Err(TotpError::DigestTooShort));
    }

    // --- format_code -------------------------------------------------------------------

    #[test]
    fn format_code_keeps_the_low_digits() {
        assert_eq!(format_code(1_284_755_224, 6).unwrap(), "755224");
        assert_eq!(format_code(1_094_287_082, 8).unwrap(), "94287082");
        assert_eq!(format_code(1_094_287_082, 7).unwrap(), "4287082");
    }

    #[test]
    fn format_code_keeps_leading_zeros() {
        assert_eq!(format_code(1_000_000_042, 6).unwrap(), "000042");
        assert_eq!(format_code(0, 8).unwrap(), "00000000");
    }

    #[test]
    fn format_code_rejects_unsupported_lengths() {
        assert_eq!(format_code(123, 5), Err(TotpError::InvalidDigits));
        assert_eq!(format_code(123, 9), Err(TotpError::InvalidDigits));
        assert_eq!(format_code(123, 0), Err(TotpError::InvalidDigits));
    }

    // --- time_step ---------------------------------------------------------------------

    #[test]
    fn time_step_counts_whole_periods() {
        assert_eq!(time_step(0, 30), Ok(0));
        assert_eq!(time_step(29, 30), Ok(0));
        assert_eq!(time_step(30, 30), Ok(1));
        assert_eq!(time_step(59, 30), Ok(1));
        assert_eq!(time_step(60, 30), Ok(2));
        assert_eq!(time_step(1_111_111_109, 30), Ok(37_037_036));
        assert_eq!(time_step(20_000_000_000, 30), Ok(666_666_666));
    }

    #[test]
    fn time_step_honours_other_periods() {
        assert_eq!(time_step(119, 60), Ok(1));
        assert_eq!(time_step(120, 60), Ok(2));
    }

    #[test]
    fn time_step_rejects_a_zero_period() {
        assert_eq!(time_step(100, 0), Err(TotpError::InvalidPeriod));
    }

    // --- hotp --------------------------------------------------------------------------

    #[test]
    fn hotp_matches_the_rfc_4226_vectors() {
        for (counter, (_, _, code)) in (0_u64..).zip(RFC4226) {
            assert_eq!(
                hotp(Algorithm::Sha1, SECRET_SHA1, counter, 6).as_deref(),
                Ok(code),
                "counter {counter}"
            );
        }
    }

    #[test]
    fn hotp_rejects_an_empty_secret() {
        assert_eq!(
            hotp(Algorithm::Sha1, &[], 0, 6),
            Err(TotpError::EmptySecret)
        );
    }

    #[test]
    fn hotp_rejects_unsupported_digit_counts() {
        assert_eq!(
            hotp(Algorithm::Sha1, SECRET_SHA1, 0, 5),
            Err(TotpError::InvalidDigits)
        );
    }

    #[test]
    fn hotp_depends_on_the_counter_and_on_the_secret() {
        let a = hotp(Algorithm::Sha1, SECRET_SHA1, 7, 8).unwrap();
        assert_ne!(a, hotp(Algorithm::Sha1, SECRET_SHA1, 8, 8).unwrap());
        assert_ne!(
            a,
            hotp(Algorithm::Sha1, b"another secret!!!!!", 7, 8).unwrap()
        );
    }

    // --- totp --------------------------------------------------------------------------

    /// RFC 6238, appendix B: 8-digit codes, 30-second period, for every algorithm.
    const RFC6238_TIMES: [u64; 6] = [
        59,
        1_111_111_109,
        1_111_111_111,
        1_234_567_890,
        2_000_000_000,
        20_000_000_000,
    ];

    fn check_rfc6238(algorithm: Algorithm, secret: &[u8], expected: [&str; 6]) {
        for (time, code) in RFC6238_TIMES.into_iter().zip(expected) {
            assert_eq!(
                totp(algorithm, secret, time, 30, 8).as_deref(),
                Ok(code),
                "{algorithm:?} at t={time}"
            );
        }
    }

    #[test]
    fn totp_matches_the_rfc_6238_vectors_for_sha1() {
        check_rfc6238(
            Algorithm::Sha1,
            SECRET_SHA1,
            [
                "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
            ],
        );
    }

    #[test]
    fn totp_matches_the_rfc_6238_vectors_for_sha256() {
        check_rfc6238(
            Algorithm::Sha256,
            SECRET_SHA256,
            [
                "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
            ],
        );
    }

    #[test]
    fn totp_matches_the_rfc_6238_vectors_for_sha512() {
        check_rfc6238(
            Algorithm::Sha512,
            SECRET_SHA512,
            [
                "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
            ],
        );
    }

    #[test]
    fn totp_with_six_digits_is_the_tail_of_the_eight_digit_code() {
        // 94287082 at t=59 => the 6-digit code is 287082.
        assert_eq!(
            totp(Algorithm::Sha1, SECRET_SHA1, 59, 30, 6).unwrap(),
            "287082"
        );
    }

    #[test]
    fn totp_is_constant_inside_a_period_and_changes_at_its_edge() {
        let at = |t| totp(Algorithm::Sha1, SECRET_SHA1, t, 30, 6).unwrap();
        assert_eq!(at(30), at(59));
        assert_ne!(at(59), at(60));
    }

    #[test]
    fn totp_rejects_a_zero_period() {
        assert_eq!(
            totp(Algorithm::Sha1, SECRET_SHA1, 59, 0, 6),
            Err(TotpError::InvalidPeriod)
        );
    }

    #[test]
    fn totp_propagates_hotp_errors() {
        assert_eq!(
            totp(Algorithm::Sha1, &[], 59, 30, 6),
            Err(TotpError::EmptySecret)
        );
        assert_eq!(
            totp(Algorithm::Sha1, SECRET_SHA1, 59, 30, 9),
            Err(TotpError::InvalidDigits)
        );
    }

    proptest! {
        #[test]
        fn totp_is_always_exactly_digits_long_and_numeric(
            secret in proptest::collection::vec(any::<u8>(), 1..64),
            time in any::<u64>(),
            digits in 6_u32..=8,
        ) {
            for algorithm in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
                let code = totp(algorithm, &secret, time, 30, digits).unwrap();
                prop_assert_eq!(code.len(), digits as usize);
                prop_assert!(code.bytes().all(|b| b.is_ascii_digit()));
            }
        }
    }
}
