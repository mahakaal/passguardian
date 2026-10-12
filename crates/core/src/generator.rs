//! Password and passphrase generator.
//!
//! LEARNING EXERCISE (PG-20). The functions below are stubs marked `todo!()`; the tests are
//! already written. Work through the steps in order and turn the tests green one step at a time:
//!
//! ```text
//! cargo test -p passguardian-core generator::tests::step1
//! cargo test -p passguardian-core generator::tests::step2
//! ... and so on, then the whole module:
//! cargo test -p passguardian-core generator
//! ```
//!
//! Randomness is *injected*: every function that needs random numbers receives `rng`, a function
//! that returns a fresh random `u32` each time it is called (or an error). In production it is
//! [`os_random_u32`]; in tests it is a scripted or pseudo-random fake, which makes the tests
//! deterministic.

use thiserror::Error;

use crate::CryptoError;

/// Lowercase letters.
pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
/// Uppercase letters.
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Decimal digits.
pub const DIGITS: &str = "0123456789";
/// Symbols.
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/";

/// Which kinds of characters a password may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // four independent switches are the natural shape here
pub struct CharClasses {
    /// Allow `a-z`.
    pub lowercase: bool,
    /// Allow `A-Z`.
    pub uppercase: bool,
    /// Allow `0-9`.
    pub digits: bool,
    /// Allow the characters in [`SYMBOLS`].
    pub symbols: bool,
}

/// Errors of the generator.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneratorError {
    /// No character class was enabled.
    #[error("at least one character class must be enabled")]
    NoCharacterClass,
    /// The password would be too short to contain one character of every enabled class.
    #[error("length must be at least {min} to include every enabled class")]
    LengthTooShort {
        /// Smallest acceptable length.
        min: usize,
    },
    /// Asked to choose among zero options (or among more than `u32::MAX`).
    #[error("cannot choose from an empty or oversized range")]
    InvalidRange,
    /// The word list is empty.
    #[error("the word list is empty")]
    EmptyWordList,
    /// A passphrase needs at least one word.
    #[error("a passphrase needs at least one word")]
    ZeroWords,
    /// The random source failed.
    #[error(transparent)]
    Random(#[from] CryptoError),
}

/// Random numbers straight from the operating system. This is the `rng` to use in production.
pub fn os_random_u32() -> Result<u32, CryptoError> {
    let bytes = crate::aead::random_bytes::<4>()?;
    Ok(u32::from_le_bytes(bytes))
}

// ---------------------------------------------------------------------------------------------
// STEP 1 — the enabled character sets.
//
// Return the character sets enabled in `classes`, in this fixed order: lowercase, uppercase,
// digits, symbols. For example, with only `digits` and `lowercase` enabled the result is
// `vec![LOWERCASE, DIGITS]`.
//
// Rust concepts: structs and field access, `bool` in `if`, `Vec::new` and `push`, `mut`.
// ---------------------------------------------------------------------------------------------
#[must_use]
pub fn class_sets(classes: &CharClasses) -> Vec<&'static str> {
    todo!("step 1")
}

// ---------------------------------------------------------------------------------------------
// STEP 2 — the alphabet.
//
// Return every character of every enabled set, one after the other (use `class_sets`).
// With all classes enabled the alphabet has 26 + 26 + 10 + SYMBOLS.len() characters.
//
// Rust concepts: iterators (`iter`, `flat_map`, `chars`), `collect`, `Vec<char>`.
// Hint: `class_sets(classes).iter().flat_map(|set| set.chars()).collect()`
// ---------------------------------------------------------------------------------------------
#[must_use]
pub fn alphabet(classes: &CharClasses) -> Vec<char> {
    todo!("step 2")
}

// ---------------------------------------------------------------------------------------------
// STEP 3 — an unbiased random index (the heart of the generator).
//
// Return a uniformly random number in `0..len`.
//
// The naive way is `rng()? % len`, and it is slightly WRONG. A `u32` has 2^32 values; unless
// `len` divides 2^32 exactly, the first few results of `%` come up one time more often than the
// others ("modulo bias"). The fix is *rejection sampling*:
//
//   1. compute `zone`, the largest multiple of `len` that is <= 2^32 (use `u64` for the math,
//      because 2^32 does not fit in a `u32`):  zone = (2^32 / len) * len
//   2. draw `x = rng()?`; if `x >= zone`, throw it away and draw again;
//   3. otherwise the answer is `x % len`.
//
// Errors: `len == 0` (or a `len` that does not fit in `u32`) is `GeneratorError::InvalidRange`.
// An error coming from `rng` is propagated with the `?` operator.
//
// Rust concepts: `loop`, `Result` and `?`, integer types and conversions (`u32::try_from`,
// `u64::from`), `Option`/`Result` mapping with `map_err`.
// ---------------------------------------------------------------------------------------------
pub fn random_index(
    rng: &mut impl FnMut() -> Result<u32, CryptoError>,
    len: usize,
) -> Result<usize, GeneratorError> {
    todo!("step 3")
}

// ---------------------------------------------------------------------------------------------
// STEP 4 — the password.
//
// Return a password of exactly `length` characters that contains AT LEAST ONE character from
// every enabled class. Suggested algorithm:
//
//   1. `let sets = class_sets(classes)`; none enabled → `NoCharacterClass`;
//      `length < sets.len()` → `LengthTooShort { min: sets.len() }`;
//   2. for every set, pick one random character of it (use `random_index`);
//   3. fill the remaining positions with random characters of the whole `alphabet`;
//   4. shuffle the result with the Fisher–Yates algorithm, so the guaranteed characters do not
//      always sit at the front:  for i in (1..n).rev() { swap(i, random_index(i + 1)) }
//
// Rust concepts: `for` over a `Vec` and over ranges, `.rev()`, `Vec::swap`, `String` from chars
// (`.into_iter().collect()`), `&mut` references, propagating errors with `?`.
// ---------------------------------------------------------------------------------------------
pub fn generate_password(
    rng: &mut impl FnMut() -> Result<u32, CryptoError>,
    length: usize,
    classes: &CharClasses,
) -> Result<String, GeneratorError> {
    todo!("step 4")
}

// ---------------------------------------------------------------------------------------------
// STEP 5 — the passphrase.
//
// Pick `count` words at random (repetition allowed) from `words` and join them with `separator`.
// Empty `words` → `EmptyWordList`; `count == 0` → `ZeroWords`.
// The word list is a parameter on purpose: which list to ship (and under which licence) is a
// separate decision.
//
// Rust concepts: slices (`&[&str]`), `Vec<&str>`, `.join`.
// ---------------------------------------------------------------------------------------------
pub fn generate_passphrase(
    rng: &mut impl FnMut() -> Result<u32, CryptoError>,
    words: &[&str],
    count: usize,
    separator: &str,
) -> Result<String, GeneratorError> {
    todo!("step 5")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const ALL: CharClasses = CharClasses {
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
    };
    const NONE: CharClasses = CharClasses {
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
    };

    /// A fake random source that returns the given values in order, and panics if it runs out
    /// (so a function that draws more numbers than expected is caught).
    fn scripted(values: &[u32]) -> impl FnMut() -> Result<u32, CryptoError> {
        let mut values = Vec::from(values).into_iter();
        move || Ok(values.next().expect("random source ran out of values"))
    }

    /// A small, deterministic pseudo-random generator (xorshift32) for statistical tests.
    fn pseudo(seed: u32) -> impl FnMut() -> Result<u32, CryptoError> {
        let mut state = seed;
        move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            Ok(state)
        }
    }

    fn failing() -> impl FnMut() -> Result<u32, CryptoError> {
        || Err(CryptoError::Randomness)
    }

    // --- Step 1 ----------------------------------------------------------------------------

    #[test]
    fn step1_nothing_enabled_gives_no_sets() {
        assert!(class_sets(&NONE).is_empty());
    }

    #[test]
    fn step1_all_enabled_in_fixed_order() {
        assert_eq!(
            class_sets(&ALL),
            vec![LOWERCASE, UPPERCASE, DIGITS, SYMBOLS]
        );
    }

    #[test]
    fn step1_only_the_enabled_sets_are_returned() {
        let classes = CharClasses {
            digits: true,
            lowercase: true,
            ..NONE
        };
        assert_eq!(class_sets(&classes), vec![LOWERCASE, DIGITS]);
    }

    // --- Step 2 ----------------------------------------------------------------------------

    #[test]
    fn step2_alphabet_is_empty_when_nothing_is_enabled() {
        assert!(alphabet(&NONE).is_empty());
    }

    #[test]
    fn step2_alphabet_has_the_expected_size() {
        let only_lower = CharClasses {
            lowercase: true,
            ..NONE
        };
        assert_eq!(alphabet(&only_lower).len(), 26);
        assert_eq!(alphabet(&ALL).len(), 26 + 26 + 10 + SYMBOLS.chars().count());
    }

    #[test]
    fn step2_alphabet_has_no_duplicates() {
        let chars = alphabet(&ALL);
        let distinct: HashSet<char> = chars.iter().copied().collect();
        assert_eq!(distinct.len(), chars.len());
    }

    #[test]
    fn step2_alphabet_keeps_the_set_order() {
        let classes = CharClasses {
            lowercase: true,
            digits: true,
            ..NONE
        };
        let expected: Vec<char> = format!("{LOWERCASE}{DIGITS}").chars().collect();
        assert_eq!(alphabet(&classes), expected);
    }

    // --- Step 3 ----------------------------------------------------------------------------

    #[test]
    fn step3_a_single_choice_is_always_index_zero() {
        let mut rng = scripted(&[0, 12345, u32::MAX]);
        assert_eq!(random_index(&mut rng, 1), Ok(0));
    }

    #[test]
    fn step3_a_value_inside_the_zone_is_reduced_modulo_len() {
        let mut rng = scripted(&[5]);
        assert_eq!(random_index(&mut rng, 10), Ok(5));
        let mut rng = scripted(&[27]);
        assert_eq!(random_index(&mut rng, 10), Ok(7));
    }

    #[test]
    fn step3_values_in_the_biased_zone_are_rejected_for_len_10() {
        // For len = 10 the zone is 4_294_967_290: 2^32 = 4_294_967_296, and the last 6 values
        // (…290 to …295) would make the digits 0..=5 more likely than 6..=9. They must be
        // thrown away and a new number drawn. Here the first two draws are rejected.
        let mut rng = scripted(&[u32::MAX, 4_294_967_290, 4_294_967_289]);
        assert_eq!(random_index(&mut rng, 10), Ok(9));
    }

    #[test]
    fn step3_values_in_the_biased_zone_are_rejected_for_len_3() {
        // For len = 3 only u32::MAX is outside the zone.
        let mut rng = scripted(&[u32::MAX, 7]);
        assert_eq!(random_index(&mut rng, 3), Ok(1));
    }

    #[test]
    fn step3_the_last_value_of_the_zone_is_still_accepted() {
        let mut rng = scripted(&[4_294_967_289]);
        assert_eq!(random_index(&mut rng, 10), Ok(9));
    }

    #[test]
    fn step3_zero_len_is_an_error() {
        let mut rng = scripted(&[1]);
        assert_eq!(random_index(&mut rng, 0), Err(GeneratorError::InvalidRange));
    }

    #[test]
    fn step3_random_source_errors_are_propagated() {
        let mut rng = failing();
        assert_eq!(
            random_index(&mut rng, 5),
            Err(GeneratorError::Random(CryptoError::Randomness))
        );
    }

    #[test]
    fn step3_every_index_is_reachable_and_roughly_uniform() {
        let mut rng = pseudo(0x9E37_79B9);
        let mut counts = [0usize; 7];
        for _ in 0..70_000 {
            counts[random_index(&mut rng, 7).unwrap()] += 1;
        }
        // Expected 10_000 each; allow ±5 %.
        for (index, count) in counts.iter().enumerate() {
            assert!(
                (9_500..=10_500).contains(count),
                "index {index} came up {count} times"
            );
        }
    }

    // --- Step 4 ----------------------------------------------------------------------------

    #[test]
    fn step4_no_class_is_an_error() {
        let mut rng = pseudo(1);
        assert_eq!(
            generate_password(&mut rng, 16, &NONE),
            Err(GeneratorError::NoCharacterClass)
        );
    }

    #[test]
    fn step4_length_below_the_number_of_classes_is_an_error() {
        let mut rng = pseudo(1);
        assert_eq!(
            generate_password(&mut rng, 3, &ALL),
            Err(GeneratorError::LengthTooShort { min: 4 })
        );
        assert!(generate_password(&mut rng, 4, &ALL).is_ok());
    }

    #[test]
    fn step4_password_has_the_requested_length() {
        let mut rng = pseudo(2);
        for length in 4..=64 {
            let password = generate_password(&mut rng, length, &ALL).unwrap();
            assert_eq!(password.chars().count(), length);
        }
    }

    #[test]
    fn step4_password_uses_only_enabled_characters() {
        let classes = CharClasses {
            lowercase: true,
            digits: true,
            ..NONE
        };
        let allowed: HashSet<char> = alphabet(&classes).into_iter().collect();
        let mut rng = pseudo(3);
        for _ in 0..200 {
            let password = generate_password(&mut rng, 24, &classes).unwrap();
            assert!(password.chars().all(|c| allowed.contains(&c)), "{password}");
        }
    }

    #[test]
    fn step4_password_has_at_least_one_character_of_every_enabled_class() {
        let mut rng = pseudo(4);
        // Short passwords are the hard case: 4 characters, 4 classes.
        for length in [4, 5, 8, 20] {
            for _ in 0..300 {
                let password = generate_password(&mut rng, length, &ALL).unwrap();
                for set in [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS] {
                    assert!(
                        password.chars().any(|c| set.contains(c)),
                        "{password:?} misses a class"
                    );
                }
            }
        }
    }

    #[test]
    fn step4_guaranteed_characters_are_not_always_in_front() {
        // With 4 classes and length 4, a missing shuffle would always give
        // lower, upper, digit, symbol in that order.
        let mut rng = pseudo(5);
        let in_class_order = (0..200)
            .filter(|_| {
                let p: Vec<char> = generate_password(&mut rng, 4, &ALL)
                    .unwrap()
                    .chars()
                    .collect();
                LOWERCASE.contains(p[0])
                    && UPPERCASE.contains(p[1])
                    && DIGITS.contains(p[2])
                    && SYMBOLS.contains(p[3])
            })
            .count();
        assert!(
            in_class_order < 40,
            "{in_class_order} of 200 were unshuffled"
        );
    }

    #[test]
    fn step4_two_passwords_are_different() {
        let mut rng = pseudo(6);
        let a = generate_password(&mut rng, 20, &ALL).unwrap();
        let b = generate_password(&mut rng, 20, &ALL).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn step4_random_source_errors_are_propagated() {
        let mut rng = failing();
        assert_eq!(
            generate_password(&mut rng, 16, &ALL),
            Err(GeneratorError::Random(CryptoError::Randomness))
        );
    }

    // --- Step 5 ----------------------------------------------------------------------------

    #[test]
    fn step5_empty_word_list_is_an_error() {
        let mut rng = pseudo(7);
        assert_eq!(
            generate_passphrase(&mut rng, &[], 4, "-"),
            Err(GeneratorError::EmptyWordList)
        );
    }

    #[test]
    fn step5_zero_words_is_an_error() {
        let mut rng = pseudo(7);
        assert_eq!(
            generate_passphrase(&mut rng, &["a"], 0, "-"),
            Err(GeneratorError::ZeroWords)
        );
    }

    #[test]
    fn step5_words_are_picked_in_order_and_joined() {
        // For 3 words the zone excludes only u32::MAX, so 0, 1, 2 map to indexes 0, 1, 2.
        let mut rng = scripted(&[2, 0, 1]);
        let phrase = generate_passphrase(&mut rng, &["apple", "bread", "cherry"], 3, "-").unwrap();
        assert_eq!(phrase, "cherry-apple-bread");
    }

    #[test]
    fn step5_passphrase_uses_only_words_of_the_list() {
        let words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
        let mut rng = pseudo(8);
        for _ in 0..100 {
            let phrase = generate_passphrase(&mut rng, &words, 6, " ").unwrap();
            let picked: Vec<&str> = phrase.split(' ').collect();
            assert_eq!(picked.len(), 6);
            assert!(picked.iter().all(|w| words.contains(w)), "{phrase}");
        }
    }

    #[test]
    fn step5_empty_separator_is_allowed_and_words_can_repeat() {
        let mut rng = scripted(&[0, 0]);
        let phrase = generate_passphrase(&mut rng, &["x", "y"], 2, "").unwrap();
        assert_eq!(phrase, "xx");
    }

    #[test]
    fn step5_random_source_errors_are_propagated() {
        let mut rng = failing();
        assert_eq!(
            generate_passphrase(&mut rng, &["a", "b"], 3, "-"),
            Err(GeneratorError::Random(CryptoError::Randomness))
        );
    }

    // --- Provided for you ------------------------------------------------------------------

    #[test]
    fn os_random_source_works() {
        assert!(os_random_u32().is_ok());
    }
}
