//! Password and passphrase generator.
//!
//! Randomness is *injected*: every function that needs random numbers receives `rng`, a function
//! that returns a fresh random `u32` each time it is called (or an error). In production that is
//! [`os_random_u32`], backed by the operating system's CSPRNG; in tests it is a scripted or
//! pseudo-random fake, which makes the tests deterministic.
//!
//! Choosing among `n` options never uses a plain `% n`, which is slightly biased: see
//! [`random_index`].

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

/// Returns the character sets enabled in `classes`, in a fixed order: lowercase, uppercase,
/// digits, symbols.
#[must_use]
pub fn class_sets(classes: &CharClasses) -> Vec<&'static str> {
    let mut chars = Vec::new();
    if classes.lowercase {
        chars.push(LOWERCASE);
    }

    if classes.uppercase {
        chars.push(UPPERCASE);
    }

    if classes.digits {
        chars.push(DIGITS);
    }

    if classes.symbols {
        chars.push(SYMBOLS);
    }

    chars
}

/// Returns every character of every enabled set, one set after the other.
#[must_use]
pub fn alphabet(classes: &CharClasses) -> Vec<char> {
    class_sets(classes)
        .iter()
        .flat_map(|set| set.chars())
        .collect()
}

/// Returns a uniformly random number in `0..len`.
///
/// The naive `rng()? % len` is slightly wrong: a `u32` has 2^32 values, and unless `len` divides
/// 2^32 exactly the first few results of `%` come up once more than the others ("modulo bias").
/// To avoid it we use *rejection sampling*: values at or above `zone`, the largest multiple of
/// `len` that fits in 2^32, are discarded and a new one is drawn. What remains maps evenly onto
/// `0..len`.
///
/// # Errors
///
/// [`GeneratorError::InvalidRange`] if `len` is zero or does not fit in a `u32`, and
/// [`GeneratorError::Random`] if the random source fails.
pub fn random_index(
    rng: &mut impl FnMut() -> Result<u32, CryptoError>,
    len: usize,
) -> Result<usize, GeneratorError> {
    let len = u32::try_from(len).map_err(|_| GeneratorError::InvalidRange)?;
    if len == 0 {
        return Err(GeneratorError::InvalidRange);
    }

    let zone: u64 = u64::pow(2, 32) / u64::from(len) * u64::from(len);

    loop {
        let x: u32 = rng()?;
        if u64::from(x) < zone {
            return usize::try_from(x % len).map_err(|_| GeneratorError::InvalidRange);
        }
    }
}

/// Generates a password of exactly `length` characters containing at least one character from
/// every enabled class.
///
/// One character is drawn from each enabled class first, so the guarantee holds by construction;
/// the remaining positions are filled from the whole alphabet. The result is then shuffled with
/// Fisher–Yates, otherwise the guaranteed characters would always sit at the front.
///
/// # Errors
///
/// [`GeneratorError::NoCharacterClass`] if no class is enabled,
/// [`GeneratorError::LengthTooShort`] if `length` is smaller than the number of enabled classes,
/// and [`GeneratorError::Random`] if the random source fails.
pub fn generate_password(
    rng: &mut impl FnMut() -> Result<u32, CryptoError>,
    length: usize,
    classes: &CharClasses,
) -> Result<String, GeneratorError> {
    let sets = class_sets(classes);
    if sets.is_empty() {
        return Err(GeneratorError::NoCharacterClass);
    }

    if length < sets.len() {
        return Err(GeneratorError::LengthTooShort { min: sets.len() });
    }

    let mut password: Vec<char> = Vec::new();
    for set in &sets {
        let chars: Vec<char> = set.chars().collect();
        password.push(chars[random_index(rng, chars.len())?]);
    }

    let remaining = length - password.len();
    let domain = alphabet(classes);

    for _ in 0..remaining {
        password.push(domain[random_index(rng, domain.len())?]);
    }

    for i in (1..password.len()).rev() {
        password.swap(i, random_index(rng, i + 1)?);
    }

    Ok(password.into_iter().collect())
}

/// Generates a passphrase of `count` words picked at random (repetition allowed) from `words`
/// and joined with `separator`.
///
/// The word list is a parameter on purpose: which list to ship, and under which licence, is a
/// separate decision.
///
/// # Errors
///
/// [`GeneratorError::EmptyWordList`] if `words` is empty, [`GeneratorError::ZeroWords`] if
/// `count` is zero, and [`GeneratorError::Random`] if the random source fails.
pub fn generate_passphrase(
    rng: &mut impl FnMut() -> Result<u32, CryptoError>,
    words: &[&str],
    count: usize,
    separator: &str,
) -> Result<String, GeneratorError> {
    if words.is_empty() {
        return Err(GeneratorError::EmptyWordList);
    }

    if count == 0 {
        return Err(GeneratorError::ZeroWords);
    }

    let mut passphrase: Vec<&str> = Vec::new();
    for _ in 0..count {
        let index = random_index(rng, words.len())?;
        passphrase.push(words[index]);
    }

    Ok(passphrase.join(separator))
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

    // --- class_sets --------------------------------------------------------------------

    #[test]
    fn class_sets_nothing_enabled_gives_no_sets() {
        assert_eq!(class_sets(&NONE), [] as [&str; 0]);
    }

    #[test]
    fn class_sets_all_enabled_in_fixed_order() {
        assert_eq!(
            class_sets(&ALL),
            vec![LOWERCASE, UPPERCASE, DIGITS, SYMBOLS]
        );
    }

    #[test]
    fn class_sets_only_the_enabled_sets_are_returned() {
        let classes = CharClasses {
            digits: true,
            lowercase: true,
            ..NONE
        };
        assert_eq!(class_sets(&classes), vec![LOWERCASE, DIGITS]);
    }

    // --- alphabet ----------------------------------------------------------------------

    #[test]
    fn alphabet_is_empty_when_nothing_is_enabled() {
        assert_eq!(alphabet(&NONE), [] as [char; 0]);
    }

    #[test]
    fn alphabet_has_the_expected_size() {
        let only_lower = CharClasses {
            lowercase: true,
            ..NONE
        };
        assert_eq!(alphabet(&only_lower).len(), 26);
        assert_eq!(alphabet(&ALL).len(), 26 + 26 + 10 + SYMBOLS.chars().count());
    }

    #[test]
    fn alphabet_has_no_duplicates() {
        let chars = alphabet(&ALL);
        let distinct: HashSet<char> = chars.iter().copied().collect();
        assert_eq!(distinct.len(), chars.len());
    }

    #[test]
    fn alphabet_keeps_the_set_order() {
        let classes = CharClasses {
            lowercase: true,
            digits: true,
            ..NONE
        };
        let expected: Vec<char> = format!("{LOWERCASE}{DIGITS}").chars().collect();
        assert_eq!(alphabet(&classes), expected);
    }

    // --- random_index ------------------------------------------------------------------

    #[test]
    fn random_index_a_single_choice_is_always_index_zero() {
        let mut rng = scripted(&[0, 12345, u32::MAX]);
        assert_eq!(random_index(&mut rng, 1), Ok(0));
    }

    #[test]
    fn random_index_a_value_inside_the_zone_is_reduced_modulo_len() {
        let mut rng = scripted(&[5]);
        assert_eq!(random_index(&mut rng, 10), Ok(5));
        let mut rng = scripted(&[27]);
        assert_eq!(random_index(&mut rng, 10), Ok(7));
    }

    #[test]
    fn random_index_values_in_the_biased_zone_are_rejected_for_len_10() {
        // For len = 10 the zone is 4_294_967_290: 2^32 = 4_294_967_296, and the last 6 values
        // (…290 to …295) would make the digits 0..=5 more likely than 6..=9. They must be
        // thrown away and a new number drawn. Here the first two draws are rejected.
        let mut rng = scripted(&[u32::MAX, 4_294_967_290, 4_294_967_289]);
        assert_eq!(random_index(&mut rng, 10), Ok(9));
    }

    #[test]
    fn random_index_values_in_the_biased_zone_are_rejected_for_len_3() {
        // For len = 3 only u32::MAX is outside the zone.
        let mut rng = scripted(&[u32::MAX, 7]);
        assert_eq!(random_index(&mut rng, 3), Ok(1));
    }

    #[test]
    fn random_index_the_last_value_of_the_zone_is_still_accepted() {
        let mut rng = scripted(&[4_294_967_289]);
        assert_eq!(random_index(&mut rng, 10), Ok(9));
    }

    #[test]
    fn random_index_zero_len_is_an_error() {
        let mut rng = scripted(&[1]);
        assert_eq!(random_index(&mut rng, 0), Err(GeneratorError::InvalidRange));
    }

    #[test]
    fn random_index_random_source_errors_are_propagated() {
        let mut rng = failing();
        assert_eq!(
            random_index(&mut rng, 5),
            Err(GeneratorError::Random(CryptoError::Randomness))
        );
    }

    #[test]
    fn random_index_every_index_is_reachable_and_roughly_uniform() {
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

    // --- generate_password -------------------------------------------------------------

    #[test]
    fn password_no_class_is_an_error() {
        let mut rng = pseudo(1);
        assert_eq!(
            generate_password(&mut rng, 16, &NONE),
            Err(GeneratorError::NoCharacterClass)
        );
    }

    #[test]
    fn password_length_below_the_number_of_classes_is_an_error() {
        let mut rng = pseudo(1);
        assert_eq!(
            generate_password(&mut rng, 3, &ALL),
            Err(GeneratorError::LengthTooShort { min: 4 })
        );
        assert!(generate_password(&mut rng, 4, &ALL).is_ok());
    }

    #[test]
    fn password_has_the_requested_length() {
        let mut rng = pseudo(2);
        for length in 4..=64 {
            let password = generate_password(&mut rng, length, &ALL).unwrap();
            assert_eq!(password.chars().count(), length);
        }
    }

    #[test]
    fn password_uses_only_enabled_characters() {
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
    fn password_has_at_least_one_character_of_every_enabled_class() {
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
    fn password_guaranteed_characters_are_not_always_in_front() {
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
    fn password_two_passwords_are_different() {
        let mut rng = pseudo(6);
        let a = generate_password(&mut rng, 20, &ALL).unwrap();
        let b = generate_password(&mut rng, 20, &ALL).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn password_random_source_errors_are_propagated() {
        let mut rng = failing();
        assert_eq!(
            generate_password(&mut rng, 16, &ALL),
            Err(GeneratorError::Random(CryptoError::Randomness))
        );
    }

    // --- generate_passphrase -----------------------------------------------------------

    #[test]
    fn passphrase_empty_word_list_is_an_error() {
        let mut rng = pseudo(7);
        assert_eq!(
            generate_passphrase(&mut rng, &[], 4, "-"),
            Err(GeneratorError::EmptyWordList)
        );
    }

    #[test]
    fn passphrase_zero_words_is_an_error() {
        let mut rng = pseudo(7);
        assert_eq!(
            generate_passphrase(&mut rng, &["a"], 0, "-"),
            Err(GeneratorError::ZeroWords)
        );
    }

    #[test]
    fn passphrase_words_are_picked_in_order_and_joined() {
        // For 3 words the zone excludes only u32::MAX, so 0, 1, 2 map to indexes 0, 1, 2.
        let mut rng = scripted(&[2, 0, 1]);
        let phrase = generate_passphrase(&mut rng, &["apple", "bread", "cherry"], 3, "-").unwrap();
        assert_eq!(phrase, "cherry-apple-bread");
    }

    #[test]
    fn passphrase_uses_only_words_of_the_list() {
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
    fn passphrase_empty_separator_is_allowed_and_words_can_repeat() {
        let mut rng = scripted(&[0, 0]);
        let phrase = generate_passphrase(&mut rng, &["x", "y"], 2, "").unwrap();
        assert_eq!(phrase, "xx");
    }

    #[test]
    fn passphrase_random_source_errors_are_propagated() {
        let mut rng = failing();
        assert_eq!(
            generate_passphrase(&mut rng, &["a", "b"], 3, "-"),
            Err(GeneratorError::Random(CryptoError::Randomness))
        );
    }

    // --- os_random_u32 -----------------------------------------------------------------

    #[test]
    fn os_random_source_works() {
        assert!(os_random_u32().is_ok());
    }
}
