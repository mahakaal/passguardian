//! Email address, validated and normalised once at the edge of the domain.

use crate::DomainError;

/// Longest address accepted (RFC 5321 limit).
pub const MAX_EMAIL_LEN: usize = 254;

/// A syntactically plausible email address, trimmed and lowercased.
///
/// The check is deliberately simple: exactly one `@`, a non-empty local part and a
/// non-empty domain, no whitespace, at most [`MAX_EMAIL_LEN`] characters. The real proof
/// that an address works is sending a message to it, which is not the domain's job.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    /// Validates and normalises `raw`.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let normalized = raw.trim().to_lowercase();

        if normalized.chars().any(char::is_whitespace) {
            return Err(DomainError::InvalidEmail);
        }

        let (local, domain) = normalized
            .split_once('@')
            .ok_or(DomainError::InvalidEmail)?;

        if local.is_empty() {
            return Err(DomainError::InvalidEmail);
        }

        if domain.is_empty() || domain.contains('@') {
            return Err(DomainError::InvalidEmail);
        }

        if normalized.len() > MAX_EMAIL_LEN {
            return Err(DomainError::InvalidEmail);
        }

        Ok(Self(normalized))
    }

    /// The normalised address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_normal_address() {
        let email = Email::parse("manu@example.com").unwrap();
        assert_eq!(email.as_str(), "manu@example.com");
    }

    #[test]
    fn trims_and_lowercases() {
        let email = Email::parse("  Manu@Example.COM \n").unwrap();
        assert_eq!(email.as_str(), "manu@example.com");
    }

    #[test]
    fn addresses_differing_only_in_case_are_equal() {
        assert_eq!(
            Email::parse("A@B.it").unwrap(),
            Email::parse("a@b.IT").unwrap()
        );
    }

    #[test]
    fn rejects_malformed_addresses() {
        for bad in [
            "",
            "   ",
            "no-at-sign",
            "two@@signs.com",
            "a@b@c.com",
            "@example.com",
            "manu@",
            "ma nu@example.com",
            "manu@exam\tple.com",
        ] {
            assert_eq!(Email::parse(bad), Err(DomainError::InvalidEmail), "{bad:?}");
        }
    }

    #[test]
    fn length_limit_is_254_characters() {
        let domain = "@example.com";
        let ok = format!("{}{domain}", "a".repeat(MAX_EMAIL_LEN - domain.len()));
        let too_long = format!("{}{domain}", "a".repeat(MAX_EMAIL_LEN - domain.len() + 1));
        assert!(Email::parse(&ok).is_ok());
        assert_eq!(Email::parse(&too_long), Err(DomainError::InvalidEmail));
    }
}
