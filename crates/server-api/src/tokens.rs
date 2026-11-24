//! Signed bearer tokens.
//!
//! A token says "this device of this user may use the API until this time". It is
//! `base64url(payload).base64url(HMAC-SHA256(secret, payload))`, with no server-side state.
//! Access tokens are short; a refresh token only buys a new access token, and only while the
//! device has not been revoked (checked by the domain at refresh time).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use passguardian_server_domain::{DeviceId, DomainError, Timestamp, UserId};
use sha2::Sha256;

/// Shortest secret accepted, in bytes.
pub const MIN_SECRET_LEN: usize = 32;

/// How long an access token lives.
pub const ACCESS_TOKEN_SECONDS: i64 = 15 * 60;

/// How long a refresh token lives.
pub const REFRESH_TOKEN_SECONDS: i64 = 30 * 24 * 60 * 60;

/// What a token may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Authorises API calls.
    Access,
    /// Only authorises asking for a new access token.
    Refresh,
}

impl TokenKind {
    fn label(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }
}

/// Who a valid token speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claims {
    /// The user.
    pub user_id: UserId,
    /// The device the token was issued to.
    pub device_id: DeviceId,
}

/// Issues and checks tokens with a server secret.
#[derive(Clone)]
pub struct TokenSigner {
    secret: Vec<u8>,
}

impl std::fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenSigner(<redacted>)")
    }
}

impl TokenSigner {
    /// Creates a signer. The secret must be at least [`MIN_SECRET_LEN`] bytes.
    pub fn new(secret: &[u8]) -> Result<Self, DomainError> {
        if secret.len() < MIN_SECRET_LEN {
            return Err(DomainError::InvalidInput);
        }
        Ok(Self {
            secret: secret.to_vec(),
        })
    }

    fn mac(&self) -> Result<Hmac<Sha256>, DomainError> {
        Hmac::<Sha256>::new_from_slice(&self.secret).map_err(|_| DomainError::InvalidInput)
    }

    /// Issues a token of `kind` for a device, valid for `lifetime_seconds` from `now`.
    pub fn issue(
        &self,
        kind: TokenKind,
        claims: Claims,
        now: Timestamp,
    ) -> Result<String, DomainError> {
        let lifetime = match kind {
            TokenKind::Access => ACCESS_TOKEN_SECONDS,
            TokenKind::Refresh => REFRESH_TOKEN_SECONDS,
        };
        let payload = format!(
            "v1|{}|{}|{}|{}",
            kind.label(),
            claims.user_id,
            claims.device_id,
            now.as_unix_seconds().saturating_add(lifetime)
        );
        let mut mac = self.mac()?;
        mac.update(payload.as_bytes());
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload.as_bytes()),
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    /// Checks a token and returns who it speaks for.
    ///
    /// Every failure (malformed, forged, expired, wrong kind) is the same error.
    pub fn verify(
        &self,
        token: &str,
        expected: TokenKind,
        now: Timestamp,
    ) -> Result<Claims, DomainError> {
        let denied = DomainError::InvalidCredentials;
        let (payload_b64, mac_b64) = token
            .split_once('.')
            .ok_or(DomainError::InvalidCredentials)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| DomainError::InvalidCredentials)?;
        let provided = URL_SAFE_NO_PAD
            .decode(mac_b64)
            .map_err(|_| DomainError::InvalidCredentials)?;

        let mut mac = self.mac()?;
        mac.update(&payload);
        mac.verify_slice(&provided)
            .map_err(|_| DomainError::InvalidCredentials)?;

        let text = String::from_utf8(payload).map_err(|_| DomainError::InvalidCredentials)?;
        let mut parts = text.split('|');
        let (Some("v1"), Some(kind), Some(user), Some(device), Some(expires), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(denied);
        };
        let expires: i64 = expires
            .parse()
            .map_err(|_| DomainError::InvalidCredentials)?;
        if kind != expected.label() || now.as_unix_seconds() >= expires {
            return Err(denied);
        }
        Ok(Claims {
            user_id: user.parse().map_err(|_| DomainError::InvalidCredentials)?,
            device_id: device
                .parse()
                .map_err(|_| DomainError::InvalidCredentials)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn signer() -> TokenSigner {
        TokenSigner::new(&[1; 32]).unwrap()
    }

    fn claims() -> Claims {
        Claims {
            user_id: UserId::from_uuid(Uuid::from_u128(1)),
            device_id: DeviceId::from_uuid(Uuid::from_u128(2)),
        }
    }

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_unix_seconds(seconds)
    }

    #[test]
    fn a_fresh_token_verifies() {
        let token = signer()
            .issue(TokenKind::Access, claims(), at(100))
            .unwrap();
        assert_eq!(
            signer().verify(&token, TokenKind::Access, at(101)),
            Ok(claims())
        );
    }

    #[test]
    fn a_token_expires() {
        let token = signer()
            .issue(TokenKind::Access, claims(), at(100))
            .unwrap();
        let last_valid = at(100 + ACCESS_TOKEN_SECONDS - 1);
        assert!(signer()
            .verify(&token, TokenKind::Access, last_valid)
            .is_ok());
        let expired = at(100 + ACCESS_TOKEN_SECONDS);
        assert_eq!(
            signer().verify(&token, TokenKind::Access, expired),
            Err(DomainError::InvalidCredentials)
        );
    }

    #[test]
    fn a_refresh_token_is_not_an_access_token_and_vice_versa() {
        let refresh = signer().issue(TokenKind::Refresh, claims(), at(0)).unwrap();
        let access = signer().issue(TokenKind::Access, claims(), at(0)).unwrap();
        assert!(signer().verify(&refresh, TokenKind::Access, at(1)).is_err());
        assert!(signer().verify(&access, TokenKind::Refresh, at(1)).is_err());
        assert!(signer().verify(&refresh, TokenKind::Refresh, at(1)).is_ok());
    }

    #[test]
    fn a_token_signed_with_another_secret_is_rejected() {
        let other = TokenSigner::new(&[2; 32]).unwrap();
        let token = other.issue(TokenKind::Access, claims(), at(0)).unwrap();
        assert!(signer().verify(&token, TokenKind::Access, at(1)).is_err());
    }

    #[test]
    fn a_modified_token_is_rejected() {
        let token = signer().issue(TokenKind::Access, claims(), at(0)).unwrap();
        for index in 0..token.len() {
            let mut bytes = token.clone().into_bytes();
            bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
            let changed = String::from_utf8(bytes).unwrap();
            if changed != token {
                assert!(
                    signer().verify(&changed, TokenKind::Access, at(1)).is_err(),
                    "accepted a token changed at {index}"
                );
            }
        }
    }

    #[test]
    fn garbage_is_rejected() {
        for garbage in ["", ".", "a.b", "not a token", "....", "\u{0}"] {
            assert!(signer().verify(garbage, TokenKind::Access, at(0)).is_err());
        }
    }

    #[test]
    fn short_secrets_are_refused() {
        assert_eq!(
            TokenSigner::new(&[1; 31]).unwrap_err(),
            DomainError::InvalidInput
        );
    }
}
