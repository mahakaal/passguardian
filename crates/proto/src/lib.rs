//! PassGuardian API contract: serializable types shared by server and clients.
//!
//! Rule: no logic here, only data. Every field that carries user data
//! must already be encrypted by the client.

use serde::{Deserialize, Serialize};

/// Response of `GET /api/v1/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// `"ok"` when the server is ready to accept traffic.
    pub status: String,
    /// Server version.
    pub version: String,
}

/// Uniform error body (inspired by RFC 9457, problem+json).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    /// Stable, machine-readable code, for example `"unavailable"`.
    pub code: String,
    /// Developer-facing message. Never contains sensitive data.
    pub message: String,
}

/// Binary fields travel as standard base64 text.
pub mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes bytes as base64.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    /// Deserializes bytes from base64.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD
            .decode(text)
            .map_err(|_| serde::de::Error::custom("invalid base64"))
    }
}

/// `POST /api/v1/accounts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Email address.
    pub email: String,
    /// Login key derived on the client (32 bytes).
    #[serde(with = "base64_bytes")]
    pub auth_key: Vec<u8>,
    /// Client key envelope: KDF parameters, salt and wrapped vault key, opaque to the server.
    #[serde(with = "base64_bytes")]
    pub key_envelope: Vec<u8>,
    /// Name of the registering device.
    pub device_name: String,
}

/// `POST /api/v1/login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Email address.
    pub email: String,
    /// Login key derived on the client (32 bytes).
    #[serde(with = "base64_bytes")]
    pub auth_key: Vec<u8>,
    /// Name of the device that is logging in.
    pub device_name: String,
}

/// Response to registration and login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    /// The user's identifier.
    pub user_id: String,
    /// This device's identifier.
    pub device_id: String,
    /// Client key envelope, as stored at registration.
    #[serde(with = "base64_bytes")]
    pub key_envelope: Vec<u8>,
    /// Short-lived token for the API.
    pub access_token: String,
    /// Long-lived token to obtain new access tokens.
    pub refresh_token: String,
}

/// `POST /api/v1/token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// The refresh token from login.
    pub refresh_token: String,
}

/// Response to a token refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// A new access token.
    pub access_token: String,
}

/// `POST /api/v1/ciphers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateCipherRequest {
    /// Identifier chosen by the client (a UUID), so items can be created offline.
    pub id: String,
    /// Folder, if any.
    pub folder_id: Option<String>,
    /// The encrypted item.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

/// `PUT /api/v1/ciphers/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCipherRequest {
    /// The revision the client last saw; a different stored revision is a conflict.
    pub revision: u64,
    /// Folder, if any.
    pub folder_id: Option<String>,
    /// The encrypted item.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

/// An encrypted item, or the tombstone of a deleted one (`deleted` true, `data` empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherResponse {
    /// Identifier.
    pub id: String,
    /// Folder, if any.
    pub folder_id: Option<String>,
    /// The encrypted item.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// The revision at which this item last changed.
    pub revision: u64,
    /// Whether this is a tombstone.
    pub deleted: bool,
}

/// Response to `GET /api/v1/sync?since=<revision>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResponse {
    /// The user's current revision: pass it as `since` next time.
    pub revision: u64,
    /// Everything that changed after `since`, in increasing revision order.
    pub changes: Vec<CipherResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_fields_are_base64_text() {
        let cipher = CipherResponse {
            id: "x".into(),
            folder_id: None,
            data: vec![0, 1, 2, 255],
            revision: 3,
            deleted: false,
        };
        let json = serde_json::to_string(&cipher).unwrap();
        assert!(json.contains("\"data\":\"AAEC/w==\""), "{json}");
        assert_eq!(
            serde_json::from_str::<CipherResponse>(&json).unwrap(),
            cipher
        );
    }

    #[test]
    fn invalid_base64_is_rejected() {
        let json = r#"{"revision":1,"folder_id":null,"data":"not base64!"}"#;
        assert!(serde_json::from_str::<UpdateCipherRequest>(json).is_err());
    }

    #[test]
    fn health_response_roundtrip() {
        let original = HealthResponse {
            status: "ok".into(),
            version: "0.1.0".into(),
        };
        let json = serde_json::to_string(&original).expect("serialization");
        let back: HealthResponse = serde_json::from_str(&json).expect("deserialization");
        assert_eq!(original, back);
    }
}
