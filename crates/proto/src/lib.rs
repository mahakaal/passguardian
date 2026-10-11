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

#[cfg(test)]
mod tests {
    use super::*;

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
