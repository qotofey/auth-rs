use crate::providers::TokenEncoderProvider;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
}

#[derive(Clone)]
pub struct JwtEncoderProvider {
    encoding_key: jsonwebtoken::EncodingKey,
    ttl_secs: u64,
}

impl JwtEncoderProvider {
    pub fn new(secret: &[u8], ttl_minutes: u64) -> Self {
        Self {
            encoding_key: jsonwebtoken::EncodingKey::from_secret(secret),
            ttl_secs: ttl_minutes * 60,
        }
    }
}

impl TokenEncoderProvider for JwtEncoderProvider {
    fn provide(&self, user_id: String) -> Option<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

        let claims = Claims {
            sub: user_id,
            exp: now + self.ttl_secs,
            iat: now,
        };

        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &self.encoding_key,
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-for-unit-tests";
    const TEST_TTL_MINUTES: u64 = 15;

    #[test]
    fn encode_jwt() {
        // Given
        let jwt_encoder = JwtEncoderProvider::new(TEST_SECRET, TEST_TTL_MINUTES);

        // When
        let token = jwt_encoder.provide("Qwerty123".to_owned()).unwrap();

        // Then
        assert_ne!(token, "Qwerty123".to_owned());
    }
}
