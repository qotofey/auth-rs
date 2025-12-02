use crate::providers::TokenProvider;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    sub: String,
    exp: u64,
    iat: u64,
}

#[derive(Clone)]
pub struct JwtEncoderProvider;

impl TokenProvider for JwtEncoderProvider {
    fn provide(&self, user_id: String) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap().as_secs() as u64;
        let expires_in = now + 15 * 60;
        let claims = Claims {
            sub: user_id.clone(),
            exp: expires_in,
            iat: now,
        };
        let access_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(), 
            &claims, 
            &jsonwebtoken::EncodingKey::from_secret(b"my-super-secret-key"),
        ).unwrap();
        Some(access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_password_hash() {
        // Given
        let jwt_encoder = JwtEncoderProvider;

        // When
        let token = jwt_encoder.provide("Qwerty123".to_owned()).unwrap();

        // Then
        assert_ne!(token, "!Qwerty123".to_owned());
    }
}

