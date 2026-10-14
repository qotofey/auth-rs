use jsonwebtoken::DecodingKey;

use crate::providers::{TokenDecoderProvider, jwt_encoder::Claims};

pub struct JwtDecoderProvider {
    decoding_key: jsonwebtoken::DecodingKey,
}

impl JwtDecoderProvider {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(secret),
        }
    }
}

impl TokenDecoderProvider for JwtDecoderProvider {
    fn provide(&self, token: String) -> Option<String> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims = std::collections::HashSet::from(["exp".to_owned()]);

        let token_data =
            jsonwebtoken::decode::<Claims>(&token, &self.decoding_key, &validation).ok()?;

        Some(token_data.claims.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_jwt() {
        // Given
        let jwt_encoder = JwtDecoderProvider;

        // When
        let token = jwt_encoder.provide("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJRd2VydHkxMjMiLCJleHAiOjE3NjYwNzk3MzgsImlhdCI6MTc2NjA3ODgzOH0.OQaBFmEhmrHc7IVtaEXz5ozEVamTKCD_1Qe_YZd0um0".to_owned()).unwrap();

        // Then
        assert_ne!(token, "!Qwerty123".to_owned());
    }
}
