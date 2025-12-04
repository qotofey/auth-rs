use base64::Engine as _;
use base64::engine::general_purpose;

use crate::providers::IdProvider;

#[derive(Clone)]
pub struct RefreshTokenGeneratorProvider;

impl IdProvider for RefreshTokenGeneratorProvider {
    fn provide(&self) -> Option<String> {
        let mut buffer = [0u8; 48];
        match getrandom::fill(&mut buffer) {
            Ok(_) => Some(general_purpose::URL_SAFE_NO_PAD.encode(&buffer)),
            Err(_) => None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_refresh_token() {
        // Given
        let id_provider = RefreshTokenGeneratorProvider;

        // When
        let token = id_provider.provide().unwrap();

        // Then
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn get_two_different_refresh_token() {
        // Given
        let id_provider = RefreshTokenGeneratorProvider;

        // When
        let res1 = id_provider.provide().unwrap();
        let res2 = id_provider.provide().unwrap();

        // Then
        assert_ne!(res1, res2);
    }
}

