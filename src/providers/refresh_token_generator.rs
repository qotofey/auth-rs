use crate::providers::IdProvider;

pub struct RefreshTokenProvider;

impl IdProvider for RefreshTokenProvider {
    fn provide(&self) -> Option<String> {
        let mut buffer = [0u8; 32];
        match getrandom::fill(&mut buffer) {
            Ok(_) => Some(hex::encode(buffer)),
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
        let id_provider = RefreshTokenProvider;

        // When
        let token = id_provider.provide().unwrap();

        // Then
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn get_two_different_refresh_token() {
        // Given
        let id_provider = RefreshTokenProvider;

        // When
        let res1 = id_provider.provide().unwrap();
        let res2 = id_provider.provide().unwrap();

        // Then
        assert_ne!(res1, res2);
    }
}

