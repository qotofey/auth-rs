use argon2::{
    Argon2,
    Algorithm,
    Version,
    Params,
    password_hash::{
        rand_core::OsRng,  
        SaltString,
        PasswordHasher, 
    },
};
use crate::providers::HashFuncProvider;

pub struct Argon2HasherProvider;

impl Argon2HasherProvider {
    // TODO: добавить параметры argon2
    // #[must_use]
    // pub fn new() -> Self {
    //     Self
    // }
}

impl HashFuncProvider for Argon2HasherProvider {
    fn provide(&self, password: String) -> Option<String> {
        let salt = SaltString::generate(&mut OsRng);
        // TODO: 
        // 1 - избавиться от магических чисел
        let params = match Params::new(32768, 2, 1, None) {
            Ok(params) => params,
            Err(_) => {
                // TODO: add logger
                return None;
            }
        };
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        );
        let password_digest = match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(_) => {
                // TODO: add legger
                return None;
            }
        };

        Some(password_digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_password_hash() {
        // Given
        let argon2_hasher = Argon2HasherProvider;

        // When
        let password_digest = argon2_hasher.provide("!Qwerty123".to_owned()).unwrap();

        // Then
        assert_ne!(password_digest, "!Qwerty123".to_string());
    }

    #[tokio::test]
    async fn get_two_different_password_hash() {
        // Given
        let argon2_hasher = Argon2HasherProvider;

        // When
        let res1 = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let res2 = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();

        // Then
        assert_ne!(res1, res2);
    }

    #[tokio::test]
    async fn get_params_from_password_hash() {
        // Given
        let argon2_hasher = Argon2HasherProvider;

        // When
        let password_digest = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let parsed_hash = argon2::PasswordHash::new(&password_digest).unwrap();
        let parsed_params = argon2::Params::try_from(&parsed_hash).unwrap(); 

        // Then
        assert_eq!(parsed_params.m_cost(), 32768);
        assert_eq!(parsed_params.t_cost(), 2);
        assert_eq!(parsed_params.p_cost(), 1);
    }
}
