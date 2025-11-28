use argon2::{
    Argon2,
    Algorithm,
    Version,
    Params,
    password_hash::{
        rand_core::OsRng,  
        SaltString,
        PasswordHash,
        PasswordHasher, 
        PasswordVerifier,
    },
};
use crate::providers::HashVerifierProvider;

pub struct Argon2VerifierProvider;

impl Argon2VerifierProvider {
    // TODO: добавить параметры argon2
    // #[must_use]
    // pub fn new() -> Self {
    //     Self
    // }
}

impl HashVerifierProvider for Argon2VerifierProvider {
    fn provide(&self, password: String, password_digest: String) -> bool {
        let parsed_hash = PasswordHash::new(&password_digest).unwrap();
        
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::HashFuncProvider;
    use crate::providers::argon2_hasher::Argon2HasherProvider;

    #[test]
    fn verify_password() {
        // Given
        let argon2_hasher = Argon2HasherProvider;
        let password_digest = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let argon2_verifier = Argon2VerifierProvider;
 
        // When
        let is_valid = argon2_verifier.provide("!Qwerty123".to_string(), password_digest);

        // Then
        assert!(is_valid);
    }

    #[test]
    fn get_two_different_password_hash() {
        // Given
        let argon2_hasher = Argon2HasherProvider;
        let hash1 = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let hash2 = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let argon2_verifier = Argon2VerifierProvider;

        // When
        let hash1_is_valid = argon2_verifier.provide("!Qwerty123".to_string(), hash1.clone());
        let hash2_is_valid = argon2_verifier.provide("!Qwerty123".to_string(), hash2.clone());

        // Then
        assert_ne!(hash1, hash2);
        assert!(hash1_is_valid);
        assert!(hash2_is_valid);
    }

    #[test]
    fn verify_invalid_password() {
        // Given
        let argon2_hasher = Argon2HasherProvider;
        let password_digest = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let argon2_verifier = Argon2VerifierProvider;
 
        // When
        let is_valid = argon2_verifier.provide("InvalidPassword".to_string(), password_digest);

        // Then
        assert!(!is_valid);
    }
}
