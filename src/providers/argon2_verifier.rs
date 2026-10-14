use crate::providers::{HashVerifierProvider, PasswordConfirmation};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};

#[derive(Clone)]
pub struct Argon2VerifierProvider {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Argon2VerifierProvider {
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }
}

impl HashVerifierProvider for Argon2VerifierProvider {
    fn provide(&self, password: String, password_digest: String) -> PasswordConfirmation {
        let parsed_hash = match PasswordHash::new(&password_digest) {
            Ok(hash) => hash,
            Err(_) => {
                return PasswordConfirmation {
                    is_confirmed: false,
                    need_upgrade: false,
                };
            }
        };

        let is_confirmed = Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok();

        let need_upgrade = if !is_confirmed {
            false
        } else {
            match argon2::Params::try_from(&parsed_hash) {
                Ok(params) => {
                    params.m_cost() != self.memory_cost
                        || params.t_cost() != self.time_cost
                        || params.p_cost() != self.parallelism
                }
                Err(_) => false,
            }
        };

        PasswordConfirmation {
            is_confirmed,
            need_upgrade,
        }
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
        let argon2_hasher = Argon2HasherProvider::new(8, 1, 1);
        let password_digest = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let argon2_verifier = Argon2VerifierProvider::new(8, 1, 1);

        // When
        let confirmation = argon2_verifier.provide("!Qwerty123".to_string(), password_digest);

        // Then
        assert!(confirmation.is_confirmed);
        assert!(!confirmation.need_upgrade);
    }

    #[test]
    fn verify_password_with_new_hash_params() {
        // Given
        let argon2_hasher = Argon2HasherProvider::new(8, 1, 1);
        let password_digest = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let argon2_verifier = Argon2VerifierProvider::new(8, 2, 1);

        // When
        let confirmation = argon2_verifier.provide("!Qwerty123".to_string(), password_digest);

        // Then
        assert!(confirmation.is_confirmed);
        assert!(confirmation.need_upgrade);
    }

    #[test]
    fn get_two_different_password_hash() {
        // Given
        let argon2_hasher = Argon2HasherProvider::new(8, 1, 1);
        let hash1 = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let hash2 = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let argon2_verifier = Argon2VerifierProvider::new(8, 1, 1);

        // When
        let hash1_is_valid = argon2_verifier.provide("!Qwerty123".to_string(), hash1.clone());
        let hash2_is_valid = argon2_verifier.provide("!Qwerty123".to_string(), hash2.clone());

        // Then
        assert_ne!(hash1, hash2);
        assert!(hash1_is_valid.is_confirmed);
        assert!(hash2_is_valid.is_confirmed);
    }

    #[test]
    fn verify_invalid_password() {
        // Given
        let argon2_hasher = Argon2HasherProvider::new(8, 1, 1);
        let password_digest = argon2_hasher.provide("!Qwerty123".to_string()).unwrap();
        let argon2_verifier = Argon2VerifierProvider::new(8, 1, 1);

        // When
        let confirmation = argon2_verifier.provide("InvalidPassword".to_string(), password_digest);

        // Then
        assert!(!confirmation.is_confirmed);
        assert!(!confirmation.need_upgrade);
    }
}
