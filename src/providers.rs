use argon2::{
    Argon2,
    Algorithm,
    Version,
    Params,
    password_hash::{
        rand_core::OsRng,  
        SaltString,
        // PasswordHash,
        PasswordHasher, 
        // PasswordVerifier,
    },
};

pub trait HashFuncProvider {
    fn provide(&self, password: &str) -> String;
}

pub struct Argon2Provider;

impl Argon2Provider {
    // TODO: добавить параметры argon2
    // #[must_use]
    // pub fn new() -> Self {
    //     Self
    // }
}

impl HashFuncProvider for Argon2Provider {
    fn provide(&self, password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        // TODO: 
        // 1 - избавиться от магических чисел
        // 2 - избавиться от unwrap
        let params = Params::new(32768, 2, 1, None).unwrap();
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        );
        // TODO: убрать unwrap
        let password_digest = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        password_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_password_hash() {
        // Given
        let argon2_provider = Argon2Provider;

        // When
        let password_digest = argon2_provider.provide("!Qwerty123");

        // Then
        assert_ne!(password_digest, "!Qwerty123");
    }

    #[tokio::test]
    async fn get_two_different_password_hash() {
        // Given
        let argon2_provider = Argon2Provider;

        // When
        let res1 = argon2_provider.provide("!Qwerty123");
        let res2 = argon2_provider.provide("!Qwerty123");

        // Then
        assert_ne!(res1, res2);
    }

    #[tokio::test]
    async fn get_params_from_password_hash() {
        // Given
        let argon2_provider = Argon2Provider;

        // When
        let password_digest = argon2_provider.provide("!Qwerty123");
        let parsed_hash = argon2::PasswordHash::new(&password_digest).unwrap();
        let parsed_params = argon2::Params::try_from(&parsed_hash).unwrap(); 

        // Then
        assert_eq!(parsed_params.m_cost(), 32768);
        assert_eq!(parsed_params.t_cost(), 2);
        assert_eq!(parsed_params.p_cost(), 1);
    }
}
