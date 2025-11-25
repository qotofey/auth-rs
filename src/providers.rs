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
    fn provide(&self, password: String) -> String;
}

pub struct Argon2Provider;

impl Argon2Provider {
    // TODO: добавить параметры argon2
    pub fn new() -> Self {
        Self
    }
}

impl HashFuncProvider for Argon2Provider {
    fn provide(&self, password: String) -> String {
        let salt = SaltString::generate(&mut OsRng);
        println!("{salt}");
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
