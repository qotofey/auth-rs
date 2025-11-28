pub mod argon2_hasher;
pub mod argon2_verifier;
pub mod jwt_encoder;
pub mod refresh_token_generator;

pub trait HashFuncProvider {
    fn provide(&self, password: String) -> Option<String>;
}

pub trait HashVerifierProvider {
    fn provide(&self, password: String, password_digest: String) -> bool;
}

pub trait TokenProvider {
    fn provide(&self, user_id: String) -> Option<String>;
}

pub trait IdProvider {
    fn provide(&self) -> Option<String>;
}
