use crate::errors::AppError;
use crate::providers::{HashFuncProvider, IdProvider, TokenProvider};

pub trait AuthenticateUserDao {
    async fn login(&self, username: String, password_digest: String) -> Result<(), AppError>;
}

pub struct AuthenticateUser<H, R>
where
    H: HashFuncProvider,
    I: IdProvider,
    T: TokenProvider,
    R: AuthenticateUserDao,
{
    hash_func_provider: H,
    refresh_token_generator: I,
    access_token_provider: T,
    repo: R,
}
