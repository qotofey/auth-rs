use crate::errors::AppError;
use crate::providers::HashFuncProvider;

pub trait RegisterUserDao {
    async fn create(&self, username: String, password_digest: String) -> Result<(), AppError>;
}

pub struct RegisterUser<H, R>
where
    H: HashFuncProvider,
    R: RegisterUserDao,
{
    hash_func_provider: H,
    repo: R,
}

impl<H, R> RegisterUser<H, R> 
where
    H: HashFuncProvider,
    R: RegisterUserDao,
{
    pub fn new(hash_func_provider: H, repo: R) -> Self {
        Self { hash_func_provider, repo }
    }

    pub async fn call(&self, username: String, password: String) -> Result<(), AppError> {
        let password_digest = self.hash_func_provider.provide(&password.trim().to_owned());

        self.repo.create(username.trim().to_lowercase(), password_digest).await?;

        Ok(())
    }
}
