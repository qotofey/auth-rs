use crate::{
    errors::AppError,
    providers::HashFuncProvider,
    app::commands::RegisterUserDao,
};

pub struct RegisterUserCommand<H, R>
where
    H: HashFuncProvider,
    R: RegisterUserDao,
{
    hash_func_provider: H,
    repo: R,
}

impl<H, R> RegisterUserCommand<H, R> 
where
    H: HashFuncProvider,
    R: RegisterUserDao,
{
    pub fn new(hash_func_provider: H, repo: R) -> Self {
        Self { hash_func_provider, repo }
    }

    pub async fn call(&self, username: String, password: String) -> Result<(), AppError> {
        let password_digest = match self.hash_func_provider.provide(password) {
            Some(hash) => hash,
            None => {
                return Err(AppError::UnknownError);
            }, 
        };
        let login_type = "username".to_string();
        self.repo.register_user(login_type, username.trim().to_lowercase(), password_digest).await?;

        Ok(())
    }
}
