use sqlx::types::uuid;
use crate::{
    errors::AppError,
    providers::{
        IdProvider, 
        TokenProvider,
    },
    app::commands::{
        Session,
        UserCredential,
    },
};

pub trait RefreshSessionDao {
    async fn refresh_session(&self, old_refresh_token: String, new_refresh_token: String) -> Result<Option<UserCredential>, sqlx::Error>;
}

pub struct RefreshSession<I, T, R>
where
    I: IdProvider,
    T: TokenProvider,
    R: RefreshSessionDao,
{
    id_provider: I,
    token_provider: T,
    repo: R,
}

#[derive(sqlx::FromRow)]
pub struct UserSession {
    pub user_credential_id: uuid::Uuid,
}

impl<I, T, R> RefreshSession<I, T, R> 
where
    I: IdProvider,
    T: TokenProvider,
    R: RefreshSessionDao
{
    pub fn new(id_provider: I, token_provider: T, repo: R) -> Self {
        Self { id_provider, token_provider, repo }
    }

    pub async fn call(&self, old_refresh_token: String) -> Result<Session, AppError> {
        let new_refresh_token = match self.id_provider.provide() {
            Some(token) => token,
            None => return Err(AppError::LoginRequired),
        };

        let result_some_credential_or_none = self.repo.refresh_session(old_refresh_token, new_refresh_token.clone()).await;
        let some_credential_or_none = match result_some_credential_or_none {
            Ok(some_credential_or_none) => some_credential_or_none,
            Err(_) => return Err(AppError::UnknownDatabaseError),
        };
        let credential = match some_credential_or_none {
            Some(credential) => credential,
            None => return Err(AppError::LoginRequired)
        };

        let access_token = match self.token_provider.provide(credential.user_id.to_string()) {
            Some(token) => token,
            None => return Err(AppError::UnknownError),
        };

        let refresh_token = new_refresh_token;
        let user_id = credential.user_id;
        Ok(Session { user_id, refresh_token, access_token })
    }
}
