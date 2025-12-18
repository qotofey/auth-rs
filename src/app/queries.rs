use crate::{
    errors::AppError,
    app::{
        UserCredential,
        UserSecret,
        User,
    },
};

pub mod find_user;

pub trait FindUserCredentialDao {
    fn find_user_credential_by_login(&self, login: String) -> impl std::future::Future<Output = Result<Option<UserCredential>, AppError>> + Send;
}

pub trait FindUserSecretDao {
    // TODO: если не найдена запись - паникаовать
    fn find_user_secret_by_user_id(&self, id: uuid::Uuid) -> impl std::future::Future<Output = Result<Option<UserSecret>, AppError>> + Send;
}

pub trait FindUserDao {
    fn find_user_by_id(&self, user_id: uuid::Uuid) -> impl std::future::Future<Output = Result<Option<User>, AppError>> + Send;
}
