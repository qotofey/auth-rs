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

#[cfg(test)]
mod tests {
    use super::*;
    use testcontainers_modules::{
        postgres,
        testcontainers::{
            ImageExt,
            runners::AsyncRunner,
        },
    };
    use crate::{
        di,
        providers,
        adapters,
    };

    #[tokio::test]
    async fn first_call_register_user_command() {
        // Given
        let postgres_container = postgres::Postgres::default()
            .with_tag("18.1-alpine")
            .start()
            .await
            .unwrap();
        let url = &format!(
            "postgres://postgres:postgres@{}:{}/postgres", 
            postgres_container.get_host().await.unwrap(), 
            postgres_container.get_host_port_ipv4(5432).await.unwrap()
        );
        let db_pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(url).await.unwrap();
        sqlx::migrate!("./migrations").run(&db_pool).await.unwrap();

        let argon2_hasher = providers::argon2_hasher::Argon2HasherProvider::new(8, 1, 1);
        let argon2_verifier = providers::argon2_verifier::Argon2VerifierProvider::new(8, 1, 1);

        let refresh_token_generator = providers::refresh_token_generator::RefreshTokenGeneratorProvider;
        let jwt_encoder = providers::jwt_encoder::JwtEncoderProvider;

        let user_repo = adapters::postgres::UserRepository::new(db_pool.clone());
        let container = di::Container::new(
            argon2_hasher,
            argon2_verifier,
            refresh_token_generator,
            jwt_encoder,
            user_repo.clone(),
            user_repo.clone(),
            user_repo.clone(),
            user_repo.clone(),
            user_repo,
        );

        // When
        let initial_users_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM users").fetch_one(&db_pool).await.unwrap();
        let initial_user_credentials_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM user_credentials").fetch_one(&db_pool).await.unwrap();
        let initial_user_passwords_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM user_passwords").fetch_one(&db_pool).await.unwrap();

        container.register_user_command.call("user0".to_string(), "Qwerty123!".to_string()).await.unwrap();

        let final_users_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM users").fetch_one(&db_pool).await.unwrap();
        let final_user_credentials_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM user_credentials").fetch_one(&db_pool).await.unwrap();
        let final_user_passwords_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM user_passwords").fetch_one(&db_pool).await.unwrap();

        // Then
        assert_eq!(final_users_count - initial_users_count, 1);
        assert_eq!(final_user_credentials_count - initial_user_credentials_count, 1);
        assert_eq!(final_user_passwords_count - initial_user_passwords_count, 1);
    }

    #[tokio::test]
    async fn repeat_username_when_calling_register_user_command() {
        // Given
        let postgres_container = postgres::Postgres::default()
            .with_tag("18.1-alpine")
            .start()
            .await
            .unwrap();

        let url = &format!("postgres://postgres:postgres@{}:{}/postgres", postgres_container.get_host().await.unwrap(), postgres_container.get_host_port_ipv4(5432).await.unwrap());

        let db_pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(url).await.unwrap();
        sqlx::migrate!("./migrations").run(&db_pool).await.unwrap();

        let argon2_hasher = providers::argon2_hasher::Argon2HasherProvider::new(8, 1, 1);
        let argon2_verifier = providers::argon2_verifier::Argon2VerifierProvider::new(8, 1, 1);

        let refresh_token_generator = providers::refresh_token_generator::RefreshTokenGeneratorProvider;
        let jwt_encoder = providers::jwt_encoder::JwtEncoderProvider;

        let user_repo = adapters::postgres::UserRepository::new(db_pool.clone());
        let container = di::Container::new(
            argon2_hasher,
            argon2_verifier,
            refresh_token_generator,
            jwt_encoder,
            user_repo.clone(),
            user_repo.clone(),
            user_repo.clone(),
            user_repo.clone(),
            user_repo,
        );
        container.register_user_command.call("user0".to_string(), "Qwerty123!".to_string()).await.unwrap();

        // When
        let initial_users_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM users").fetch_one(&db_pool).await.unwrap();
        let initial_user_credentials_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM user_credentials").fetch_one(&db_pool).await.unwrap();
        let initial_user_passwords_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM user_passwords").fetch_one(&db_pool).await.unwrap();

        let res = container.register_user_command.call("user0".to_string(), "123123".to_string()).await;

        let final_users_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM users").fetch_one(&db_pool).await.unwrap();
        let final_user_credentials_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM user_credentials").fetch_one(&db_pool).await.unwrap();
        let final_user_passwords_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM user_passwords").fetch_one(&db_pool).await.unwrap();

        // Then
        assert_eq!(final_users_count - initial_users_count, 0);
        assert_eq!(final_user_credentials_count - initial_user_credentials_count, 0);
        assert_eq!(final_user_passwords_count - initial_user_passwords_count, 0);
        assert!(matches!(res, Err(AppError::UsernameIsTaken)));
    }

    #[tokio::test]
    async fn introduce_marginal_spaces_when_calling_register_user_command() {
        // Given
        let postgres_container = postgres::Postgres::default()
            .with_tag("18.1-alpine")
            .start()
            .await
            .unwrap();

        let url = &format!("postgres://postgres:postgres@{}:{}/postgres", postgres_container.get_host().await.unwrap(), postgres_container.get_host_port_ipv4(5432).await.unwrap());

        let db_pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(url).await.unwrap();
        sqlx::migrate!("./migrations").run(&db_pool).await.unwrap();

        let argon2_hasher = providers::argon2_hasher::Argon2HasherProvider::new(8, 1, 1);
        let argon2_verifier = providers::argon2_verifier::Argon2VerifierProvider::new(8, 1, 1);

        let refresh_token_generator = providers::refresh_token_generator::RefreshTokenGeneratorProvider;
        let jwt_encoder = providers::jwt_encoder::JwtEncoderProvider;

        let user_repo = adapters::postgres::UserRepository::new(db_pool.clone());
        let container = di::Container::new(
            argon2_hasher,
            argon2_verifier,
            refresh_token_generator,
            jwt_encoder,
            user_repo.clone(),
            user_repo.clone(),
            user_repo.clone(),
            user_repo.clone(),
            user_repo,
        );

        // When
        let res = container.register_user_command.call(" \tuser0 \r\n  ".to_string(), "123123".to_string()).await;

        // Then
        let (kind, login) = sqlx::query_as::<_, (String, String)>("SELECT kind, login FROM user_credentials").fetch_one(&db_pool).await.unwrap();

        assert_eq!(kind, "username".to_string());
        assert_eq!(login, "user0".to_string());
    }
}
