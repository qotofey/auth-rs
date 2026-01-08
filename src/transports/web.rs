use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::{
    app::{
        commands::{
            AuthenticateUserDao, ChangePasswordDao, DeleteUserDao, RefreshSessionDao,
            RegisterUserDao, RestoreUserDao,
        },
        queries::{FindUserCredentialDao, FindUserSecretDao},
    },
    di::Container,
    errors::AppError,
    providers::{HashFuncProvider, HashVerifierProvider, IdProvider, TokenEncoderProvider},
};

pub struct Server<H, V, I, T, R, A, S, D, C>
where
    H: HashFuncProvider + Clone + Send + Sync + 'static,
    V: HashVerifierProvider + Clone + Send + Sync + 'static,
    I: IdProvider + Clone + Send + Sync + 'static,
    T: TokenEncoderProvider + Clone + Send + Sync + 'static,
    R: RegisterUserDao + Send + Sync + 'static,
    A: FindUserCredentialDao
        + FindUserSecretDao
        + AuthenticateUserDao
        + ChangePasswordDao
        + Clone
        + Send
        + Sync
        + 'static,
    S: RefreshSessionDao + Send + Sync + 'static,
    D: DeleteUserDao + Send + Sync + 'static,
    C: RestoreUserDao + Send + Sync + 'static,
{
    container: Arc<Container<H, V, I, T, R, A, S, D, C>>,
}

impl<H, V, I, T, R, A, S, D, C> Server<H, V, I, T, R, A, S, D, C>
where
    H: HashFuncProvider + Clone + Send + Sync + 'static,
    V: HashVerifierProvider + Clone + Send + Sync + 'static,
    I: IdProvider + Clone + Send + Sync + 'static,
    T: TokenEncoderProvider + Clone + Send + Sync + 'static,
    R: RegisterUserDao + Send + Sync + 'static,
    A: FindUserCredentialDao
        + FindUserSecretDao
        + AuthenticateUserDao
        + ChangePasswordDao
        + Clone
        + Send
        + Sync
        + 'static,
    S: RefreshSessionDao + Send + Sync + 'static,
    D: DeleteUserDao + Send + Sync + 'static,
    C: RestoreUserDao + Send + Sync + 'static,
{
    pub fn new(container: Arc<Container<H, V, I, T, R, A, S, D, C>>) -> Self {
        Self { container }
    }

    pub async fn run(self, port: u16) {
        let router = get_router(self.container);
        let addr = format!("0.0.0.0:{}", port);
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

        axum::serve(listener, router).await.unwrap();
    }
}

fn get_router<H, V, I, T, R, A, S, D, C>(
    container: Arc<Container<H, V, I, T, R, A, S, D, C>>,
) -> Router
where
    H: HashFuncProvider + Clone + Send + Sync + 'static,
    V: HashVerifierProvider + Clone + Send + Sync + 'static,
    I: IdProvider + Clone + Send + Sync + 'static,
    T: TokenEncoderProvider + Clone + Send + Sync + 'static,
    R: RegisterUserDao + Send + Sync + 'static,
    A: FindUserCredentialDao
        + FindUserSecretDao
        + AuthenticateUserDao
        + ChangePasswordDao
        + Clone
        + Send
        + Sync
        + 'static,
    S: RefreshSessionDao + Send + Sync + 'static,
    D: DeleteUserDao + Send + Sync + 'static,
    C: RestoreUserDao + Send + Sync + 'static,
{
    // TODO: реализовать все эти ручки
    Router::new()
        // .route("/api/v1/user", post(register_user)) // зарегистрировать пользователя
        .route("/api/v1/user", get(get_user)) // получить данные о пользователе
        // .route("/api/v1/user", patch(update_user)) // обновить пользователя
        // .route("/api/v1/user", delete(delete_user)) // удалить пользователя
        // .route("/api/v1/user/session", post(authenticate_user)) // создать сессию
        // .route("/api/v1/user/session", put(refresh_session)) // обновить сессию
        // .route("/api/v1/user/session", delete(destroy_session)) // закрыть сессию
        // .route("/api/v1/user/password", post(change_password)) // сменить пароль
        .with_state(container)
}

async fn get_user<H, V, I, T, R, A, S, D, C>(
    State(container): State<Arc<Container<H, V, I, T, R, A, S, D, C>>>,
) -> Result<Json<MetaResponse>, AppError>
where
    H: HashFuncProvider + Clone + Send + 'static,
    V: HashVerifierProvider + Clone + Send + 'static,
    I: IdProvider + Clone + Send + 'static,
    T: TokenEncoderProvider + Clone + 'static,
    R: RegisterUserDao + Send + 'static,
    A: FindUserCredentialDao
        + FindUserSecretDao
        + AuthenticateUserDao
        + ChangePasswordDao
        + Clone
        + Send
        + 'static,
    S: RefreshSessionDao + Send + 'static,
    D: DeleteUserDao + Send + 'static,
    C: RestoreUserDao + Send + 'static,
{
    Ok(Json(MetaResponse {
        version: "1.1".to_string(),
    }))
}

// async fn register_user<H, V, I, T, R, A, S, D, C>(
//     State(container): State<Arc<Container<H, V, I, T, R, A, S, D, C>>>,
//     Json(input): Json<RegisterUserRequest>,
// ) -> Result<Json<MetaResponse>>, AppError>
// where
//     H: HashFuncProvider + Clone + Send + Sync + 'static,
//     V: HashVerifierProvider + Clone + Send + Sync + 'static,
//     I: IdProvider + Clone + Send + Sync + 'static,
//     T: TokenEncoderProvider + Clone + Send + Sync + 'static,
//     R: RegisterUserDao + Send + Sync + 'static,
//     A: FindUserCredentialDao
//         + FindUserSecretDao
//         + AuthenticateUserDao
//         + ChangePasswordDao
//         + Clone
//         + Send
//         + Sync
//         + 'static,
//     S: RefreshSessionDao + Send + Sync + 'static,
//     D: DeleteUserDao + Send + Sync + 'static,
//     C: RestoreUserDao + Send + Sync + 'static,
// {
//     container
//         .register_user_command
//         .call(input.username, input.password)
//         .await
//         .map(|_| {
//             Json(MetaResponse {
//                 version: "1.1".to_string(),
//             })
//         })
// }

#[derive(Deserialize, Serialize)]
struct RegisterUserRequest {
    username: String,
    password: String,
}

#[derive(Deserialize, Serialize)]
struct MetaResponse {
    version: String,
}

#[derive(Debug)]
struct UpdateUserRequest {
    first_name: Option<Option<String>>,
    middle_name: Option<Option<String>>,
    last_name: Option<Option<String>>,
    birthdate: Option<Option<chrono::NaiveDate>>,
    gender: Option<Option<String>>,
}
