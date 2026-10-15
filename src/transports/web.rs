use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};

use crate::{di::AppContainer, errors::AppError};

pub struct Server {
    container: Arc<AppContainer>,
}

impl Server {
    pub fn new(container: Arc<AppContainer>) -> Self {
        Self { container }
    }

    pub async fn run(self, host: &str, port: u16) {
        let router = get_router(self.container);
        let addr = format!("{}:{}", host, port);
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

        axum::serve(listener, router).await.unwrap();
    }
}

fn get_router(container: Arc<AppContainer>) -> Router {
    Router::new()
        .route("/api/v1/user", post(register_user))
        .with_state(container)
}

async fn register_user(
    State(container): State<Arc<AppContainer>>,
    Json(input): Json<RegisterUserRequest>,
) -> Result<(StatusCode, Json<MetaResponse>), AppError> {
    container
        .register_user_command
        .call(input.username, input.password)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(MetaResponse {
            version: "1.1".to_string(),
        }),
    ))
}

#[derive(Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct MetaResponse {
    pub version: String,
}

// TODO: остальные ручки - по аналогии
//   GET    /api/v1/user           -> get_user
//   PATCH  /api/v1/user           -> update_user
//   DELETE /api/v1/user           -> delete_user
//   POST   /api/v1/user/session   -> authenticate_user
//   PUT    /api/v1/user/session   -> refresh_session
//   DELETE /api/v1/user/session   -> destroy_session
//   POST   /api/v1/user/password  -> change_password
