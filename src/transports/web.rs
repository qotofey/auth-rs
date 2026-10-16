use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{di::AppContainer, errors::AppError, transports::jsonapi::collect_validation_errors};

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
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    if let Err(errors) = input.data.attributes.validate() {
        let api_errors = collect_validation_errors(&errors, "/data/attributes");
        return Err(AppError::Validation(api_errors));
    }

    container
        .register_user_command
        .call(
            input.data.attributes.username,
            input.data.attributes.password,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "meta": {
                "version": "1.1"
            }
        })),
    ))
}

#[derive(Deserialize, Validate)]
pub struct RegisterUserRequest {
    pub data: RegisterUserData,
}

#[derive(Deserialize, Validate)]
pub struct RegisterUserData {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub attributes: RegisterUserAttributes,
}

#[derive(Deserialize, Validate)]
pub struct RegisterUserAttributes {
    #[validate(
        length(min = 2, max = 50),
        custom(function = "validate_non_blank_username")
    )]
    pub username: String,
    #[validate(length(min = 8, max = 100))]
    pub password: String,
}

fn validate_non_blank_username(username: &str) -> Result<(), validator::ValidationError> {
    if username.trim().is_empty() {
        return Err(validator::ValidationError::new("blank"));
    }
    Ok(())
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
