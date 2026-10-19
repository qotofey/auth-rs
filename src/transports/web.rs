use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use serde::Deserialize;
use validator::Validate;

use crate::{
    app::NewUserProfile,
    di::AppContainer,
    errors::AppError,
    transports::jsonapi::{JsonApiRequest, JsonApiResponse, collect_validation_errors},
};

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
        .route("/api/v1/user/session", post(authenticate_user))
        .layer(middleware::from_fn(with_lang))
        .with_state(container)
}

async fn with_lang(request: Request, next: Next) -> Response {
    let lang = request
        .headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            if s.starts_with("ru") || s.contains(",ru") || s.contains(" ru") {
                "ru"
            } else {
                "en"
            }
        })
        .unwrap_or("ru");

    rust_i18n::set_locale(lang);
    next.run(request).await
}

async fn register_user(
    State(container): State<Arc<AppContainer>>,
    JsonApiRequest(input): JsonApiRequest<RegisterUserRequest>,
) -> Result<JsonApiResponse<serde_json::Value>, AppError> {
    if let Err(errors) = input.data.attributes.validate() {
        let api_errors = collect_validation_errors(&errors, "/data/attributes");
        return Err(AppError::Validation(api_errors));
    }

    let attrs = input.data.attributes;
    let profile = NewUserProfile {
        first_name: attrs.first_name,
        middle_name: attrs.middle_name,
        last_name: attrs.last_name,
        birthdate: attrs.birthdate,
        gender: attrs.gender,
    };

    container
        .register_user_command
        .call(attrs.username, attrs.password, profile)
        .await?;

    Ok(JsonApiResponse(
        StatusCode::CREATED,
        serde_json::json!({ "meta": { "version": "1.1" } }),
    ))
}

async fn authenticate_user(
    State(container): State<Arc<AppContainer>>,
    JsonApiRequest(input): JsonApiRequest<AuthenticateUserRequest>,
) -> Result<JsonApiResponse<serde_json::Value>, AppError> {
    if let Err(errors) = input.data.attributes.validate() {
        let api_errors = collect_validation_errors(&errors, "/data/attributes");
        return Err(AppError::Validation(api_errors));
    }

    let session = container
        .authenticate_user_command
        .call(input.data.attributes.login, input.data.attributes.password)
        .await?;

    Ok(JsonApiResponse(
        StatusCode::CREATED,
        serde_json::json!({
            "data": {
                "type": "sessions",
                "id": session.user_id.to_string()
            },
            "meta": {
                "accessToken": session.access_token,
                "refreshToken": session.refresh_token
            }
        }),
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
    #[validate(length(min = 2, max = 50), custom(function = "validate_non_blank"))]
    pub username: String,
    #[validate(length(min = 8, max = 100))]
    pub password: String,

    #[serde(default)]
    #[validate(length(max = 255))]
    pub first_name: Option<String>,
    #[serde(default)]
    #[validate(length(max = 255))]
    pub middle_name: Option<String>,
    #[serde(default)]
    #[validate(length(max = 255))]
    pub last_name: Option<String>,
    #[serde(default)]
    pub birthdate: Option<chrono::NaiveDate>,
    #[serde(default)]
    pub gender: Option<crate::app::Gender>,
}

#[derive(Deserialize, Validate)]
pub struct AuthenticateUserRequest {
    pub data: AuthenticateUserData,
}

#[derive(Deserialize, Validate)]
pub struct AuthenticateUserData {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub attributes: AuthenticateUserAttributes,
}

#[derive(Deserialize, Validate)]
pub struct AuthenticateUserAttributes {
    #[validate(custom(function = "validate_non_blank"))]
    pub login: String,
    #[validate(custom(function = "validate_non_blank"))]
    pub password: String,
}

fn validate_non_blank(value: &str) -> Result<(), validator::ValidationError> {
    if value.trim().is_empty() {
        return Err(validator::ValidationError::new("blank"));
    }
    Ok(())
}

// TODO: остальные ручки - по аналогии
//   GET    /api/v1/user           -> get_user
//   PATCH  /api/v1/user           -> update_user
//   DELETE /api/v1/user           -> delete_user
//   PUT    /api/v1/user/session   -> refresh_session
//   DELETE /api/v1/user/session   -> destroy_session
//   POST   /api/v1/user/password  -> change_password
