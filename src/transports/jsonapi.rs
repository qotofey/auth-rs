//! Минимальный JSON:API 1.1 envelope для Axum.

use axum::{
    Json,
    body::to_bytes,
    extract::{FromRequest, Request},
    http::{
        StatusCode,
        header::{CONTENT_TYPE, HeaderValue},
    },
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};
use validator::{ValidationError, ValidationErrors, ValidationErrorsKind};

use crate::errors::AppError;

const JSON_API_CONTENT_TYPE: &str = "application/vnd.api+json";
const MAX_BODY_BYTES: usize = 1024 * 1024;

pub struct JsonApiRequest<T>(pub T);

impl<T, S> FromRequest<S> for JsonApiRequest<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_lowercase)
            .unwrap_or_default();

        let base = content_type.split(';').next().unwrap_or("").trim();
        if base != JSON_API_CONTENT_TYPE {
            return Err(AppError::UnsupportedMediaType);
        }

        let bytes = to_bytes(req.into_body(), MAX_BODY_BYTES)
            .await
            .map_err(|e| AppError::InvalidInput(e.to_string()))?;

        let value: T = serde_json::from_slice(bytes.as_ref()).map_err(serde_error_to_app_error)?;

        Ok(JsonApiRequest(value))
    }
}

pub struct JsonApiResponse<T>(pub StatusCode, pub T);

impl<T: Serialize> IntoResponse for JsonApiResponse<T> {
    fn into_response(self) -> Response {
        (
            self.0,
            [(
                CONTENT_TYPE,
                HeaderValue::from_static(JSON_API_CONTENT_TYPE),
            )],
            Json(self.1),
        )
            .into_response()
    }
}

fn serde_error_to_app_error(e: serde_json::Error) -> AppError {
    if e.is_data() {
        let raw = e.to_string();
        if let Some(field) = extract_missing_field(&raw) {
            let detail = t!("serde.missing_field", field = field).to_string();
            let pointer = format!("/{}", to_camel_case(&field));
            AppError::Validation(vec![ErrorObject::new("422", detail).with_pointer(pointer)])
        } else {
            let detail = t!("serde.invalid_body").to_string();
            AppError::Validation(vec![ErrorObject::new("422", detail)])
        }
    } else {
        let detail = t!("serde.invalid_json").to_string();
        AppError::InvalidInput(detail)
    }
}

fn extract_missing_field(detail: &str) -> Option<String> {
    let rest = detail.strip_prefix("missing field `")?;
    let field = rest.split('`').next()?;
    Some(field.to_string())
}

#[derive(Debug, Serialize)]
pub struct ErrorDocument {
    pub errors: Vec<ErrorObject>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorObject {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<ErrorSource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

fn to_camel_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper_next = false;
    for ch in s.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

impl ErrorObject {
    pub fn new(status: &str, detail: impl Into<String>) -> Self {
        Self {
            status: status.to_string(),
            title: None,
            detail: Some(detail.into()),
            source: None,
        }
    }

    pub fn with_pointer(mut self, pointer: impl Into<String>) -> Self {
        let mut source = self.source.take().unwrap_or(ErrorSource {
            pointer: None,
            header: None,
        });
        source.pointer = Some(pointer.into());
        self.source = Some(source);
        self
    }

    pub fn with_header(mut self, header: impl Into<String>) -> Self {
        let mut source = self.source.take().unwrap_or(ErrorSource {
            pointer: None,
            header: None,
        });
        source.header = Some(header.into());
        self.source = Some(source);
        self
    }

    fn from_field_error(
        field: impl AsRef<str>,
        pointer_prefix: &str,
        err: &ValidationError,
    ) -> Self {
        let field = field.as_ref();
        let detail = format_validation_error(field, err);
        let pointer_field = to_camel_case(field);
        Self::new("422", detail).with_pointer(format!("{}/{}", pointer_prefix, pointer_field))
    }
}

fn format_validation_error(field: &str, err: &ValidationError) -> String {
    match err.code.as_ref() {
        "length" => {
            let min = err.params.get("min").and_then(|v| v.as_u64());
            let max = err.params.get("max").and_then(|v| v.as_u64());
            match (min, max) {
                (Some(min), Some(max)) if field == "username" => {
                    t!("validation.username_length", min = min, max = max).to_string()
                }
                (Some(min), Some(max)) if field == "password" => {
                    t!("validation.password_length", min = min, max = max).to_string()
                }
                (None, Some(max)) if field == "first_name" => {
                    t!("validation.first_name_max", max = max).to_string()
                }
                (None, Some(max)) if field == "middle_name" => {
                    t!("validation.middle_name_max", max = max).to_string()
                }
                (None, Some(max)) if field == "last_name" => {
                    t!("validation.last_name_max", max = max).to_string()
                }
                _ => format!("{}: invalid length", field),
            }
        }
        "blank" => match field {
            "username" => t!("validation.username_blank").to_string(),
            "login" => t!("validation.login_blank").to_string(),
            "password" => t!("validation.password_blank").to_string(),
            _ => format!("{}: must not be blank", field),
        },
        other => format!("{}: {}", field, other),
    }
}

pub fn collect_validation_errors(
    errors: &ValidationErrors,
    pointer_prefix: &str,
) -> Vec<ErrorObject> {
    let mut result = Vec::new();

    let mut fields: Vec<_> = errors.field_errors().into_iter().collect();
    fields.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (field, errs) in fields {
        for err in errs {
            result.push(ErrorObject::from_field_error(&field, pointer_prefix, err));
        }
    }

    for (_code, kind) in errors.errors() {
        match kind {
            ValidationErrorsKind::Struct(nested) => {
                result.extend(collect_validation_errors(nested, pointer_prefix));
            }
            ValidationErrorsKind::List(list) => {
                for nested in list.values() {
                    result.extend(collect_validation_errors(nested, pointer_prefix));
                }
            }
            ValidationErrorsKind::Field(_) => {}
        }
    }

    result
}
