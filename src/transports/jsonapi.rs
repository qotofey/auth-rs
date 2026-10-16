//! Минимальный JSON:API 1.1 envelope для Axum.

use serde::Serialize;
use validator::{ValidationError, ValidationErrors, ValidationErrorsKind};

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

    pub fn with_source(mut self, pointer: impl Into<String>) -> Self {
        self.source = Some(ErrorSource {
            pointer: Some(pointer.into()),
        });
        self
    }

    fn from_field_error(
        field: impl AsRef<str>,
        pointer_prefix: &str,
        err: &ValidationError,
    ) -> Self {
        let field = field.as_ref();
        let detail = format_validation_error(field, err);
        Self::new("422", detail).with_source(format!("{}/{}", pointer_prefix, field))
    }
}

fn format_validation_error(field: &str, err: &ValidationError) -> String {
    match err.code.as_ref() {
        "length" => {
            let min = err.params.get("min").and_then(|v| v.as_u64()).unwrap_or(0);
            let max = err.params.get("max").and_then(|v| v.as_u64()).unwrap_or(0);
            // Определяем, к какому полю относится ошибка
            let key = if field == "username" {
                "validation.username_length"
            } else {
                "validation.password_length"
            };
            t!(key, min = min, max = max).to_string()
        }
        "blank" => t!("validation.username_blank").to_string(),
        other => format!("{}: {}", field, other),
    }
}

/// Собирает все ошибки валидации в список JSON:API-ошибок.
///
/// `pointer_prefix` — например, `"/data/attributes"`.
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
            ValidationErrorsKind::Field(_) => {
                // Уже обработано выше через field_errors()
            }
        }
    }

    result
}
