#[cfg(feature = "authenticator")]
pub mod authenticator;
#[cfg(feature = "mfa_send_code")]
pub mod random_code_auth;

use std::{error::Error as StdError, future::Future, pin::Pin};

use actix_web::{http::StatusCode, HttpRequest, HttpResponse, ResponseError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// When TOTP is used, the secret needs to be stored somewhere
/// This is a repository trait that loads the secret for a given user
#[async_trait]
pub trait TotpSecretRepository<U> {
    async fn get_auth_secret(&self, user: &U) -> Result<String, GetTotpSecretError>;
}

#[derive(Error, Debug)]
#[error("Retrieving TOTP secret failed: {msg}")]
pub struct GetTotpSecretError {
    msg: String,
}

impl GetTotpSecretError {
    pub fn new(msg: &str) -> Self {
        Self {
            msg: msg.to_owned(),
        }
    }
}

impl Default for GetTotpSecretError {
    fn default() -> Self {
        Self {
            msg: "Cannot get secret".to_owned(),
        }
    }
}

// ToDo:
// Split Factor in two traits:
// one should be public, the other needs to be pub (crate) to hide is_condition_met() and generate_code()
pub trait Factor {
    /// Responsible for generating the code and sending it to the user. Currently its needed to retrieve the user from the request
    fn generate_code(
        &self,
        req: &HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), GenerateCodeError>>>>;
    /// Identifier for the Factor. Can be any String it only needs to be unique inside the app
    fn get_unique_id(&self) -> String;
    /// checks the code and returns empty Ok if code is correct, an Error otherwise
    fn check_code(
        &self,
        code: &str,
        req: &HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), CheckCodeError>>>>;
}

#[derive(Error, Debug)]
pub enum ConditionCheckError {
    #[error("can't check condition: {0}")]
    CantCheckCondition(String),
}

#[derive(Error, Debug)]
#[error("GenerateCodeError: {message}{}", cause.as_ref().map(|e| format!(", caused by: {e}")).unwrap_or_else(|| ".".to_owned()))]
pub struct GenerateCodeError {
    message: String,
    #[source]
    cause: Option<Box<dyn StdError>>,
}

impl ResponseError for GenerateCodeError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().body(self.message.clone())
    }
}

impl GenerateCodeError {
    pub fn new(msg: &str) -> Self {
        Self {
            message: msg.to_owned(),
            cause: None,
        }
    }

    pub fn new_with_cause(msg: &str, e: impl Into<Box<dyn StdError>>) -> Self {
        Self {
            message: msg.to_owned(),
            cause: Some(e.into()),
        }
    }
}

#[derive(Error, Debug)]
pub enum CheckCodeError {
    #[error("unknown server error: {0}")]
    UnknownError(String),
    #[error("Time is up: {0}")]
    TimeIsUp(String),
    #[error("invalid code")]
    InvalidCode,
    #[error("login rejected. unauthorized")]
    FinallyRejected,
}

#[derive(Serialize, Deserialize)]
struct MfaError {
    pub error: String,
    pub message: String,
    pub retry: bool,
}

impl MfaError {
    pub fn new(error: &str, message: &str, retry: bool) -> Self {
        Self {
            error: error.to_owned(),
            message: message.to_owned(),
            retry,
        }
    }
}

impl ResponseError for CheckCodeError {
    fn status_code(&self) -> StatusCode {
        match self {
            CheckCodeError::UnknownError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
    fn error_response(&self) -> HttpResponse {
        match self {
            CheckCodeError::UnknownError(m) => {
                HttpResponse::InternalServerError().json(MfaError::new("unknown_error", m, false))
            }
            CheckCodeError::TimeIsUp(m) => {
                HttpResponse::Unauthorized().json(MfaError::new("time_is_up", m, false))
            }
            CheckCodeError::InvalidCode => {
                HttpResponse::Unauthorized().json(MfaError::new("code_invalid", "", true))
            }
            CheckCodeError::FinallyRejected => HttpResponse::Unauthorized().json(MfaError::new(
                "login_finally_rejected",
                "",
                false,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GenerateCodeError, GetTotpSecretError};

    #[test]
    fn generate_error_should_print_cause_test() {
        let orig = GetTotpSecretError::new("orig error");
        let code_error = GenerateCodeError::new_with_cause("error", orig);

        assert_eq!(
            format!("{}", code_error),
            "GenerateCodeError: error, caused by: Retrieving TOTP secret failed: orig error"
        );
    }
}
