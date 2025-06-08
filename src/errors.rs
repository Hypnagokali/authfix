//! Error types for all kinds of authentication

use std::fmt;

use actix_web::{HttpResponse, ResponseError};

#[derive(Debug)]
pub struct UnauthorizedError {
    message: String,
}

impl UnauthorizedError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

impl Default for UnauthorizedError {
    fn default() -> Self {
        Self {
            message: "Not authorized".to_owned(),
        }
    }
}

impl fmt::Display for UnauthorizedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Debug unauth error")
    }
}

impl ResponseError for UnauthorizedError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::UNAUTHORIZED
    }

    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::Unauthorized().json(self.message.clone())
    }
}
