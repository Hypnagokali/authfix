use actix_web::{HttpRequest, HttpResponse, ResponseError};
use futures::future::LocalBoxFuture;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// The unencrypted credentials coming directly from the request
#[derive(Deserialize)]
pub struct LoginToken {
    pub username: String,
    pub password: String,
}

/// Trait that handles the loading of a user and executes a success and error handler
pub trait LoadUserService: Send + Sync {
    type User: DeserializeOwned + Serialize + Clone;

    /// Gets a [LoginToken] and returns a user if credentials are correct a [LoadUserError] otherwise
    fn load_user(
        &self,
        login_token: &LoginToken,
    ) -> LocalBoxFuture<'_, Result<Self::User, LoadUserError>>;

    /// Is called after the user has successfully completed authentication
    #[allow(unused)]
    fn on_success_handler(
        &self,
        req: &HttpRequest,
        user: &Self::User,
    ) -> LocalBoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(async { Ok(()) })
    }

    /// Is called when the login fails
    #[allow(unused)]
    fn on_error_handler(&self, req: &HttpRequest) -> LocalBoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Error, Debug)]
pub enum LoadUserError {
    #[error("Username or password wrong")]
    LoginFailed,
}

#[derive(Error, Debug)]
pub enum HandlerError {
    #[error("Unexpected error in a handler function: {0}")]
    Unexpected(String),
}

impl ResponseError for LoadUserError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Unauthorized().body(self.to_string())
    }
}

impl ResponseError for HandlerError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().body(self.to_string())
    }
}
