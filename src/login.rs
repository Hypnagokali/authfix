use std::future::Future;

use actix_web::{HttpRequest, HttpResponse, ResponseError};
use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;

/// Credentials comming from the login request
#[derive(Deserialize)]
pub struct LoginToken {
    pub email: String,
    pub password: String,
}
/// Loads the users by their credentials
/// # Example
/// ```no_run
/// use authfix::login::{LoginToken, LoadUserByCredentials, LoadUserError};
/// struct User {
///     name: String,
/// }
///
/// struct AuthenticationService;
///
/// impl LoadUserByCredentials for AuthenticationService {
///     type User = User;
///
///     async fn load_user(&self, login_token: &LoginToken) -> Result<Self::User, LoadUserError> {
///         // Currently Authfix does not provide hashing functions, you can use for example https://docs.rs/argon2/latest/argon2/
///         // This is a simplified example:
///         if login_token.email == "test@example.org" && login_token.password == "password" {
///             Ok(User {
///                 name: "Johnny".to_owned(),
///             })
///         } else {
///             Err(LoadUserError::LoginFailed)
///         }
///     }
/// }
/// ```
pub trait LoadUserByCredentials {
    type User;

    /// Gets a [LoginToken] and returns a user if credentials are correct a [LoadUserError] otherwise
    fn load_user(
        &self,
        login_token: &LoginToken,
    ) -> impl Future<Output = Result<Self::User, LoadUserError>>;
}

/// This trait is called, if the login was successful
///
/// # Example
/// ```no_run
/// use authfix::async_trait;
/// use actix_web::HttpRequest;
/// use authfix::login::HandlerError;
/// use authfix::login::SuccessHandler;
/// struct MySuccessHandler;
/// struct YourUser;
///
/// #[async_trait(?Send)]
/// impl SuccessHandler for MySuccessHandler {
///    type User = YourUser;
///    async fn on_success(&self, user: &Self::User, req: HttpRequest) -> Result<(), HandlerError> {
///         // do something meaningful
///         Ok(())
///     }
/// }
/// ```
#[async_trait(?Send)]
pub trait SuccessHandler {
    type User;

    async fn on_success(&self, user: &Self::User, req: HttpRequest) -> Result<(), HandlerError>;
}

/// This trait is called, if the login failed
///
/// # Example
/// ```no_run
/// use authfix::async_trait;
/// use actix_web::HttpRequest;
/// use authfix::login::HandlerError;
/// use authfix::login::FailureHandler;
/// struct MyFailureHandler;
///
/// #[async_trait(?Send)]
/// impl FailureHandler for MyFailureHandler {
///    async fn on_failure(&self, req: HttpRequest) -> Result<(), HandlerError> {
///         // do something meaningful
///         Ok(())
///     }
/// }
/// ```
#[async_trait(?Send)]
pub trait FailureHandler {
    async fn on_failure(&self, req: HttpRequest) -> Result<(), HandlerError>;
}

#[derive(Error, Debug)]
pub enum LoadUserError {
    #[error("Credentials wrong")]
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
