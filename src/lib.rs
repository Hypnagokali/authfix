use core::fmt;
use std::{future::{ready, Ready}, rc::Rc};
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, ResponseError};
use serde::de::DeserializeOwned;

pub mod middleware;
pub mod session;

/// This trait is used to retrieve the logged in user.
/// If no user was found (e.g. in Actix-Session) it will return an Err.
/// 
/// Currently it is only implemented for actix-session:
/// 
/// [Impl for Actix-Session](crate::session::session_auth::GetUserFromSession)
pub trait GetAuthenticatedUserFromRequest<U> 
where 
    U: DeserializeOwned {
    fn get_authenticated_user(&self, req: &HttpRequest) -> Result<U, ()>;
}

pub struct AuthToken<U> 
where
    U: DeserializeOwned 
{
    inner: Rc<AuthTokenInner<U>>       
}

impl<U> AuthToken<U>
where
    U: DeserializeOwned
{
    pub fn get_authenticated_user(&self) -> &U {
        &self.inner.user
    }

    pub (crate) fn new(user: U) -> Self {
        Self {
            inner: Rc::new(AuthTokenInner { user })
        }
    }

    pub (crate) fn from_ref(token: &AuthToken<U>) -> Self {
        AuthToken { inner: Rc::clone(&token.inner) }
    }
}

struct AuthTokenInner<U> 
where 
    U: DeserializeOwned
{
    user: U,
}


impl<U> FromRequest for AuthToken<U> 
where
    U: DeserializeOwned + 'static
{
    type Error = Error;
    type Future = Ready<Result<AuthToken<U>, Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let extensions = req.extensions();
        if let Some(token) = extensions.get::<AuthToken<U>>() {
            return ready(Ok(AuthToken::from_ref(token)));
        }

        ready(Err(UnauthorizedError::default().into()))
    }
}

#[derive(Debug)]
pub struct UnauthorizedError {
    message: String,
}

impl UnauthorizedError {

    pub fn default() -> Self {
        Self {
            message: "Not authorized".to_owned(),
        }
    }

    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
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

