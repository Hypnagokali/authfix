use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, ResponseError};
use core::fmt;
use serde::de::DeserializeOwned;
use std::{
    cell::{Ref, RefCell}, future::{ready, Ready}, rc::Rc
};

pub mod middleware;
pub mod session;

/// This trait is used to retrieve the logged in user.
/// If no user was found (e.g. in Actix-Session) it will return an Err.
///
/// Currently it is only implemented for actix-session:
///
/// [Impl for Actix-Session](crate::session::session_auth::GetUserFromSession)
pub trait AuthenticationProvider<U>
where
    U: DeserializeOwned,
{
    fn get_authenticated_user(&self, req: &HttpRequest) -> Result<U, NoAuthenticatedUserError>;
    fn invalidate(&self, req: HttpRequest);
}

pub struct NoAuthenticatedUserError;

pub struct AuthToken<U>
where
    U: DeserializeOwned,
{
    inner: Rc<RefCell<AuthTokenInner<U>>>,
}

impl<U> AuthToken<U>
where
    U: DeserializeOwned,
{
    pub fn get_authenticated_user(&self) -> Ref<U> {
        Ref::map(self.inner.borrow(), |inner| &inner.user)
    }

    pub fn is_valid(&self) -> bool {
        let inner = self.inner.borrow();
        inner.is_valid
    }

    pub fn invalidate(&self) {
        let mut inner = self.inner.as_ref().borrow_mut();
        inner.is_valid = false;
    }


    pub(crate) fn new(user: U) -> Self {
        Self {
            inner: Rc::new(RefCell::new(AuthTokenInner{ user, is_valid: true })),
        }
    }

    pub(crate) fn from_ref(token: &AuthToken<U>) -> Self {
        AuthToken {
            inner: Rc::clone(&token.inner),
        }
    }
}

struct AuthTokenInner<U>
where
    U: DeserializeOwned,
{
    user: U,
    is_valid: bool,
}

impl<U> FromRequest for AuthToken<U>
where
    U: DeserializeOwned + 'static,
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
