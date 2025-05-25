//! Authentication middleware for Actix Web.
//!
//! *Warning: this library has been created for the purpose to setup a quick authentication for private projects and to get the authenticated in user in `Actix Web` handlers easily.
//! It has hardly been tested so far and might contain serious security issues. So its currently not an option for using in production. Help is always welcome :)*
//!
//! `auth-middleware-for-actix-web` makes it easy to configure authentication in Actix Web.
//! It provides a middleware with which secured paths can be defined globally and it provides an extractor [AuthToken] that can be used, to
//! retrieve the currently logged in user.
//!
//! # Examples
//! ## For session based authentication ([Actix Session](https://docs.rs/actix-session/latest/actix_session/)).
//! *New example is needed*

use actix_web::{
    dev::{Extensions, ServiceRequest},
    Error, FromRequest, HttpMessage, HttpRequest,
};
use errors::UnauthorizedError;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    cell::{Ref, RefCell},
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
};

pub mod config;
pub mod errors;
pub mod login;
pub mod mfa;
pub mod middleware;
pub mod multifactor;
pub mod session;

// re-exports
pub use actix_session;
pub use async_trait;

pub trait AccountInfo {
    fn get_user_identification(&self) -> String {
        "user_identification is not implemented".to_owned()
    }

    fn is_user_disabled(&self) -> bool {
        false
    }
    fn is_account_locked(&self) -> bool {
        false
    }
}

pub trait AuthUser: AccountInfo + Serialize + DeserializeOwned + Clone {}
impl<T> AuthUser for T where T: AccountInfo + Serialize + DeserializeOwned + Clone {}

/// This trait is used to retrieve the logged in user.
/// If no user was found (e.g. in Actix-Session) it will return an Err.
///
/// Currently it is only implemented for actix-session:
/// [SessionAuthProvider](crate::session::session_auth::SessionAuthProvider)
pub trait AuthenticationProvider<U>
where
    U: AuthUser + 'static,
{
    fn get_auth_token(
        &self,
        req: &HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthToken<U>, UnauthorizedError>>>>;
    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>>;

    /// Configure the authentication provider. Prepares login related request.
    #[allow(unused)]
    fn configure_provider(&self, extensions: &mut Extensions) {
        // default implementation does not configure anything
    }

    fn is_user_authorized_for_request(
        &self,
        service_request: ServiceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceRequest, UnauthorizedError>>>>;
}

/// Extractor that holds the authenticated user
///
/// [`AuthToken`] will be used to handle the logged in user within secured routes. If you inject it a route that is not secured,
/// an 401 [UnauthorizedError] will be returned to the client.
/// Retrieve the current user:
/// ```ignore
/// #[get("/secured-route")]
/// pub async fn secured_route(token: AuthToken<User>) -> impl Responder {
///     HttpResponse::Ok().body(format!(
///         "Request from user: {}",
///         token.get_authenticated_user().email
///     ))
/// }
/// ```
#[derive(Clone)]
pub struct AuthToken<U>
where
    U: AuthUser,
{
    inner: Rc<RefCell<AuthTokenInner<U>>>,
}

impl<U> AuthToken<U>
where
    U: AuthUser,
{
    pub fn get_authenticated_user(&self) -> Ref<U> {
        Ref::map(self.inner.borrow(), |inner| &inner.user)
    }

    pub(crate) fn needs_mfa(&self) -> bool {
        let inner: Ref<'_, AuthTokenInner<U>> = self.inner.borrow();
        inner.auth_state == AuthState::NeedsMfa
    }

    pub(crate) fn is_valid(&self) -> bool {
        let inner = self.inner.borrow();
        inner.auth_state != AuthState::Invalid
    }

    pub(crate) fn is_authenticated(&self) -> bool {
        let inner = self.inner.borrow();
        inner.auth_state == AuthState::Authenticated
    }

    pub fn invalidate(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.auth_state = AuthState::Invalid;
    }

    pub(crate) fn new(user: U, auth_state: AuthState) -> Self {
        Self {
            inner: Rc::new(RefCell::new(AuthTokenInner { user, auth_state })),
        }
    }

    pub(crate) fn from_ref(token: &AuthToken<U>) -> Self {
        AuthToken {
            inner: Rc::clone(&token.inner),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum AuthState {
    Authenticated,
    NeedsMfa,
    Invalid,
}

struct AuthTokenInner<U>
where
    U: AuthUser,
{
    user: U,
    auth_state: AuthState,
}

impl<U> FromRequest for AuthToken<U>
where
    U: AuthUser + 'static,
{
    type Error = Error;
    type Future = Ready<Result<AuthToken<U>, Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let extensions = req.extensions();
        if let Some(token) = extensions.get::<AuthToken<U>>() {
            return ready(Ok(AuthToken::from_ref(token)));
        }

        // ToDo: not a good error, needs 500
        ready(Err(UnauthorizedError::default().into()))
    }
}

pub trait AuthTokenExt {
    fn get_auth_token<U: AuthUser + 'static>(&self) -> Option<AuthToken<U>>;
}

impl AuthTokenExt for HttpRequest {
    fn get_auth_token<U: AuthUser + 'static>(&self) -> Option<AuthToken<U>> {
        let ext = self.extensions();
        ext.get::<AuthToken<U>>()
            .map(|auth_token_ref| AuthToken::from_ref(auth_token_ref))
    }
}
