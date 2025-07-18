//! # Authfix
//! Authfix makes it easy to add an authentication layer to an Actix Web app.
//!
//! It provides a middleware with which secured paths can be defined globally. It also provides an extractor ([AuthToken]) that can be used to
//! retrieve the currently logged in user.
//!
//! # Session Authentication
//! Currently, only session authentication is supported (OIDC is planned). It is designed to work with Single Page Applications, so it offers a JSON API for login, logout and mfa verification. Redirects
//! are then handled by the SPA.
//!
//! # Async traits
//! To use this library, the user has to implement certrain traits (e.g.: [MfaHandleMfaRequest](crate::multifactor::config::HandleMfaRequest)) and most of them
//! are async. To make the implementation easier and less verbose, these traits use the [async_trait](https://crates.io/crates/async-trait) crate. Unfortunately, this makes the docs a bit messy, so all this
//! traits provide an example.
//!
//! # Disclaimer
//! *The library is still in the early stages and a work in progress so it can contain security flaws. Please report them or provide a PR: [Authfix Repo](https://github.com/Hypnagokali/authfix)*
//!
//! # Examples
//! ## Example Repository
//! see: [authfix-examples](https://github.com/Hypnagokali/authfix-examples)
//! 
//! ## Session based authentication
//! The session based authentication is based on: [Actix Session](https://docs.rs/actix-session/latest/actix_session/). Authfix re-exports actix_session, you don't need it as a dependency.
//! ```no_run
//! use actix_web::{HttpResponse, HttpServer, Responder, cookie::Key, get};
//! use authfix::{
//!     AuthToken,
//!     async_trait,
//!     login::{LoadUserByCredentials, LoadUserError, LoginToken},
//!     session::{app_builder::SessionLoginAppBuilder, AccountInfo},
//! };
//! use serde::{Deserialize, Serialize};
//!
//! // A user intended for session authentication must derive or implement Clone, Serialize, and Deserialize.
//! #[derive(Clone, Serialize, Deserialize)]
//! struct User {
//!     name: String,
//! }
//!
//! // AccountInfo trait is used for disabling the user or to lock the account
//! // The user is enabled by default
//! impl AccountInfo for User {}
//!
//! // Struct that handles the authentication
//! struct AuthenticationService;
//!
//! impl LoadUserByCredentials for AuthenticationService {
//!     type User = User;
//!
//!     async fn load_user(&self, login_token: &LoginToken) -> Result<Self::User, LoadUserError> {
//!         // load user by email logic and check password
//!         // currently authfix does not provide hashing functions, you can use for example https://docs.rs/argon2/latest/argon2/
//!         if login_token.email == "test@example.org" && login_token.password == "password" {
//!             Ok(User {
//!                 name: "Johnny".to_owned(),
//!             })
//!         } else {
//!             Err(LoadUserError::LoginFailed)
//!         }
//!     }
//! }
//!
//! // You have access to the user via the AuthToken extractor in secured routes.
//! #[get("/secured")]
//! async fn secured(auth_token: AuthToken<User>) -> impl Responder {
//!     let user = auth_token.get_authenticated_user();
//!     HttpResponse::Ok().json(&*user)
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let key = Key::generate();
//!     HttpServer::new(move || {
//!         // SessionLoginAppBuilder is the simplest way to create an App instance configured with session based authentication
//!         // This config registers: /login, /logout and /login/mfa (even if mfa is not configured)
//!         SessionLoginAppBuilder::create(AuthenticationService, key.clone())
//!             .build()
//!             .service(secured)
//!     })
//!     .bind("127.0.0.1:7080")?
//!     .run()
//!     .await
//! }
//! ```

use actix_web::{
    dev::{Extensions, ServiceRequest},
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse,
};
use errors::UnauthorizedError;

use std::{
    cell::{Ref, RefCell},
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
};

pub mod errors;
pub mod helper;
pub mod login;
pub mod middleware;
pub mod multifactor;
pub mod factor_impl;
pub mod session;

// re-exports
pub use async_trait::async_trait;

/// Main component used by the middleware to handle the authentication mechanism
///
/// Its responsible for checking if the user is authorized and for invalidating the session/token/whatever after logout.
/// Additionally it is responsible for configuring special request (injecting services), such as for login or mfa.
/// If you want to implement your custom authentication mechanism, implement this trait and provide a way to store the user
pub trait AuthenticationProvider<U>
where
    U: 'static,
{
    /// Tries to retrieve the logged in user or fails with [UnauthorizedError]
    /// Returns a Future because its likely that this method can be used for calling an external service
    fn get_auth_token(
        &self,
        service_request: &ServiceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthToken<U>, UnauthorizedError>>>>;

    /// This is a hook that is called before the request is handled.
    /// It should be used to analyze the request and return a response if needed.
    /// Its not intended for checking whether the user is authenticated (use `get_auth_token` for that).
    ///
    /// Returns a response that is sent before the request is handled.
    /// This is useful for example to redirect the user to root if he tried accessing the login page although he is already authenticated.
    #[allow(unused)]
    fn response_before_request_handling(&self, req: &HttpRequest) -> Option<HttpResponse> {
        None
    }

    /// Invalidates the authentication after [AuthToken] has been set to [AuthState::Invalid].
    /// Returns a Future: same as for `get_auth_token`
    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>>;

    fn is_request_config_required(&self, req: &HttpRequest) -> bool;

    /// Configures the request if needed
    ///
    /// E.g.: the session authentication requires a user service to retrieve the user by credentials - this service is injected using this method.
    #[allow(unused)]
    fn configure_request(&self, extensions: &mut Extensions);
}

/// Extractor that holds the authenticated user
///
/// If you inject [AuthToken] in a route that is not secured (a public route), it will respond with 500.
///
/// # Example:
/// ```ignore
/// #[get("/secured-route")]
/// pub async fn secured_route(token: AuthToken<User>) -> impl Responder {
///     HttpResponse::Ok().body(format!(
///         "Request from user: {}",
///         token.get_authenticated_user().email
///     ))
/// }
/// ```
pub struct AuthToken<U> {
    inner: Rc<RefCell<AuthTokenInner<U>>>,
}

impl<U> Clone for AuthToken<U>
where
    U: 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<U> AuthToken<U> {
    /// Returns a reference to the logged in user.
    pub fn get_authenticated_user(&self) -> Ref<U> {
        Ref::map(self.inner.borrow(), |inner| &inner.user)
    }

    /// Invalidates the AuthToken. This triggers [AuthenticationProvider::invalidate]
    pub fn invalidate(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.auth_state = AuthState::Invalid;
    }

    pub(crate) fn is_mfa_needed(&self) -> bool {
        let inner: Ref<'_, AuthTokenInner<U>> = self.inner.borrow();
        inner.auth_state == AuthState::NeedsMfa
    }

    pub(crate) fn is_valid(&self) -> bool {
        let inner = self.inner.borrow();
        inner.auth_state != AuthState::Invalid
    }

    #[allow(unused)]
    pub(crate) fn is_authenticated(&self) -> bool {
        let inner = self.inner.borrow();
        inner.auth_state == AuthState::Authenticated
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

struct AuthTokenInner<U> {
    user: U,
    auth_state: AuthState,
}

impl<U> FromRequest for AuthToken<U>
where
    U: 'static,
{
    type Error = Error;
    type Future = Ready<Result<AuthToken<U>, Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let extensions = req.extensions();
        if let Some(token) = extensions.get::<AuthToken<U>>() {
            return ready(Ok(AuthToken::from_ref(token)));
        }

        ready(Err(actix_web::error::ErrorInternalServerError(
            "'AuthToken' cannot be used in public routes.",
        )))
    }
}

/// Extension to get the [AuthToken] from [HttpRequest]
/// ```no_run
/// use actix_web::HttpRequest;
/// use authfix::AuthTokenExt;
/// use serde::Deserialize;
/// #[derive(Deserialize)]
/// struct User {
///    email: String
/// }
///
/// fn some_function(req: actix_web::HttpRequest) -> bool {
///     req.get_auth_token::<User>().is_some()
/// }
/// ```
pub trait AuthTokenExt {
    fn get_auth_token<U: 'static>(&self) -> Option<AuthToken<U>>;
}

impl AuthTokenExt for HttpRequest {
    fn get_auth_token<U: 'static>(&self) -> Option<AuthToken<U>> {
        let ext = self.extensions();
        ext.get::<AuthToken<U>>()
            .map(|auth_token_ref| AuthToken::from_ref(auth_token_ref))
    }
}
