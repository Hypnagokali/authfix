//! # Authfix
//! Authfix makes it easy to add an authentication layer to Actix Web.
//!
//! It provides a middleware with which secured paths can be defined globally. It also provides an extractor ([AuthToken]) that can be used to
//! retrieve the currently logged in user.
//!
//! # Session Authentication
//! Currently, only session authentication is supported (OIDC is planned). It is designed to work with Single Page Applications, so it offers a JSON API for login, logout and mfa verification. Redirects
//! are then handled by the SPA.
//!
//! # Async traits
//! To use this library, the user has to implement certrain traits (e.g.: [LoadUserByCredentials](crate::login::LoadUserByCredentials)) and most of them
//! are async. To make the implementation easier and less verbose, these traits use the [async_trait](https://crates.io/crates/async-trait) crate. Unfortunately, this makes the docs a bit messy, so the 
//! original trait definition is provided in the trait's documentation.
//! 
//! *The library is still in the early stages and a work in progress so it can contain security flaws. Please report them or provide a PR: [Authfix Repo](https://github.com/Hypnagokali/authfix)*
//!
//! # Examples
//! ## Session based authentication 
//! The session based authentication is based on: [Actix Session](https://docs.rs/actix-session/latest/actix_session/). Authfix re-exports actix_session, you don't need it as a dependency.
//! ```no_run
//! use actix_web::{HttpResponse, HttpServer, Responder, cookie::Key, get};
//! use authfix::{
//!     AccountInfo, AuthToken,
//!     async_trait::async_trait,
//!     login::{LoadUserByCredentials, LoadUserError, LoginToken},
//!     session::app_builder::SessionLoginAppBuilder,
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
//! // LoadUsersByCredentials uses async_trait, so its needed when implementing the trait for AuthenticationService
//! // async_trait is re-exported by authfix.
//! #[async_trait]
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

pub mod middleware;
pub mod session;
pub mod errors;
pub mod login;
pub mod mfa;
pub mod multifactor;

// re-exports
pub use actix_session;
pub use async_trait;

/// Contains the information about the user account.
/// 
/// There is only a semantic difference between disabling a user or locking the account. 
/// In both cases, the user cannot log in.
/// `get_user_identification` is used for logging.
pub trait AccountInfo {
    fn get_user_identification(&self) -> String {
        "user_identification is not implemented".to_owned()
    }

    /// If user is disabled, login is not possible
    fn is_user_disabled(&self) -> bool {
        false
    }

    /// If account is locked, login is not possible
    fn is_account_locked(&self) -> bool {
        false
    }
}

/// This is a helper trait to bundle all necessary traits needed by a user
/// 
/// Simply derive Serialize, Deserialize
pub trait AuthUser: AccountInfo + Serialize + DeserializeOwned + Clone {}
impl<T> AuthUser for T where T: AccountInfo + Serialize + DeserializeOwned + Clone {}

/// Authentication lifecycle hooks
///
/// Its responsible for checking if the user is authorized and for invalidating the session/token/whatever after logout.
/// Additionally it is responsible for configuring special request (injecting services), such as for login or mfa.
pub trait AuthenticationProvider<U>
where
    U: AuthUser + 'static,
{
    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>>;

    /// Configures the request if needed
    #[allow(unused)]
    fn configure_request(&self, extensions: &mut Extensions) {
        // default implementation does not configure anything
    }

    fn get_auth_token(
        &self,
        service_request: &ServiceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthToken<U>, UnauthorizedError>>>>;
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
