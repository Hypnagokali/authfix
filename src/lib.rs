//! Authfix provides a quick and easy way to add authentication to your [Actix Web](https://docs.rs/actix-web/latest/actix_web/index.html) app.
//!
//! The [AuthToken] extractor enables straightforward access to the authenticated user in secured handlers.
//!
//! # Quick start
//! For a quick start, use the working examples from [authfix-examples](https://github.com/Hypnagokali/authfix-examples)
//!
//! # Session Authentication
//! Currently, only session authentication is supported (OIDC support is planned). This implementation is built on
//! [actix-session](https://docs.rs/actix-session/latest/actix_session/index.html). Authfix re-exports actix-session for this reason.
//!
//! The session authentication flow can be configured in two modes.
//!
//! 1. API based (default)
//!     - It is designed to work with Single Page Applications, so it offers a JSON API for login, logout and mfa verification. Redirects
//!       are then handled by the SPA.
//! 2. Redirect based
//!     - Instead of returning 401 for unauthorized requests, it redirects the user to the login page. The login flow is completely handled by the browser.
//!       You just have to define the login, mfa and logout pages. The redirects are going to the same routes as defined in [Routes](crate::session::config::Routes).
//!       To activate this mode, set `with_redirect_flow()` in [SessionLoginAppBuilder](crate::session::app_builder::SessionLoginAppBuilder).
//!
//! # Async traits
//! To use this library, it is necessary to implement certrain traits (e.g.: [LoadUserByCredentials](crate::login::LoadUserByCredentials)).
//! Wherever possible, native async syntax is supported.
//!
//! However, some of the traits must be `dyn compatible`, so the [async_trait](https://crates.io/crates/async-trait) crate
//! is used for those (e.g. for [MfaHandleMfaRequest](crate::multifactor::config::HandleMfaRequest)).
//!
//! Authfix re-exports the [authfix::async_trait](crate::async_trait) macro.
//!
//! # Examples
//! ## Session based authentication
//! ```no_run
//! use actix_web::{HttpResponse, HttpServer, Responder, cookie::Key, get};
//! use authfix::{
//!     AuthToken,
//!     login::{LoadUserByCredentials, LoadUserError, LoginToken},
//!     session::{AccountInfo, app_builder::SessionLoginAppBuilder},
//! };
//! use serde::{Deserialize, Serialize};
//!
//! // A user intended for session authentication must derive Serialize, and Deserialize.
//! #[derive(Serialize, Deserialize)]
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
//!     let user = auth_token.authenticated_user();
//!     HttpResponse::Ok().json(&*user)
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let key = Key::generate();
//!     HttpServer::new(move || {
//!         // SessionLoginAppBuilder is the simplest way to create an App instance configured with session based authentication
//!         // This default config registers handlers for: /login, /logout and /login/mfa.
//!         SessionLoginAppBuilder::create(AuthenticationService, key.clone())
//!             .build()
//!             .service(secured)
//!     })
//!     .bind("127.0.0.1:7080")?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ## Configure the session
//! ```no_run
//! use actix_web::{HttpResponse, HttpServer, Responder, cookie::Key, get, middleware::Logger};
//! use authfix::{
//!     AuthToken,
//!     login::{LoadUserByCredentials, LoadUserError, LoginToken},
//!     session::{
//!         AccountInfo,
//!         actix_session::{
//!             SessionMiddleware,
//!             config::{PersistentSession, SessionLifecycle},
//!             storage::CookieSessionStore,
//!         },
//!         app_builder::SessionLoginAppBuilder,
//!     },
//! };
//! use serde::{Deserialize, Serialize};
//!
//! // A user intended for session authentication must derive or implement Serialize, and Deserialize.
//! #[derive(Serialize, Deserialize)]
//! struct User {
//!     name: String,
//! }
//!
//! impl AccountInfo for User {}
//!
//! // Struct that handles the authentication
//! struct AuthenticationService;
//!
//! // LoadUsersByCredentials uses async_trait, so its needed when implementing the trait for AuthenticationService
//! // async_trait is re-exported by authfix.
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
//!     let user = auth_token.authenticated_user();
//!     HttpResponse::Ok().json(&*user)
//! }
//!
//! pub fn session_config(key: Key) -> SessionMiddleware<CookieSessionStore> {
//!     let persistent_session = PersistentSession::default();
//!     let lc = SessionLifecycle::PersistentSession(persistent_session);
//!     SessionMiddleware::builder(CookieSessionStore::default(), key)
//!         .cookie_name("sessionId".to_string())
//!         .cookie_http_only(true)
//!         .cookie_same_site(actix_web::cookie::SameSite::Strict)
//!         .cookie_secure(false)
//!         .session_lifecycle(lc)
//!         .build()
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let key = Key::generate();
//!     HttpServer::new(move || {
//!         // SessionLoginAppBuilder is the simplest way to create an App instance configured with session based authentication
//!         SessionLoginAppBuilder::create_with_session_middleware(
//!             AuthenticationService,
//!             session_config(key.clone()),
//!         )
//!         // create App instance with build()
//!         .build()
//!         .wrap(Logger::default())
//!         .service(secured)
//!     })
//!     .bind("127.0.0.1:7080")?
//!     .run()
//!     .await
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use actix_web::{
    dev::{Extensions, ServiceRequest},
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse,
};
use errors::UnauthorizedError;

use std::{
    cell::RefCell,
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
    sync::Arc,
};

pub mod errors;
mod helper;
pub mod login;
pub mod middleware;
pub mod multifactor;
pub mod session;

// re-exports
/// Re-exported `async_trait` macro for use in trait definitions.
pub use async_trait::async_trait;

/// Main component used by the middleware to handle the actual authentication mechanism
///
/// Its main responsibility is to attempt retrieving the logged-in user or respond with an [UnauthorizedError].
/// Additionally it is responsible for configuring special request (e.g. injecting services), such as for login or mfa.
///
/// Currently only [SessionAuthProvider](crate::session::session_auth::SessionAuthProvider) implements [AuthenticationProvider].
pub trait AuthenticationProvider<U>
where
    U: 'static,
{
    /// Tries to retrieve the logged in user or fails with [UnauthorizedError]
    fn try_get_auth_token(
        &self,
        service_request: &ServiceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthToken<U>, UnauthorizedError>>>>;

    /// This is a hook that is called before any request is handled.
    /// It should be used to analyze the request and return a response if needed.
    /// Its not intended for checking whether the user is authenticated (use `try_get_auth_token` for that).
    ///
    /// Returns a response that is sent before the request is handled.
    /// This is useful for example to redirect the user to root if he tried accessing the login page although he is already authenticated.
    #[allow(unused)]
    fn respond_before_request_handling(&self, req: &HttpRequest) -> Option<HttpResponse> {
        None
    }

    /// Invalidates the authentication after [AuthToken] has been set to invalid.
    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>>;

    fn is_request_config_required(&self, req: &HttpRequest) -> bool;

    /// Configures the request if needed
    ///
    /// E.g.: the session authentication requires a user service to retrieve the user by credentials - this service is injected using this method.
    #[allow(unused)]
    fn configure_request(&self, extensions: &mut Extensions);
}

/// Extractor that holds the authenticated user.
///
/// Injecting [AuthToken] into an unsecured (public) route currently results in a 500 error.
///
/// # Example
/// ```no_run
/// use actix_web::{get, HttpResponse, Responder};
/// use authfix::AuthToken;
///
/// struct User {
///    email: String,
/// }
///
/// #[get("/secured-route")]
/// async fn secured_route(token: AuthToken<User>) -> impl Responder {
///     HttpResponse::Ok().body(format!(
///         "Request from user: {}",
///         token.authenticated_user().email
///     ))
/// }
/// ```
pub struct AuthToken<U> {
    inner_state: Rc<RefCell<AuthTokenInner>>,
    user: Arc<U>,
}

impl<U> Clone for AuthToken<U>
where
    U: 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner_state: Rc::clone(&self.inner_state),
            user: Arc::clone(&self.user),
        }
    }
}

impl<U> AuthToken<U> {
    /// Returns a reference to the logged in user.
    pub fn authenticated_user(&self) -> Arc<U> {
        Arc::clone(&self.user)
    }

    /// Invalidates the AuthToken. This triggers [AuthenticationProvider::invalidate]
    pub fn invalidate(&self) {
        let mut inner = self.inner_state.borrow_mut();
        inner.auth_state = AuthState::Invalid;
    }

    pub(crate) fn is_mfa_needed(&self) -> bool {
        let inner = self.inner_state.borrow();
        inner.auth_state == AuthState::NeedsMfa
    }

    pub(crate) fn is_valid(&self) -> bool {
        let inner = self.inner_state.borrow();
        inner.auth_state != AuthState::Invalid
    }

    #[allow(unused)]
    pub(crate) fn is_authenticated(&self) -> bool {
        let inner = self.inner_state.borrow();
        inner.auth_state == AuthState::Authenticated
    }

    pub(crate) fn new(user: U, auth_state: AuthState) -> Self {
        Self {
            inner_state: Rc::new(RefCell::new(AuthTokenInner { auth_state })),
            user: Arc::new(user),
        }
    }

    pub(crate) fn from_ref(token: &AuthToken<U>) -> Self {
        AuthToken {
            inner_state: Rc::clone(&token.inner_state),
            user: Arc::clone(&token.user),
        }
    }
}

#[derive(PartialEq, Debug)]
enum AuthState {
    Authenticated,
    NeedsMfa,
    Invalid,
}

struct AuthTokenInner {
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
///     req.auth_token::<User>().is_some()
/// }
/// ```
pub trait AuthTokenExt {
    fn auth_token<U: 'static>(&self) -> Option<AuthToken<U>>;
}

impl AuthTokenExt for HttpRequest {
    fn auth_token<U: 'static>(&self) -> Option<AuthToken<U>> {
        let ext = self.extensions();
        ext.get::<AuthToken<U>>()
            .map(|auth_token_ref| AuthToken::from_ref(auth_token_ref))
    }
}
