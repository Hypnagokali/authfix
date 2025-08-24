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
//! use actix_web::{HttpResponse, HttpServer, Responder, cookie::Key, get};
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
    any::Any,
    cell::{Ref, RefCell},
    collections::HashMap,
    future::{ready, Future, Ready},
    ops::Deref,
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
    ///
    /// If the user is not logged in, it returns an [UnauthorizedError].
    /// It must not return a [LoginState] with [AuthState::Unauthenticated].
    fn try_get_auth_token(
        &self,
        service_request: &ServiceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<LoginState<U>, UnauthorizedError>>>>;

    /// This is a hook that is called before any request is handled.
    ///
    /// It should be used to analyze the request and return a response if needed.
    /// Its not intended for checking whether the user is authenticated (use `try_get_auth_token` for that).
    ///
    /// Returns a response that is sent before the request is handled.
    /// This is useful for example to redirect the user to root if he tried accessing the login page although he is already authenticated.
    #[allow(unused)]
    fn respond_before_request_handling(&self, req: &HttpRequest) -> Option<HttpResponse> {
        None
    }

    /// Invalidates the authentication after [AuthToken] has been flagged for logout.
    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>>;

    /// This method is used to check whether the request requires additional configuration.
    ///
    /// If it returns true, the [AuthenticationProvider::configure_request] method will be called.
    fn is_request_config_required(&self, req: &HttpRequest) -> bool;

    /// Configures the request if needed
    ///
    /// E.g.: the session authentication requires a user service to retrieve the user by credentials - this service is injected using this method.
    #[allow(unused)]
    fn configure_request(&self, extensions: &mut Extensions);
}

/// State of the login
///
/// If no authentications has been performed, the state is [AuthState::Unauthenticated].
/// If the user has been authenticated, but a challenge is still outstanding, the state is [AuthState::PendingChallenge].
/// If the user has been authenticated completely, the state is [AuthState::Authenticated].
/// Right after the user has been logged out, the state is [AuthState::Invalid] until the whole authentication has been invalidated.
pub struct LoginState<U>(Rc<RefCell<LoginStateInner<U>>>);

impl<U> Clone for LoginState<U> {
    fn clone(&self) -> Self {
        LoginState(Rc::clone(&self.0))
    }
}

struct LoginStateInner<U> {
    token: Option<AuthToken<U>>,
    map: HashMap<String, Box<dyn Any>>,
    state: AuthState,
}

impl<U> LoginState<U> {
    /// Returns the [AuthToken] if it exists in the [LoginState].
    pub fn token(&self) -> Option<AuthToken<U>> {
        self.0.borrow().token.as_ref().map(AuthToken::from_ref)
    }

    /// Can store information of any type about the login state.
    pub fn set<T: Any>(&self, key: &str, t: T) {
        self.0.borrow_mut().map.insert(key.to_owned(), Box::new(t));
    }

    // Retrieves a value from the [LoginState] by its key.
    pub fn get<T: Any>(&self, key: &str) -> Option<Ref<'_, T>> {
        Ref::filter_map(self.0.borrow(), |inner| {
            inner
                .map
                .get(key)
                .and_then(|state| state.downcast_ref::<T>())
        })
        .ok()
    }

    /// Returns the current state of the [LoginState].
    pub fn state(&self) -> Ref<'_, AuthState> {
        Ref::map(self.0.borrow(), |inner| &inner.state)
    }

    /// Sets an [AuthToken], which means, a user has been authenticated (maybe a challenge is still outstanding).
    ///
    /// # panics
    /// Panics if the [AuthState] is [AuthState::Unauthenticated]
    pub fn new(token: AuthToken<U>, auth_state: AuthState) -> Self {
        if auth_state == AuthState::Unauthenticated {
            panic!("Cannot create a LoginState with AuthToken and AuthState::Unauthenticated");
        }
        let inner = LoginStateInner {
            token: Some(AuthToken::from_ref(&token)),
            map: HashMap::new(),
            state: auth_state,
        };

        Self(Rc::new(RefCell::new(inner)))
    }

    /// Creates a new [LoginState] without an [AuthToken].
    ///
    /// [LoguinState] can be extracted anywhere and if it contains no user information
    /// it can be interpreted as 'anonymous user'.
    pub fn empty() -> Self {
        let inner = LoginStateInner {
            token: None,
            map: HashMap::new(),
            state: AuthState::Unauthenticated,
        };

        Self(Rc::new(RefCell::new(inner)))
    }

    pub fn from_ref(login_state: &LoginState<U>) -> Self {
        LoginState(Rc::clone(&login_state.0))
    }
}

impl<U: 'static> FromRequest for LoginState<U> {
    type Error = Error;

    type Future = Ready<Result<LoginState<U>, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let extensions = req.extensions();
        if let Some(login_state) = extensions.get::<LoginState<U>>() {
            ready(Ok(LoginState::from_ref(login_state)))
        } else {
            ready(Ok(LoginState::empty()))
        }
    }
}

/// Extractor that holds the authenticated user.
///
/// Injecting [AuthToken] into an unsecured (public) route results in a 500 error.
/// You can use [AuthTokenOption] for public routes.
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

/// Wrapper around Option<AuthToken<U>> for ergonomic extraction.
///
/// This can be used as an extractor in handlers where authentication is optional.
pub struct AuthTokenOption<U>(Option<AuthToken<U>>);

impl<U> Deref for AuthTokenOption<U> {
    type Target = Option<AuthToken<U>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<U> Clone for AuthToken<U> {
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

    pub fn is_marked_for_logout(&self) -> bool {
        self.inner_state.borrow().logout
    }

    /// Invalidates the AuthToken and initiate a logout.
    pub fn mark_for_logout(&self) {
        let mut inner = self.inner_state.borrow_mut();
        inner.logout = true;
    }

    pub(crate) fn new(user: U) -> Self {
        Self {
            inner_state: Rc::new(RefCell::new(AuthTokenInner { logout: false })),
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
pub enum AuthState {
    Unauthenticated,
    Authenticated,
    PendingChallenge,
    Invalid,
}

struct AuthTokenInner {
    // there will be more fields here, such as roles and permissions
    logout: bool,
}

impl<U> FromRequest for AuthTokenOption<U>
where
    U: 'static,
{
    type Error = Error;
    type Future = Ready<Result<AuthTokenOption<U>, Error>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        let token = AuthToken::<U>::from_request(req, payload).into_inner().ok();
        ready(Ok(AuthTokenOption(token)))
    }
}

impl<U> FromRequest for AuthToken<U>
where
    U: 'static,
{
    type Error = Error;
    type Future = Ready<Result<AuthToken<U>, Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let extensions = req.extensions();
        if let Some(login_state) = extensions.get::<LoginState<U>>() {
            if let Some(token) = login_state.token() {
                return ready(Ok(token));
            }
        }

        // If we reach this point, the AuthToken is not available in the request.
        // If this point is reached in secured routes, something must be wrong with the AuthenticationProvider or Middleware.
        ready(Err(actix_web::error::ErrorInternalServerError(
            "'AuthToken' cannot be used in public routes. Please use 'AuthTokenOption' instead.",
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

        ext.get::<LoginState<U>>().and_then(|state| state.token())
    }
}
