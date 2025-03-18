use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    time::SystemTime,
};

use actix_session::{
    storage::SessionStore, Session, SessionExt, SessionInsertError, SessionMiddleware,
};
use actix_web::{
    body::MessageBody,
    cookie::Key,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    App, Error, FromRequest, HttpRequest,
};
use log::error;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    login::LoadUserService, middleware::AuthMiddleware, AuthState, AuthToken,
    AuthenticationProvider, UnauthorizedError,
};

use super::handlers::{login_config, SessionLoginHandler};

const SESSION_KEY_USER: &str = "user";
const SESSION_KEY_NEED_MFA: &str = "needs_mfa";
const SESSION_KEY_LOGIN_VALID_UNTIL: &str = "login_valid_until";

/// Provider for session based authentication.
///
/// Uses [Actix-Session](https://docs.rs/actix-session/latest/actix_session/), so it must be set as middleware.
/// # Examples
/// See crate example.
#[derive(Clone)]
pub struct SessionAuthProvider;

impl<U> AuthenticationProvider<U> for SessionAuthProvider
where
    U: DeserializeOwned + Clone + 'static,
{
    fn get_auth_token(
        &self,
        req: &actix_web::HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthToken<U>, UnauthorizedError>>>> {
        let s = req.get_session().clone();

        // ToDo: refactor: remove the matches here
        let user = match s.get::<U>(SESSION_KEY_USER) {
            Ok(Some(user)) => user,
            _ => return Box::pin(ready(Err(UnauthorizedError::default()))),
        };

        let state = match s.get::<String>(SESSION_KEY_NEED_MFA) {
            Ok(Some(_mfa_id)) => AuthState::NeedsMfa,
            Ok(None) => AuthState::Authenticated,
            Err(_) => {
                error!("Cannot read `need_mfa' value from session");
                return Box::pin(ready(Err(UnauthorizedError::default())));
            }
        };

        Box::pin(ready(Ok(AuthToken::new(user, state))))
    }

    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>> {
        let s = req.get_session();
        s.purge();

        Box::pin(async {})
    }
}

pub(crate) struct LoginSession {
    session: Session,
}

impl LoginSession {
    pub(crate) fn new(session: Session) -> Self {
        Self { session }
    }

    pub fn mfa_challenge_done(&self) {
        self.session.remove(SESSION_KEY_NEED_MFA);
    }

    pub fn needs_mfa(&self, mfa_id: &str) -> Result<(), SessionInsertError> {
        self.session.insert(SESSION_KEY_NEED_MFA, mfa_id)
    }

    pub fn set_user<U: Serialize>(&self, user: U) -> Result<(), SessionInsertError> {
        self.session.insert(SESSION_KEY_USER, user)
    }

    pub fn valid_until(&self, valid_until: SystemTime) -> Result<(), SessionInsertError> {
        self.session
            .insert(SESSION_KEY_LOGIN_VALID_UNTIL, valid_until)
    }

    pub fn no_longer_valid(&self) -> bool {
        match self
            .session
            .get::<SystemTime>(SESSION_KEY_LOGIN_VALID_UNTIL)
        {
            Ok(Some(valid_until)) => SystemTime::now() > valid_until,
            _ => true,
        }
    }

    pub fn reset(&self) {
        self.session.renew();
        self.session.clear();
    }

    pub fn destroy(&self) {
        self.session.purge();
    }
}

impl FromRequest for LoginSession {
    type Error = Error;
    type Future = Ready<Result<LoginSession, Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let session = req.get_session();
        ready(Ok(LoginSession::new(session)))
    }
}

/// Factory function to generate an actix_web::App instance with session login
pub fn session_login_factory<U: Serialize + DeserializeOwned + Clone + 'static>(
    login_handler: SessionLoginHandler<impl LoadUserService<User = U> + 'static, U>,
    auth_middleware: AuthMiddleware<impl AuthenticationProvider<U> + Clone + 'static, U>,
    session_store: impl SessionStore + 'static,
    key: Key,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Response = ServiceResponse<impl MessageBody>,
        Config = (),
        InitError = (),
        Error = Error,
    >,
> {
    App::new()
        .configure(login_config(login_handler))
        .wrap(auth_middleware)
        .wrap(SessionMiddleware::new(session_store, key))
}
