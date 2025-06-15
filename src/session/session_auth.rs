use std::{
    future::{ready, Future, Ready},
    marker::PhantomData,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    time::SystemTime,
};

use actix_session::{Session, SessionExt, SessionInsertError};
use actix_web::{
    dev::{Extensions, ServiceRequest},
    Error, FromRequest, HttpRequest,
};
use log::error;

use crate::{
    login::LoadUserByCredentials, mfa::MfaConfig, session::config::Routes, AuthState, AuthToken,
    AuthUser, AuthenticationProvider, UnauthorizedError,
};

const SESSION_KEY_USER: &str = "authfix__user";
const SESSION_KEY_NEED_MFA: &str = "authfix__needs_mfa";
const SESSION_KEY_LOGIN_VALID_UNTIL: &str = "authfix__login_valid_until";

/// Provider for session based authentication.
///
/// Uses [Actix-Session](https://docs.rs/actix-session/latest/actix_session/), so it must be set as middleware. If you use 
/// the [SessionLoginAppBuilder](crate::session::app_builder::SessionLoginAppBuilder) it is set by default.
#[derive(Clone)]
pub struct SessionAuthProvider<U, L>
where
    U: AuthUser + 'static,
    L: LoadUserByCredentials<User = U> + 'static,
{
    mfa_config: Rc<MfaConfig<U>>,
    #[allow(dead_code)] // load_user will be registered as extension later
    load_user: Arc<L>,
    routes: Arc<Routes>,
    phantom_data: PhantomData<U>,
}

impl<U, L> SessionAuthProvider<U, L>
where
    U: AuthUser + 'static,
    L: LoadUserByCredentials<User = U> + 'static,
{
    /// Creates a new SessionAuthProvider without mfa.
    ///
    /// Arc is used here because L could be a service that is shared across the application (e.g. UserService)
    pub fn new(load_user: Arc<L>, routes: Arc<Routes>) -> Self {
        Self {
            mfa_config: Rc::new(MfaConfig::empty()),
            load_user,
            routes,
            phantom_data: PhantomData,
        }
    }

    /// Creates a new SessionAuthProvider with mfa
    pub fn new_with_mfa(load_user: Arc<L>, mfa_config: MfaConfig<U>, routes: Arc<Routes>) -> Self {
        Self {
            mfa_config: Rc::new(mfa_config),
            load_user,
            routes,
            phantom_data: PhantomData,
        }
    }

    pub fn get_auth_token_from_session(
        &self,
        req: &actix_web::HttpRequest,
    ) -> Result<AuthToken<U>, UnauthorizedError> {
        let session = req.get_session().clone();

        let user = match session.get::<U>(SESSION_KEY_USER) {
            Ok(Some(user)) => user,
            _ => {
                error!("No user in session. Cannot read {}", SESSION_KEY_USER);
                return Err(UnauthorizedError::default());
            }
        };

        let state = match session.get::<String>(SESSION_KEY_NEED_MFA) {
            Ok(Some(_mfa_id)) => AuthState::NeedsMfa,
            Ok(None) => AuthState::Authenticated,
            Err(_) => {
                error!("Cannot read '{}' value from session", SESSION_KEY_NEED_MFA);
                return Err(UnauthorizedError::default());
            }
        };

        Ok(AuthToken::new(user, state))
    }
}

impl<U, L> AuthenticationProvider<U> for SessionAuthProvider<U, L>
where
    U: AuthUser + 'static,
    L: LoadUserByCredentials<User = U> + 'static,
{
    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>> {
        let session = req.get_session();
        session.purge();

        Box::pin(ready(()))
    }

    fn is_request_config_required(&self, req: &HttpRequest) -> bool {
        // Maybe the pathmatcher should be used for comparing paths (see #131)
        self.routes.get_login() == req.path() || self.routes.get_mfa() == req.path()
    }

    fn configure_request(&self, extensions: &mut Extensions) {
        extensions.insert(Rc::clone(&self.mfa_config));
        extensions.insert(Arc::clone(&self.load_user));
    }

    fn get_auth_token(
        &self,
        req: &ServiceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthToken<U>, UnauthorizedError>>>> {
        let request_path = req.request().path().to_owned();

        let auth_token_req = self.get_auth_token_from_session(req.request());
        let mfa_route = self.routes.get_mfa().to_owned();

        Box::pin(async move {
            let token = auth_token_req?;

            let mut is_valid_mfa_req = false;
            if token.needs_mfa()
                && mfa_route == request_path
            {
                is_valid_mfa_req = true;
            }

            if !is_valid_mfa_req && !token.is_authenticated() {
                return Err(UnauthorizedError::default());
            }

            Ok(token)
        })
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

    pub fn is_mfa_needed(&self) -> bool {
        matches!(
            self.session.get::<String>(SESSION_KEY_NEED_MFA),
            Ok(Some(_))
        )
    }

    pub fn set_user<U: AuthUser>(&self, user: U) -> Result<(), SessionInsertError> {
        self.session.insert(SESSION_KEY_USER, user)
    }

    pub fn get_user<U: AuthUser>(&self) -> Option<U> {
        match self.session.get::<U>(SESSION_KEY_USER) {
            Ok(Some(user)) => Some(user),
            _ => None,
        }
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

    pub fn get_mfa_id(&self) -> Option<String> {
        self.session
            .get::<String>(SESSION_KEY_NEED_MFA)
            .unwrap_or_default()
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
