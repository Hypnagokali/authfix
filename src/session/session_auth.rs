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
    http::header::{ACCEPT, LOCATION},
    Error, FromRequest, HttpMessage, HttpRequest,
};
use log::error;

use crate::{
    errors::UnauthorizedRedirect, helper::redirect_response_builder, login::{FailureHandler, LoadUserByCredentials, SuccessHandler}, middleware::PathMatcher, multifactor::config::MfaConfig, session::{
        config::Routes, SessionUser, SESSION_KEY_LOGIN_VALID_UNTIL, SESSION_KEY_NEED_MFA,
        SESSION_KEY_USER,
    }, AuthState, AuthToken, AuthenticationProvider, LoginState, UnauthorizedError
};

type LoginStateResult<U> = Result<LoginState<U>, UnauthorizedError>;

/// Provider for session based authentication.
///
/// The provider is built on [Actix-Session](https://docs.rs/actix-session/latest/actix_session/). To use it, the `SessionMiddleware` must be set as middleware
/// after [AuthMiddleware](crate::middleware::AuthMiddleware), so that it is called first.
///
/// If you use the [SessionLoginAppBuilder](crate::session::app_builder::SessionLoginAppBuilder) this is all handled by the builder.
#[derive(Clone)]
pub struct SessionAuthProvider<U, L>
where
    U: SessionUser + 'static,
    L: LoadUserByCredentials<User = U> + 'static,
{
    mfa_config: Rc<MfaConfig<U>>,
    #[allow(dead_code)] // load_user will be registered as extension later
    load_user: Arc<L>,
    error_handler: Rc<Option<Box<dyn FailureHandler>>>,
    success_handler: Rc<Option<Box<dyn SuccessHandler<User = U>>>>,
    routes: Routes,
    redirect_flow: bool,
    phantom_data: PhantomData<U>,
}

impl<U, L> SessionAuthProvider<U, L>
where
    U: SessionUser + 'static,
    L: LoadUserByCredentials<User = U> + 'static,
{
    /// Creates a new SessionAuthProvider without mfa.
    ///
    /// Arc is used here because L could be a service that is shared across the application (e.g. UserService)
    pub fn new(load_user: Arc<L>, routes: Routes) -> Self {
        Self {
            mfa_config: Rc::new(MfaConfig::empty()),
            load_user,
            error_handler: Rc::new(None),
            success_handler: Rc::new(None),
            routes,
            phantom_data: PhantomData,
            redirect_flow: false,
        }
    }

    /// Creates a new SessionAuthProvider with mfa
    pub fn new_with_mfa(load_user: Arc<L>, mfa_config: MfaConfig<U>, routes: Routes) -> Self {
        Self {
            mfa_config: Rc::new(mfa_config),
            load_user,
            error_handler: Rc::new(None),
            success_handler: Rc::new(None),
            routes,
            phantom_data: PhantomData,
            redirect_flow: false,
        }
    }

    pub fn set_redirect_flow(&mut self, with_redirect: bool) {
        self.redirect_flow = with_redirect;
    }

    pub fn set_error_handler<F>(&mut self, error_handler: F)
    where
        F: FailureHandler + 'static,
    {
        self.error_handler = Rc::new(Some(Box::new(error_handler)));
    }

    pub(crate) fn set_error_handler_from_rc(
        &mut self,
        error_handler: Rc<Option<Box<dyn FailureHandler>>>,
    ) {
        self.error_handler = error_handler;
    }

    pub fn set_success_handler<S>(&mut self, success_handler: S)
    where
        S: SuccessHandler<User = U> + 'static,
    {
        self.success_handler = Rc::new(Some(Box::new(success_handler)));
    }

    pub(crate) fn set_success_handler_from_rc(
        &mut self,
        success_handler: Rc<Option<Box<dyn SuccessHandler<User = U>>>>,
    ) {
        self.success_handler = success_handler;
    }

    /// Creates a valid (not Unauthenticated) LoginState from the session or returns an UnauthorizedError.
    pub fn valid_login_state_from_session(&self, req: &actix_web::HttpRequest) -> LoginStateResult<U> {
        // use cached result if available
        if let Some(result) = req.extensions().get::<LoginStateResult<U>>() {
            return result.clone();
        }

        let session = req.get_session().clone();

        let user = match session.get::<U>(SESSION_KEY_USER) {
            Ok(Some(user)) => user,
            _ => {
                error!("No user in session. Cannot read {SESSION_KEY_USER}");
                return Err(build_error_cache_result(self, req));
            }
        };

        let state = match session.get::<String>(SESSION_KEY_NEED_MFA) {
            Ok(Some(_mfa_id)) => AuthState::PendingChallenge,
            Ok(None) => AuthState::Authenticated,
            Err(_) => {
                error!("Cannot read '{SESSION_KEY_NEED_MFA}' value from session");
                return Err(build_error_cache_result(self, req));
            }
        };

        let res = Ok(LoginState::new(AuthToken::new(user), state));


        req.extensions_mut().insert(res.clone());
        res
    }
}

impl<U, L> AuthenticationProvider<U> for SessionAuthProvider<U, L>
where
    U: SessionUser + 'static,
    L: LoadUserByCredentials<User = U> + 'static,
{
    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>> {
        let session = req.get_session();
        session.purge();

        Box::pin(ready(()))
    }

    fn respond_before_request_handling(
        &self,
        req: &HttpRequest,
    ) -> Option<actix_web::HttpResponse> {
        if req.method() != actix_web::http::Method::GET {
            return None;
        }

        let login_state = self.valid_login_state_from_session(req).ok();

        if let Some(login_state) = login_state {
            if *login_state.state() == AuthState::Authenticated
                && self.redirect_flow
                && (PathMatcher::are_equal(self.routes.login(), req.path())
                    || PathMatcher::are_equal(self.routes.mfa(), req.path()))
            {
                // redirect to "default" if already logged in
                return Some(
                    redirect_response_builder()
                        .insert_header((LOCATION, self.routes.default_redirect()))
                        .finish(),
                );
            }
        }

        None
    }

    fn is_request_config_required(&self, req: &HttpRequest) -> bool {
        PathMatcher::are_equal(self.routes.login(), req.path())
            || PathMatcher::are_equal(self.routes.mfa(), req.path())
    }

    fn configure_request(&self, extensions: &mut Extensions) {
        extensions.insert(Rc::clone(&self.mfa_config));
        extensions.insert(Arc::clone(&self.load_user));
        extensions.insert(Rc::clone(&self.error_handler));
        extensions.insert(Rc::clone(&self.success_handler));
    }

    fn try_get_auth_token(
        &self,
        req: &ServiceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<LoginState<U>, UnauthorizedError>>>> {
        let request_path = req.request().path().to_owned();

        let login_state_res = self.valid_login_state_from_session(req.request());
        let mfa_route = self.routes.mfa().to_owned();

        let error = build_error(self, req.request());
        Box::pin(async move {
            let login_state = login_state_res?;

            if *login_state.state() == AuthState::Authenticated
                || (*login_state.state() == AuthState::PendingChallenge && PathMatcher::are_equal(&mfa_route, &request_path))
            {
                Ok(login_state)
            } else {
                Err(error)
            }
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

    pub fn set_needs_mfa(&self, mfa_id: &str) -> Result<(), SessionInsertError> {
        self.session.insert(SESSION_KEY_NEED_MFA, mfa_id)
    }

    pub fn is_mfa_needed(&self) -> bool {
        matches!(
            self.session.get::<String>(SESSION_KEY_NEED_MFA),
            Ok(Some(_))
        )
    }

    pub fn set_user<U: SessionUser>(&self, user: &U) -> Result<(), SessionInsertError> {
        self.session.insert(SESSION_KEY_USER, user)
    }

    pub fn user<U: SessionUser>(&self) -> Option<U> {
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

    pub fn mfa_id(&self) -> Option<String> {
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

fn build_error_cache_result<U, L>(
    session_provider: &SessionAuthProvider<U, L>,
    req: &HttpRequest,
) -> UnauthorizedError
where
    U: SessionUser,
    L: LoadUserByCredentials<User = U>,
{
    let error = build_error(session_provider, req);
    req.extensions_mut()
        .insert(Err::<AuthToken<U>, UnauthorizedError>(error.clone()));
    error
}

fn build_error<U, L>(
    session_provider: &SessionAuthProvider<U, L>,
    req: &HttpRequest,
) -> UnauthorizedError
where
    U: SessionUser,
    L: LoadUserByCredentials<User = U>,
{
    if session_provider.redirect_flow {
        req.headers()
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.contains("text/html"))
            .map(|_| {
                let redirect_to_login = session_provider.routes.login();
                UnauthorizedError::new_redirect(UnauthorizedRedirect::new_with_redirect_uri(
                    redirect_to_login,
                    req.path(),
                    req.query_string(),
                ))
            })
            .unwrap_or_default()
    } else {
        UnauthorizedError::default()
    }
}
