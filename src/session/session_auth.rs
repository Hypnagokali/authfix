use std::{
    future::{ready, Future, Ready}, marker::PhantomData, pin::Pin, rc::Rc, time::SystemTime
};

use actix_session::{
    storage::SessionStore, Session, SessionExt, SessionInsertError, SessionMiddleware,
};
use actix_web::{
    body::MessageBody, cookie::Key, dev::{ServiceFactory, ServiceRequest, ServiceResponse}, web::Data, App, Error, FromRequest, HttpMessage, HttpRequest
};
use log::error;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    config::Routes, login::LoadUserService, middleware::AuthMiddleware, multifactor::Factor, AuthState, AuthToken, AuthenticationProvider, UnauthorizedError
};

use super::handlers::{login_config, SessionLoginHandler};

const SESSION_KEY_USER: &str = "authfix__user";
const SESSION_KEY_NEED_MFA: &str = "authfix__needs_mfa";
const SESSION_KEY_LOGIN_VALID_UNTIL: &str = "authfix__login_valid_until";

/// Provider for session based authentication.
///
/// Uses [Actix-Session](https://docs.rs/actix-session/latest/actix_session/), so it must be set as middleware.
/// # Examples
/// See crate example.
#[derive(Clone)]
pub struct SessionAuthProvider<U> 
where
    U: DeserializeOwned + Clone + 'static
{
    additional_factor: Rc<Option<Box<dyn Factor>>>,
    phantom_data: PhantomData<U>
}

impl<U> SessionAuthProvider<U>
where
    U: DeserializeOwned + Clone + 'static {
    
    pub fn new(factor: Box<dyn Factor>) -> Self {
        Self {
            additional_factor: Rc::new(Some(factor)),
            phantom_data: PhantomData,
        }
    }
}

impl<U> Default for SessionAuthProvider<U> 
where
    U: DeserializeOwned + Clone + 'static 
{
    fn default() -> Self {
        Self { additional_factor: Rc::new(None), phantom_data: PhantomData }
    }
}

impl<U> AuthenticationProvider<U> for SessionAuthProvider<U>
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
            _ => {
                error!("No user in session. Cannot read {}", SESSION_KEY_USER);
                return Box::pin(ready(Err(UnauthorizedError::default())));
            }
        };

        let state = match s.get::<String>(SESSION_KEY_NEED_MFA) {
            Ok(Some(_mfa_id)) => AuthState::NeedsMfa,
            Ok(None) => AuthState::Authenticated,
            Err(_) => {
                error!("Cannot read '{}' value from session", SESSION_KEY_NEED_MFA);
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

    fn configure_provider(&self, extensions: &mut actix_web::dev::Extensions) {
        extensions.insert(Rc::clone(&self.additional_factor));
    }
        
    fn is_user_authorized_for_request(&self, req: ServiceRequest) -> Pin<Box<dyn Future<Output = Result<ServiceRequest, UnauthorizedError>>>> {
        let request_path = req.request().path().to_owned();
        let mut mfa_route_option = None;

        if let Some(routes) = req.app_data::<Data<Routes>>() {
            mfa_route_option = Some(routes.get_mfa().to_owned());
        }

        let auth_token_req = self.get_auth_token(req.request());
        Box::pin(async move {
            let token = auth_token_req.await?;

            let mut is_valid_mfa_req = false;
            if token.needs_mfa()
                && mfa_route_option.is_some()
                && mfa_route_option.unwrap() == request_path
            {
                is_valid_mfa_req = true;
            }

            if !is_valid_mfa_req && !token.is_authenticated() {
                return Err(UnauthorizedError::default());
            }

            {
                let mut extensions = req.extensions_mut();
                extensions.insert(token);
            }
            
            // is it really needed on each secured route? or only on /mfa and /login?

            Ok(req)
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
        matches!(self.session.get::<String>(SESSION_KEY_NEED_MFA), Ok(Some(_)))
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
            _=> true
        }
    }

    pub fn get_mfa_id(&self) -> Option<String> {
        self.session.get::<String>(SESSION_KEY_NEED_MFA).unwrap_or_default()
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

/// Factory for an [actix_web::App] with [actix_session::SessionMiddleware] as parameter
pub fn session_login_factory<
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: SessionStore + 'static,
>(
    login_handler: SessionLoginHandler<impl LoadUserService<User = U> + 'static, U>,
    auth_middleware: AuthMiddleware<impl AuthenticationProvider<U> + Clone + 'static, U>,
    session_middleware: SessionMiddleware<S>,
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
        .wrap(session_middleware)
}

/// Factory for an [actix_web::App] with a default [actix_session::SessionMiddleware]
pub fn default_session_login_factory<U: Serialize + DeserializeOwned + Clone + 'static>(
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
