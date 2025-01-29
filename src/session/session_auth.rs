use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    time::SystemTime,
};

use actix_session::{Session, SessionExt, SessionInsertError};
use actix_web::{Error, FromRequest, HttpRequest};
use log::error;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{AuthState, AuthToken, AuthenticationProvider, UnauthorizedError};

const SESSION_KEY_USER: &str = "user";
const SESSION_KEY_NEED_MFA: &str = "needs_mfa";

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

#[derive(Deserialize, Serialize, Debug, Clone)]
struct SessionBasedLoginState {
    authenticated: bool,                  // if true, is fully authenticated for app
    factors_already_checked: Vec<String>, // IDs of checked factors
    needs_mfa_with_id: Option<String>,    // ID of next factor
    mfa_code: Option<String>,
    valid_unti: SystemTime, // after this timestamp LoginState is discarded
}

/// Extractor to set the user into the current session
///
/// It is needed to set the user after a successfull login.
/// Currently this crate does not provide traits and structs for the login process.
///
/// # Examples:
/// ```ignore
/// #[post("/login")]
/// async fn login(session: UserSession) -> impl Responder {
///     // here goes the login logic. If successfull:
///     let user = User { email: "jenny@example.org".to_owned(), name: "Jenny B.".to_owned() };
///
///     session.set_user(user).expect("User could not be set in session");
///     // if not succesfull return 401.
///     return HttpResponse::Ok();
/// }
/// ```
pub struct UserSession {
    session: Session,
}

impl UserSession {
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
}

impl FromRequest for UserSession {
    type Error = Error;
    type Future = Ready<Result<UserSession, Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let session = req.get_session();
        ready(Ok(UserSession::new(session)))
    }
}
