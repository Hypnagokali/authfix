use std::{
    future::{ready, Future, Ready},
    pin::Pin,
};

use actix_session::{Session, SessionExt, SessionInsertError};
use actix_web::{Error, FromRequest, HttpRequest};
use serde::{de::DeserializeOwned, Serialize};

use crate::{AuthenticationProvider, UnauthorizedError};

/// Provider for session based authentication.
///
/// Uses [Actix-Session](https://docs.rs/actix-session/latest/actix_session/), so it must be set as middleware.
/// # Examples
/// See crate example.
#[derive(Clone)]
pub struct SessionAuthProvider;

impl<U> AuthenticationProvider<U> for SessionAuthProvider
where
    U: DeserializeOwned + 'static,
{
    fn get_authenticated_user(
        &self,
        req: &actix_web::HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<U, UnauthorizedError>>>> {
        let s = req.get_session().clone();

        let user = match s.get::<U>("user") {
            Ok(Some(user)) => user,
            _ => return Box::pin(ready(Err(UnauthorizedError::default()))),
        };

        Box::pin(ready(Ok(user)))
    }

    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>> {
        let s = req.get_session();
        s.purge();

        Box::pin(async {})
    }
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

    pub fn set_user<U: Serialize>(&self, user: U) -> Result<(), SessionInsertError> {
        match self.session.insert("user", user) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }

        self.session.remove("ttl");

        Ok(())
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
