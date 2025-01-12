use std::{
    fmt::Debug,
    future::{ready, Future, Ready},
    ops::Deref, pin::Pin,
};

use actix_session::{Session, SessionExt, SessionInsertError};
use actix_web::{Error, FromRequest, HttpRequest};
use serde::{de::DeserializeOwned, Serialize};

use crate::{AuthenticationProvider, UnauthorizedError};

#[derive(Clone)]
pub struct SessionAuthProvider;

impl<U> AuthenticationProvider<U> for SessionAuthProvider
where
    U: DeserializeOwned + 'static,
{
    fn get_authenticated_user(&self, req: &actix_web::HttpRequest) -> Pin<Box<dyn Future<Output = Result<U, UnauthorizedError>>>> {
        let s = req.get_session().clone();

        let user = match s.get::<U>("user") {
            Ok(Some(user)) => user,
            _ => return Box::pin(ready(Err(UnauthorizedError::default()))),
        };

        Box::pin(ready(Ok(user)))
    }
    
    fn invalidate(&self, req: HttpRequest) -> Pin<Box<dyn Future<Output = ()>>> {
        let s =req.get_session();
        s.purge();

        Box::pin(async {})
    }

}

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

/// For Debugging purposes. May be removed in the future.
/// Example:
/// let ds = DebuggableSession(session);
/// println!("{?:}", ds);
pub struct DebuggableSession(pub Session);

impl Deref for DebuggableSession {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for DebuggableSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self.0.entries();
        let keys = entries.keys();

        let mut debug = f.debug_tuple("Session");
        for key in keys {
            match self.0.get::<String>(key) {
                Ok(Some(s)) => {
                    debug.field(&format!("{} => {}", key, s));
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }

        debug.finish()
    }
}
