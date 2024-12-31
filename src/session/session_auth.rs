use std::{fmt::Debug, future::{ready, Ready}, ops::Deref, time::{Duration, SystemTime}};

use actix_session::{Session, SessionExt};
use actix_web::{Error, FromRequest, HttpRequest};
use serde::{de::DeserializeOwned, Serialize};

use crate::GetAuthenticatedUserFromRequest;

#[derive(Clone)]
pub struct GetUserFromSession;

impl<U> GetAuthenticatedUserFromRequest<U> for GetUserFromSession
where
    U: DeserializeOwned,
{
    fn get_authenticated_user(&self, req: &actix_web::HttpRequest) -> Result<U, ()> {
        let s = req.get_session();

        let user = match s.get::<U>("user") {
            Ok(Some(user)) => user,
            _ => return Err(()),
        };

        let ttl = match s.get::<SystemTime>("ttl") {
            Ok(ttl) => ttl,
            Err(_) => return Err(()),
        };

        if let Some(ttl) = ttl {
            let now = SystemTime::now();
            if now > ttl {
                s.purge();
                return Err(());
            }            
        }

        Ok(user)
    }
}

pub struct UserSession {
    session: Session,
}

impl UserSession {
    pub (crate) fn new(session: Session) -> Self {
        Self {
            session,
        }
    }

    pub fn set_user<U: Serialize>(&self, user: U) -> Result<(), ()> {
        match self.session.insert("user", user) {
            Ok(_) => {},
            Err(_) => return Err(()),
        }

        self.session.remove("ttl");

        Ok(())
    }

    pub fn set_user_with_ttl<U: Serialize>(&self, user: U, ttl_in_seconds: u64) -> Result<(), ()> {
        match self.session.insert("user", user) {
            Ok(_) => {},
            Err(_) => return Err(()),
        }

        let now: SystemTime = SystemTime::now();
        let ttl = now + Duration::from_secs(ttl_in_seconds);

        match self.session.insert("ttl", ttl) {
            Ok(_) => return Ok(()),
            Err(_) => Err(()),
        }
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
