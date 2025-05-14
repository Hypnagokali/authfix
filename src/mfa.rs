use std::rc::Rc;

use actix_web::{dev::Payload, FromRequest, HttpMessage, HttpRequest, ResponseError};
use async_trait::async_trait;
use futures::future::{ready, Ready};
use log::warn;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::multifactor::Factor;

#[async_trait]
pub trait MfaByUser {
    type User;

    async fn get_mfa_id_by_user(&self, user: Self::User) -> Result<Option<String>, MfaError>;
}

#[derive(Error, Debug)]
#[error("Cannot load Mfa ID by user: {msg}")]
pub struct MfaError {
    msg: String,
}

impl MfaError {
    pub fn new(msg: &str) -> Self {
        Self {
            msg: msg.to_owned(),
        }
    }
}

impl Default for MfaError {
    fn default() -> Self {
        Self {
            msg: "Something went wrong".to_owned(),
        }
    }
}

impl ResponseError for MfaError {}

pub struct MfaConfigInner<U> {
    factors: Vec<Box<dyn Factor>>,
    condition: fn(&U, &HttpRequest) -> bool,
    load_mfa: Box<dyn MfaByUser<User = U>>,
}

pub struct MfaConfig<U>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
{
    inner: Rc<Option<MfaConfigInner<U>>>,
}

impl<U> MfaConfig<U>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
{
    pub fn empty() -> Self {
        Self {
            inner: Rc::new(None),
        }
    }

    pub fn new(
        factors: Vec<Box<dyn Factor>>,
        load_mfa: impl MfaByUser<User = U> + 'static,
        condition: fn(&U, &HttpRequest) -> bool,
    ) -> Self {
        Self {
            inner: Rc::new(Some(MfaConfigInner {
                factors,
                condition,
                load_mfa: Box::new(load_mfa),
            })),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.inner.is_some()
    }

    pub fn is_condition_met(&self, user: &U, req: &HttpRequest) -> bool {
        if let Some(inner) = self.inner.as_ref() {
            (inner.condition)(user, req)
        } else {
            warn!("Tried to use 'MfaConfig::is_condition_met' while MfaConfig is not configured");
            false
        }
    }

    pub async fn get_factor_by_user(&self, user: &U) -> Option<&Box<dyn Factor>> {
        if let Some(inner) = self.inner.as_ref() {
            match inner.load_mfa.get_mfa_id_by_user(user.clone()).await {
                Ok(Some(mfa)) => inner.factors.iter().find(|f| f.get_unique_id() == mfa),
                _ => None,
            }
        } else {
            warn!("Tried to use 'MfaConfig::get_factor_by_user' while MfaConfig is not configured");
            None
        }
    }
}

impl<U> FromRequest for MfaConfig<U>
where
    U: Serialize + DeserializeOwned + Clone,
{
    type Error = actix_web::Error;
    type Future = Ready<Result<MfaConfig<U>, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let extensions = req.extensions();
        if let Some(mfa_config) = extensions.get::<Rc<MfaConfig<U>>>() {
            ready(Ok(MfaConfig {
                inner: Rc::clone(&mfa_config.inner),
            }))
        } else {
            ready(Ok(MfaConfig::empty()))
        }
    }
}
