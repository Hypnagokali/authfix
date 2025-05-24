use std::rc::Rc;

use actix_web::{dev::Payload, FromRequest, HttpMessage, HttpRequest, HttpResponse, ResponseError};
use async_trait::async_trait;
use futures::future::{ready, Ready};
use log::warn;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::multifactor::Factor;

#[async_trait(?Send)]
pub trait HandleMfaRequest {
    type User;

    async fn get_mfa_id_by_user(&self, user: &Self::User) -> Result<Option<String>, MfaError>;

    #[allow(unused)]
    async fn is_condition_met(&self, user: &Self::User, req: HttpRequest) -> bool {
        true
    }

    #[allow(unused)]
    async fn handle_success(&self, user: &Self::User, mut res: HttpResponse) -> HttpResponse {
        res
    }
}

#[derive(Error, Debug)]
#[error("Handling of mfa request failed: {msg}")]
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
    handle_mfa: Box<dyn HandleMfaRequest<User = U>>,
    timeout: u64,
}

#[derive(Clone)]
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
        handle_mfa: impl HandleMfaRequest<User = U> + 'static,
    ) -> Self {
        Self {
            inner: Rc::new(Some(MfaConfigInner {
                factors,
                handle_mfa: Box::new(handle_mfa),
                timeout: 300, // 5 minutes as default value
            })),
        }
    }

    pub fn new_with_timeout(
        factors: Vec<Box<dyn Factor>>,
        handle_mfa: impl HandleMfaRequest<User = U> + 'static,
        timeout: u64
    ) -> Self {
        Self {
            inner: Rc::new(Some(MfaConfigInner {
                factors,
                handle_mfa: Box::new(handle_mfa),
                timeout,
            })),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.inner.is_some()
    }

    pub fn get_timeout_in_seconds(&self) -> u64 {
        if let Some(inner) = self.inner.as_ref() {
            inner.timeout
        } else {
            print_not_configured_warn();
            0
        }
    }

    pub async fn is_condition_met(&self, user: &U, req: HttpRequest) -> bool {
        if let Some(inner) = self.inner.as_ref() {
            inner.handle_mfa.is_condition_met(user, req).await
        } else {
            print_not_configured_warn();
            false
        }
    }

    pub async fn handle_success(&self, user: &U, res: HttpResponse) -> HttpResponse {
        if let Some(inner) = self.inner.as_ref() {
            inner.handle_mfa.handle_success(user, res).await
        } else {
            print_not_configured_warn();
            res
        }
    }

    pub async fn get_factor_by_user(&self, user: &U) -> Option<&Box<dyn Factor>> {
        if let Some(inner) = self.inner.as_ref() {
            match inner.handle_mfa.get_mfa_id_by_user(user).await {
                Ok(Some(mfa)) => inner.factors.iter().find(|f| f.get_unique_id() == mfa),
                _ => None,
            }
        } else {
            print_not_configured_warn();
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

fn print_not_configured_warn() {
    warn!("An attempt was made to use a MfaConfig method, although its not configured");
}
