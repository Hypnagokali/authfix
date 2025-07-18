//! This module contains MFA realated types and traits

use crate::multifactor::factor::Factor;
use actix_web::{
    dev::Payload, FromRequest, HttpMessage, HttpRequest, HttpResponseBuilder, ResponseError,
};
use async_trait::async_trait;
use futures::future::{ready, Ready};
use log::warn;
use std::rc::Rc;
use thiserror::Error;

///  Handles the MFA request
///
/// # Example
/// ```no_run
/// use authfix::async_trait;
/// use actix_web::{HttpRequest, HttpResponseBuilder};
/// use authfix::multifactor::config::{HandleMfaRequest, MfaError};
/// use authfix::multifactor::factor::Factor;
/// use authfix::factor_impl::authenticator::AuthenticatorFactor;
/// struct MyMfaHandler;
/// struct YourUser;
///
/// #[async_trait(?Send)]
/// impl HandleMfaRequest for MyMfaHandler {
///     type User = YourUser;
///
///     async fn get_mfa_id_by_user(&self, user: &Self::User) -> Result<Option<String>, MfaError> {
///         // if the user uses an authenticator
///        Ok(Some(AuthenticatorFactor::id().to_owned()))
///     }
///
///     // you can omit this method. This is the default implementation:
///     async fn is_condition_met(&self, user: &Self::User, req: HttpRequest) -> bool {
///         // Maybe you want to check if the user has a cookie set
///         true
///     }
///
///     // you can omit this method. This is the default implementation:
///     async fn handle_success(&self, user: &Self::User, mut res: HttpResponseBuilder) -> HttpResponseBuilder {
///         // Maybe you want to set a cookie here
///         res
///     }
/// }
/// ```
#[async_trait(?Send)]
pub trait HandleMfaRequest {
    type User;

    async fn get_mfa_id_by_user(&self, user: &Self::User) -> Result<Option<String>, MfaError>;

    #[allow(unused)]
    async fn is_condition_met(&self, user: &Self::User, req: HttpRequest) -> bool {
        true
    }

    #[allow(unused)]
    async fn handle_success(
        &self,
        user: &Self::User,
        mut res: HttpResponseBuilder,
    ) -> HttpResponseBuilder {
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

struct MfaConfigInner<U> {
    factors: Vec<Box<dyn Factor>>,
    handle_mfa: Box<dyn HandleMfaRequest<User = U>>,
    timeout: u64,
}

pub struct MfaConfig<U>
where
    U: 'static,
{
    inner: Rc<Option<MfaConfigInner<U>>>,
}

impl<U> Clone for MfaConfig<U>
where
    U: 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<U> MfaConfig<U>
where
    U: 'static,
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
        timeout: u64,
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

    pub async fn handle_success(&self, user: &U, res: HttpResponseBuilder) -> HttpResponseBuilder {
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

impl<U> FromRequest for MfaConfig<U> {
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
