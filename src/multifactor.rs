use std::{error::Error as StdError, future::{ready, Future, Ready}, pin::Pin, rc::Rc};

use actix_web::{dev::Payload, error, FromRequest, HttpMessage, HttpRequest};
use serde::de::DeserializeOwned;
use thiserror::Error;

/// When TOTP is used, the secret needs to be stored somewhere
/// This is a repository trait that loads the secret for a given user
pub trait TotpSecretRepository<U> 
where U: DeserializeOwned
{
    type Error: StdError;
    fn get_auth_secret(&self, user: &U) -> impl Future<Output = Result<String, Self::Error>>;
}

#[derive(Error, Debug)]
pub enum GetTotpSecretError {
    #[error("GetTotpSecretError: {0}")]
    DefaultError(String)
}

// ToDo:
// Split Factor in two traits:
// one should be public, the other needs to be pub (crate) to hide is_condition_met() and generate_code()
pub trait Factor {
    /// Called first. Directly after checking credentials was successfully 
    /// If condition is met, this factor will be used to check the users identity
    fn is_condition_met(&self, req: &HttpRequest) -> Pin<Box<dyn Future<Output = Result<bool, ConditionCheckError>>>>;
    /// Called second. It generates the code, the code can then saved in the session or a token. It can be empty when using for example TOTP
    fn generate_code(&self, req: &HttpRequest) -> Result<Option<String>, GenerateCodeError>;
    /// Identifier for the Factor. Can be any String it only needs to be unique inside the app
    fn get_unique_id(&self) -> String;
    /// checks the code and returns empty Ok if code is correct, an Error otherwise
    fn check_code(&self, code: &str, req: &HttpRequest) -> Pin<Box<dyn Future<Output = Result<(), CheckCodeError>>>>;
}



pub struct OptionalFactor {
    value: Rc<Option<Box<dyn Factor>>>,
}

impl OptionalFactor {
    pub fn get_value(&self) -> &Option<Box<dyn Factor>> {
        self.value.as_ref()
    }
}

impl FromRequest for OptionalFactor {
    type Error = actix_web::Error;
    type Future = Ready<Result<OptionalFactor, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let extensions = req.extensions();
        if let Some(factor) = extensions.get::<Rc<Option<Box<dyn Factor>>>>() {
            ready(Ok(
                Self {
                    value: Rc::clone(factor),
                }
            ))
        } else {
            ready(Ok(Self {
                value: Rc::new(None)
            }))
        }
    }
}


#[derive(Error, Debug)]
pub enum ConditionCheckError {
    #[error("can't check condition: {0}")]
    CantCheckCondition(String)
}

#[derive(Error, Debug)]
#[error("GenerateCodeError: {message}{}", cause.as_ref().map(|e| format!(", caused by: {e}")).unwrap_or_else(|| ".".to_owned()))]
pub struct GenerateCodeError {
    message: String,
    #[source]
    cause: Option<Box<dyn StdError>>
}

impl GenerateCodeError {
    pub fn new(msg: &str) -> Self {
        Self {
            message: msg.to_owned(),
            cause: None,
        }
    }

    pub fn new_with_cause(msg: &str, e: impl Into<Box<dyn StdError>>) -> Self {
        Self {
            message: msg.to_owned(),
            cause: Some(e.into())
        }
    }
}


#[derive(Error, Debug)]
pub enum CheckCodeError {
    #[error("unknown server error: {0}")]
    UnknownError(String),
    #[error("invalid code")]
    InvalidCode,
    #[error("login rejected. unauthorized")]
    FinallyRejected,
}

#[cfg(test)]
mod tests {
    use super::{GenerateCodeError, GetTotpSecretError};


    #[test]
    fn generate_error_should_print_cause_test() {
        let orig = GetTotpSecretError::DefaultError("orig error".to_owned());
        let code_error = GenerateCodeError::new_with_cause("error", orig);

        assert_eq!(
            format!("{}", code_error),
            "GenerateCodeError: error, caused by: GetTotpSecretError: orig error"
        );
    }

}

